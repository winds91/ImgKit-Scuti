use crate::filesystem::f2fs::*;
use crate::filesystem::f2fs::{F2fsError, Result};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, RwLock};

pub struct F2fsVolume {
    file: Arc<RwLock<File>>,
    pub superblock: Superblock,
    nat_cache: Arc<RwLock<HashMap<Nid, NatEntry>>>,
    nat_journal_cache: Arc<RwLock<HashMap<Nid, NatEntry>>>,
    nat_blocks_per_copy: u32,
}

impl F2fsVolume {
    pub fn new(path: &str) -> Result<Self> {
        let file = File::open(path)?;
        let file = Arc::new(RwLock::new(file));

        // Read superblock
        let mut buf = vec![0u8; F2FS_BLKSIZE];
        {
            let mut f = file
                .write()
                .map_err(|e| F2fsError::LockError(format!("文件锁写入失败: {}", e)))?;
            f.seek(SeekFrom::Start(F2FS_SUPER_OFFSET))?;
            f.read_exact(&mut buf)?;
        }
        let superblock = Superblock::from_bytes(&buf)?;
        let log_blocks_per_seg = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
        let blocks_per_seg = 1u32
            .checked_shl(log_blocks_per_seg)
            .ok_or_else(|| F2fsError::InvalidData("无效的 log_blocks_per_seg".into()))?;
        let segment_count_nat = u32::from_le_bytes([buf[60], buf[61], buf[62], buf[63]]);
        let nat_blocks_per_copy = (segment_count_nat / 2).saturating_mul(blocks_per_seg);
        let nat_journal_cache = Arc::new(RwLock::new(HashMap::new()));

        Ok(F2fsVolume {
            file,
            superblock,
            nat_cache: Arc::new(RwLock::new(HashMap::new())),
            nat_journal_cache,
            nat_blocks_per_copy,
        })
    }

    pub fn read_block(&self, block: Block) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; F2FS_BLKSIZE];
        let offset = block.0 as u64 * F2FS_BLKSIZE as u64;

        let mut file = self
            .file
            .write()
            .map_err(|e| F2fsError::LockError(format!("文件锁写入失败: {}", e)))?;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buf)?;

        Ok(buf)
    }

    pub fn read_node(&self, nid: Nid) -> Result<Vec<u8>> {
        let nat_entry = self.get_nat_entry(nid)?;
        self.read_block(nat_entry.block_addr)
    }

    fn get_nat_entry(&self, nid: Nid) -> Result<NatEntry> {
        // Check cache first
        {
            let cache = self
                .nat_cache
                .read()
                .map_err(|e| F2fsError::LockError(format!("NAT 缓存读取失败: {}", e)))?;
            if let Some(entry) = cache.get(&nid) {
                return Ok(entry.clone());
            }
        }
        {
            let cache = self
                .nat_journal_cache
                .read()
                .map_err(|e| F2fsError::LockError(format!("NAT journal 缓存读取失败: {}", e)))?;
            if let Some(entry) = cache.get(&nid) {
                let entry = entry.clone();
                let mut nat_cache = self
                    .nat_cache
                    .write()
                    .map_err(|e| F2fsError::LockError(format!("NAT 缓存写入失败: {}", e)))?;
                nat_cache.insert(nid, entry.clone());
                return Ok(entry);
            }
        }

        // Read NAT block
        let nat_block_idx = nid.0 / NAT_ENTRY_PER_BLOCK as u32;
        let entry_idx = (nid.0 % NAT_ENTRY_PER_BLOCK as u32) as usize;
        let mut entry =
            self.read_nat_entry_from_copy(self.superblock.nat_blkaddr, nat_block_idx, entry_idx)?;
        if (entry.block_addr.0 == 0 || !self.is_valid_block(entry.block_addr))
            && self.nat_blocks_per_copy > 0
            && let Ok(secondary) = self.read_nat_entry_from_copy(
                self.superblock.nat_blkaddr + self.nat_blocks_per_copy,
                nat_block_idx,
                entry_idx,
            )
            && secondary.block_addr.0 != 0
            && self.is_valid_block(secondary.block_addr)
        {
            entry = secondary;
        }

        // cache
        {
            let mut cache = self
                .nat_cache
                .write()
                .map_err(|e| F2fsError::LockError(format!("NAT 缓存写入失败: {}", e)))?;
            cache.insert(nid, entry.clone());
        }

        Ok(entry)
    }

    fn read_nat_entry_from_copy(
        &self,
        nat_base_blkaddr: u32,
        nat_block_idx: u32,
        entry_idx: usize,
    ) -> Result<NatEntry> {
        let nat_block = Block(nat_base_blkaddr + nat_block_idx);
        let data = self.read_block(nat_block)?;
        let entry_offset = entry_idx * NAT_ENTRY_SIZE;
        let entry_end = entry_offset + NAT_ENTRY_SIZE;
        if entry_end > data.len() {
            return Err(F2fsError::InvalidData("NAT 条目读取越界".into()));
        }
        NatEntry::from_bytes(&data[entry_offset..entry_end])
    }

    pub fn is_valid_block(&self, block: Block) -> bool {
        block.0 >= self.superblock.main_blkaddr && block.0 < self.superblock.block_count as u32
    }
}
