## F2FS 提取一致性修复与 Windows 大小写冲突处理优化

本次发布聚焦跨格式提取一致性与 Windows 目录大小写兼容性，主要更新如下:

- 修复 F2FS 内联数据偏移计算错误，解决部分文件内容提取异常问题。
- 修复 F2FS 目录项解析中的续槽位处理逻辑，提升目录遍历与文件发现完整性。
- 新增 Windows 动态大小写冲突检测: 仅当输出目录大小写不敏感且存在同名异大小写路径时中止提取，并提示开启大小写敏感目录。
- 统一 EXT4、F2FS、EROFS、SUPER 的大小写冲突处理逻辑，减少不同格式下的行为差异。

---

## F2FS Extraction Consistency Fixes and Windows Case-Conflict Handling Improvements

This release focuses on cross-format extraction consistency and Windows case-sensitivity compatibility:

- Fixed incorrect inline data offset calculation in F2FS extraction to avoid corrupted file output.
- Fixed continuation-slot handling in F2FS directory entry parsing to improve traversal completeness.
- Added dynamic case-conflict detection on Windows: extraction is blocked only when the target directory is case-insensitive and case-only path conflicts exist, with actionable guidance for enabling case sensitivity.
- Unified case-conflict handling behavior across EXT4, F2FS, EROFS, and SUPER extraction flows.
