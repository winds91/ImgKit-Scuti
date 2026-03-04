use anyhow::{Result, anyhow};
#[cfg(windows)]
use std::fs::{self, OpenOptions};
use std::path::{Component, Path, PathBuf};

pub fn normalize_image_path(path: &Path) -> Result<PathBuf> {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Normal(name) => normalized.push(name),
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                return Err(anyhow!("路径包含父目录跳转: {:?}", path));
            }
            Component::Prefix(_) => {
                return Err(anyhow!("路径包含不允许的盘符前缀: {:?}", path));
            }
        }
    }

    Ok(normalized)
}

pub fn sanitize_single_component(name: &str) -> Result<String> {
    let normalized = normalize_image_path(Path::new(name))?;
    let mut components = normalized.components();

    let first = components
        .next()
        .ok_or_else(|| anyhow!("路径组件为空: {}", name))?;
    if components.next().is_some() {
        return Err(anyhow!("路径组件包含分隔符: {}", name));
    }

    match first {
        Component::Normal(value) => Ok(value.to_string_lossy().to_string()),
        _ => Err(anyhow!("无效的路径组件: {}", name)),
    }
}

pub fn join_output_path(root: &Path, image_path: &Path) -> Result<PathBuf> {
    let normalized = normalize_image_path(image_path)?;
    Ok(root.join(normalized))
}

pub fn is_case_sensitive_directory(path: &Path) -> Result<bool> {
    #[cfg(windows)]
    {
        fs::create_dir_all(path)?;
        let check_dir = path.join(format!(".imgkit_case_check_{}", std::process::id()));

        if check_dir.exists() {
            fs::remove_dir_all(&check_dir)?;
        }
        fs::create_dir_all(&check_dir)?;

        let lower = check_dir.join("imgkit_case_probe");
        let upper = check_dir.join("IMGKIT_CASE_PROBE");

        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lower)
            .map_err(|e| anyhow!("创建大小写检测文件失败: {}", e))?;

        let upper_result = OpenOptions::new().write(true).create_new(true).open(&upper);
        let _ = fs::remove_dir_all(&check_dir);

        match upper_result {
            Ok(_) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(err) => Err(anyhow!("大小写检测失败: {}", err)),
        }
    }

    #[cfg(not(windows))]
    {
        let _ = path;
        Ok(true)
    }
}

pub fn build_windows_case_conflict_message(
    output_dir: &Path,
    existing_path: &Path,
    incoming_path: &Path,
) -> String {
    #[cfg(windows)]
    {
        format!(
            "检测到仅大小写不同的冲突路径:\n\
  {}\n\
  {}\n\
当前输出目录未开启大小写敏感: {}\n\
此提示仅适用于 Windows。\n\
请在该目录执行以下命令开启:\n\
  fsutil file setCaseSensitiveInfo . enable\n\
可用以下命令验证状态:\n\
  fsutil file queryCaseSensitiveInfo .\n\
如提示权限不足, 请使用管理员身份打开 PowerShell 后重试。",
            existing_path.display(),
            incoming_path.display(),
            output_dir.display()
        )
    }

    #[cfg(not(windows))]
    {
        let _ = output_dir;
        let _ = existing_path;
        let _ = incoming_path;
        String::new()
    }
}

pub fn check_windows_case_conflict(
    case_map: &mut std::collections::HashMap<String, PathBuf>,
    output_dir: &Path,
    path: &Path,
) -> Result<()> {
    #[cfg(not(windows))]
    {
        let _ = (case_map, output_dir, path);
    }

    #[cfg(windows)]
    {
        let normalized = normalize_image_path(path)?;
        let key = normalized.to_string_lossy().to_lowercase();
        if let Some(existing) = case_map.get(&key) {
            if existing != &normalized {
                return Err(anyhow!(
                    "{}",
                    build_windows_case_conflict_message(output_dir, existing, &normalized)
                ));
            }
            return Ok(());
        }

        case_map.insert(key, normalized);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_image_path_basic() {
        let normalized = normalize_image_path(Path::new("/system/bin/sh")).unwrap();
        assert_eq!(normalized, PathBuf::from("system/bin/sh"));
    }

    #[test]
    fn test_normalize_image_path_reject_parent_dir() {
        assert!(normalize_image_path(Path::new("../etc/passwd")).is_err());
    }

    #[test]
    fn test_sanitize_single_component() {
        assert_eq!(sanitize_single_component("vendor").unwrap(), "vendor");
        assert!(sanitize_single_component("../vendor").is_err());
        assert!(sanitize_single_component("a/b").is_err());
    }
}
