mod category;

use htmlescape;
use pretty_bytes::converter::convert;
use serde_json;
use std::error;
use std::fs;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use config::Config;

/// On windows, fixes paths with by changing "/" to "\"
/// On unix, keep path as is
/// 
/// # Examples
///
/// ```
/// let path = "some/windows/path.txt";
/// if cfg!(windows) {
///     assert_eq!(String::from(r"some\windows\path.txt"), fix_path(path));
/// }   
/// ```
pub fn fix_path(path: &str) -> String {
    let path = String::from(path);
    if cfg!(windows) {
        return path.replace("/", "\\").replace(r"\\", r"\");
    }   
    path
}

#[test]
fn test_fix_path() {
    let path = "some/windows/path.txt";
    if cfg!(windows) {
        assert_eq!(String::from(r"some\windows\path.txt"), fix_path(path));
    } else {
        assert_eq!(String::from("some/windows/path.txt"), fix_path(path));
    }
}

// This function is a secure version of the join method for PathBuf. The standart join method can
// allow path tranversal, this function doesn't.
pub fn secure_join<P: AsRef<Path> + fmt::Debug>(first: PathBuf, second: P) -> Result<PathBuf, io::Error> {
    println!("first {:#?}, second {:#?}", first, second);
    let mut result = first.clone();
    result = result.join(second);
    result = result.canonicalize()?;

    // Check if first is still a parent of result
    if result.starts_with(first) {
        Ok(result)
    } else {
        println!("SECURITY: prevented path traversal attack");
        Err(io::Error::new(
            io::ErrorKind::Other,
            "Paths are not securely joinable",
        ))
    }
}

#[derive(Serialize, Deserialize)]
struct FolderItem {
    name: String,
}

impl FolderItem {
    fn from_name(folder_name: &str) -> FolderItem {
        FolderItem {
            name: htmlescape::encode_minimal(&folder_name),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct FileItem {
    name: String,
    size: String,
    category: String,
}

impl FileItem {
    fn from(file_name: &str, simple_icons: bool, bytes: u64) -> FileItem {
        FileItem {
            category: category::get_from_name(&file_name, simple_icons),
            name: htmlescape::encode_minimal(&file_name),
            size: convert(bytes as f64).replace(" B", " bytes"),
        }
    }

    fn from_name(file_name: &str, simple_icons: bool) -> FileItem {
        FileItem {
            category: category::get_from_name(&file_name, simple_icons),
            name: htmlescape::encode_minimal(&file_name),
            size: String::new(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct FileRespond {
    action: String,
    path: String,
    folders: Vec<FolderItem>,
    files: Vec<FileItem>,
}

impl FileRespond {
    fn from_path(path_name: &str) -> FileRespond {
        FileRespond {
            action: "sendFilelist".to_string(),
            path: htmlescape::encode_minimal(&path_name),
            folders: Vec::new(),
            files: Vec::new(),
        }
    }
}

pub fn get_file_respond(path_end: &str, config: &Config) -> String {
    println!("path: {}", path_end);
    let path_end_fixed = fix_path(path_end);
    let path_end = path_end_fixed.as_str();
    let path = match secure_join(config.path.clone(), PathBuf::from(path_end)) {
        Ok(path) => path,
        Err(_) => {
            return json!({
                "action": "sendError",
                "message": format!("Cannot read the given path: {:?}", path_end)
            }).to_string();
        }
    };

    let entries = match fs::read_dir(&path) {
        Ok(e) => e,
        Err(_) => {
            return json!({
                "action": "sendError",
                "message": format!("Cannot read the given path: {:?}", path_end)
            }).to_string();
        }
    };

    println!("Open path: {:?}", path_end);
    let mut respond = FileRespond::from_path(path_end);

    for entry in entries {
        let _ = add_entry(&mut respond, entry, config).map_err(|e| eprintln!("Error: {}", e));
    }

    serde_json::to_string(&respond).unwrap_or_else(|_| {
        json!({
            "action": "sendError",
            "message": "Cannot parse content"
        }).to_string()
    })
}

/// Adds given file system entry to the response struct.
fn add_entry(
    respond: &mut FileRespond,
    entry: Result<fs::DirEntry, io::Error>,
    config: &Config,
) -> Result<(), Box<dyn error::Error>> {
    let entry = entry?;
    let file_type = entry.file_type()?;
    let file_name = match entry.file_name().into_string() {
        Ok(f) => f,
        // Bail creates an error with the given string body
        Err(_) => bail!("failed to get filename"),
    };
    if file_type.is_dir() {
        respond.folders.push(FolderItem::from_name(&file_name));
    } else {
        let item = match entry.metadata() {
            Ok(meta) => FileItem::from(&file_name, config.simple_icons, meta.len()),
            Err(_) => FileItem::from_name(&file_name, config.simple_icons),
        };

        respond.files.push(item);
    }
    Ok(())
}

pub fn get_new_folder_respond(path_end: &str, config: &Config) -> String {
    let path_end = PathBuf::from(path_end);
    let path_end_parent = match path_end.parent() {
        Some(path) => path.to_path_buf(),
        None => PathBuf::from(""),
    };

    match secure_join(config.path.clone(), path_end_parent) {
        Ok(_) => (),
        Err(_) => {
            return json!({
                "action": "sendNewFolder",
                "created": false,
                "message": "Cannot create new folder, because the path is invalid"
            }).to_string()
        }
    };

    let path = config.path.clone().join(path_end.clone());

    match fs::create_dir(path) {
        Ok(_) => (),
        Err(e) => {
            return json!({
                "action": "sendNewFolder",
                "created": false,
                "message": format!("Cannot create new folder.<br<br>Exact Error: {}", e)
            }).to_string();
        }
    }

    println!("Creat Folder: {:?}", path_end);

    json!({
        "action": "sendNewFolder",
        "created": true,
        "message": ""
    }).to_string()
}
