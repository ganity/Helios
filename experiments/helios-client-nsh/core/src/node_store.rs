//! Node metadata in a platform-supplied private directory.
use std::{fs, io::Write, path::Path};

use helios_client_model::{NodeProfile, import_connection_link};
use helios_config::ConnectionLink;

pub fn import(state_dir: &Path, input: &str) -> Result<NodeProfile, String> {
    let link = ConnectionLink::decode(input).map_err(|error| error.to_string())?;
    let id = link.storage_id().map_err(|error| error.to_string())?;
    let node = import_connection_link(input, state_dir)?;
    let path = state_dir.join("nodes").join(format!("imported-{id}"));
    let bytes = serde_json::to_vec(&node).map_err(|error| error.to_string())?;
    let final_path = path.join("node.json");
    let mut file = tempfile::NamedTempFile::new_in(path).map_err(|error| error.to_string())?;
    file.write_all(&bytes).map_err(|error| error.to_string())?;
    file.as_file()
        .sync_all()
        .map_err(|error| error.to_string())?;
    file.persist(final_path)
        .map_err(|error| error.to_string())?;
    Ok(node)
}

fn load_file(path: &Path) -> Result<NodeProfile, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

pub fn load(state_dir: &Path) -> Result<Vec<NodeProfile>, String> {
    let directory = state_dir.join("nodes");
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.to_string()),
    };
    let mut nodes = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        if entry
            .file_type()
            .map_err(|error| error.to_string())?
            .is_dir()
            && entry.file_name().to_string_lossy().starts_with("imported-")
        {
            let path = entry.path().join("node.json");
            if path.exists() {
                nodes.push(load_file(&path)?);
            }
        }
    }
    nodes.sort_by(|a, b| a.name.cmp(&b.name).then(a.server.cmp(&b.server)));
    Ok(nodes)
}

/// Locate by stored identity, never use an editable profile path as a deletion target.
fn metadata_path(state_dir: &Path, token_file: &Path) -> Result<std::path::PathBuf, String> {
    for entry in fs::read_dir(state_dir.join("nodes")).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.file_type().map_err(|e| e.to_string())?.is_dir()
            && entry.file_name().to_string_lossy().starts_with("imported-")
        {
            let path = entry.path().join("node.json");
            if path.exists() && load_file(&path)?.token_file == token_file {
                return Ok(path);
            }
        }
    }
    Err("节点不存在".into())
}

pub fn update(state_dir: &Path, node: &NodeProfile) -> Result<(), String> {
    if node.name.trim().is_empty() || node.credential_id.trim().is_empty() {
        return Err("节点名称和凭据标识不能为空".into());
    }
    node.config().map_err(|e| e.to_string())?;
    crate::session::Session::from_node(node).map_err(|e| e.to_string())?;
    let path = metadata_path(state_dir, &node.token_file)?;
    let original = load_file(&path)?;
    if original.ca_certificate != node.ca_certificate {
        return Err("更换证书请导入新的节点链接".into());
    }
    let mut file =
        tempfile::NamedTempFile::new_in(path.parent().unwrap()).map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec(node).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist(path).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn remove(state_dir: &Path, token_file: &Path) -> Result<(), String> {
    let path = metadata_path(state_dir, token_file)?;
    fs::remove_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())
}

pub fn select(state_dir: &Path, token_file: &Path) -> Result<(), String> {
    metadata_path(state_dir, token_file)?;
    let mut file = tempfile::NamedTempFile::new_in(state_dir).map_err(|e| e.to_string())?;
    file.write_all(token_file.to_string_lossy().as_bytes())
        .map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist(state_dir.join("selected-node"))
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn selection<'a>(state_dir: &Path, nodes: &'a [NodeProfile]) -> Option<&'a NodeProfile> {
    let selected = fs::read_to_string(state_dir.join("selected-node")).ok();
    nodes
        .iter()
        .find(|node| Some(node.token_file.to_string_lossy().as_ref()) == selected.as_deref())
        .or_else(|| nodes.first())
}

#[cfg(test)]
mod tests {
    use helios_config::{ConnectionLink, TransportPreference};

    #[test]
    fn imports_multiple_nodes_and_restores_them_without_exposing_token_in_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["test.invalid".into()]).unwrap();
        let make_link = |name: &str, port: u16| {
            ConnectionLink::new(
                name.into(),
                ([127, 0, 0, 1], port).into(),
                "test.invalid".into(),
                cert.cert.der().as_ref(),
                "main".into(),
                [42; 32],
                TransportPreference::Tls,
            )
            .unwrap()
            .encode()
            .unwrap()
        };
        let first = make_link("First", 443);
        super::import(directory.path(), &first).unwrap();
        super::import(directory.path(), &first).unwrap();
        super::import(directory.path(), &make_link("Second", 444)).unwrap();
        let nodes = super::load(directory.path()).unwrap();
        assert_eq!(
            nodes
                .iter()
                .map(|node| node.name.as_str())
                .collect::<Vec<_>>(),
            ["First", "Second"]
        );
        for node in nodes {
            assert_eq!(
                std::fs::read_to_string(&node.token_file).unwrap(),
                "2a".repeat(32)
            );
            let metadata =
                std::fs::read_to_string(node.token_file.parent().unwrap().join("node.json"))
                    .unwrap();
            assert!(!metadata.contains(&"2a".repeat(32)));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(node.token_file)
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        }
        assert!(super::import(directory.path(), "invalid").is_err());
        assert_eq!(super::load(directory.path()).unwrap().len(), 2);
        let mut first = super::load(directory.path()).unwrap().remove(0);
        super::select(directory.path(), &first.token_file).unwrap();
        assert_eq!(
            super::selection(directory.path(), &super::load(directory.path()).unwrap())
                .unwrap()
                .name,
            "First"
        );
        first.name = "Renamed".into();
        first.server = "[::1]:8443".into();
        super::update(directory.path(), &first).unwrap();
        assert_eq!(super::load(directory.path()).unwrap()[0].name, "Renamed");
        first.server = "invalid".into();
        assert!(super::update(directory.path(), &first).is_err());
        assert_eq!(
            super::load(directory.path()).unwrap()[0].server,
            "[::1]:8443"
        );
        assert!(super::remove(directory.path(), directory.path()).is_err());
        super::remove(directory.path(), &first.token_file).unwrap();
        let remaining = super::load(directory.path()).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].name, "Second");
        assert_eq!(
            super::selection(directory.path(), &remaining).unwrap().name,
            "Second"
        );
        assert!(remaining[0].token_file.exists());
    }
}
