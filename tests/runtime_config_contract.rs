// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};

const LEGACY_EXTENSION_ARC_EXTRACTORS: usize = 0;

#[test]
fn legacy_runtime_extension_extractors_stay_removed_from_handlers() {
    let mut files = Vec::new();
    collect_rs_files(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );

    let count = files
        .iter()
        .filter(|path| is_legacy_handler_surface(path))
        .map(|path| {
            fs::read_to_string(path)
                .unwrap_or_else(|err| panic!("{} reads: {err}", path.display()))
                .matches("Extension<Arc<")
                .count()
        })
        .sum::<usize>();

    assert_eq!(
        count, LEGACY_EXTENSION_ARC_EXTRACTORS,
        "request handlers and middleware must read compiled runtime state through RuntimeSnapshot"
    );
}

fn is_legacy_handler_surface(path: &Path) -> bool {
    let relative = path
        .strip_prefix(env!("CARGO_MANIFEST_DIR"))
        .expect("path is under crate root");
    relative.starts_with("src/api")
        || relative.starts_with("src/audit")
        || relative == Path::new("src/observability.rs")
}

fn collect_rs_files(path: PathBuf, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(&path).unwrap_or_else(|err| panic!("{} lists: {err}", path.display()))
    {
        let entry = entry.expect("directory entry reads");
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}
