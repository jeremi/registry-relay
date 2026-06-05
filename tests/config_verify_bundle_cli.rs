// SPDX-License-Identifier: Apache-2.0
//! CLI coverage for governed configuration bundle verification.

use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::Utc;
use registry_platform_config::sha256_uri;
use registry_platform_ops::internal_config_hash;
use serde_json::{json, Value};
use tempfile::TempDir;
use tough::editor::signed::PathExists;
use tough::editor::RepositoryEditor;
use tough::key_source::{KeySource, LocalKeySource};
use tough::schema::Target;

const TUF_TARGETS_SIGNER_KID: &str =
    "8ec3a843a0f9328c863cac4046ab1cacbbc67888476ac7acf73d9bcd9a223ada";

struct SignedConfigFixture {
    root_path: PathBuf,
    metadata_dir: PathBuf,
    targets_dir: PathBuf,
    datastore_dir: PathBuf,
    target_name: String,
}

fn tough_fixture(name: &str) -> PathBuf {
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .expect("CARGO_HOME or HOME is set");
    let src_root = cargo_home.join("registry/src");
    let registry = std::fs::read_dir(&src_root)
        .expect("cargo registry src exists")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.join("tough-0.22.0/tests/data").is_dir())
        .expect("tough-0.22.0 source fixture directory exists");
    registry.join("tough-0.22.0/tests/data").join(name)
}

fn write_current_config(tmp: &TempDir, signer_kid: &str) -> PathBuf {
    let root_sha = sha256_uri(
        &std::fs::read(tough_fixture("simple-rsa").join("root.json"))
            .expect("trusted TUF root fixture reads"),
    );
    let config_path = tmp.path().join("current.yaml");
    let yaml = format!(
        r#"
instance:
  id: relay-lab
  environment: lab
server:
  bind: 127.0.0.1:0
config_trust:
  antirollback_state_path: "{}"
  local_approval_state_path: "{}"
  accepted_roots:
    - root_id: ops-root
      production: false
      tuf_root_sha256: "{}"
      high_risk_change_classes: []
      signers:
        {}:
          kid: {}
          enabled: true
      roles:
        - name: config-admin
          threshold: 1
          signer_kids:
            - {}
          allowed_change_classes:
            - public_metadata
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
vocabularies: {{}}
auth:
  mode: api_key
  api_keys: []
datasets: []
audit:
  sink: stdout
"#,
        tmp.path().join("antirollback.json").display(),
        tmp.path().join("local-approvals.json").display(),
        root_sha,
        signer_kid,
        signer_kid,
        signer_kid
    );
    std::fs::write(&config_path, yaml).expect("current config writes");
    config_path
}

fn candidate_config_yaml(tmp: &TempDir) -> String {
    format!(
        r#"
instance:
  id: relay-lab
  environment: lab
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
vocabularies: {{}}
auth:
  mode: api_key
  api_keys: []
datasets: []
audit:
  sink: stdout
config_trust:
  antirollback_state_path: "{}"
  local_approval_state_path: "{}"
  accepted_roots:
    - root_id: ops-root
      production: false
      tuf_root_sha256: "{}"
      high_risk_change_classes: []
      signers:
        {}:
          kid: {}
          enabled: true
      roles:
        - name: config-admin
          threshold: 1
          signer_kids:
            - {}
          allowed_change_classes:
            - public_metadata
"#,
        tmp.path().join("candidate-antirollback.json").display(),
        tmp.path().join("candidate-local-approvals.json").display(),
        sha256_uri(
            &std::fs::read(tough_fixture("simple-rsa").join("root.json"))
                .expect("trusted TUF root fixture reads"),
        ),
        TUF_TARGETS_SIGNER_KID,
        TUF_TARGETS_SIGNER_KID,
        TUF_TARGETS_SIGNER_KID
    )
}

async fn write_signed_config_tuf_fixture(tmp: &TempDir, config_yaml: &str) -> SignedConfigFixture {
    let repo_dir = tmp.path().join("signed-config");
    let source_dir = repo_dir.join("source");
    let metadata_dir = repo_dir.join("metadata");
    let targets_dir = repo_dir.join("targets");
    let datastore_dir = repo_dir.join("datastore");
    std::fs::create_dir_all(&source_dir).expect("source dir");
    std::fs::create_dir_all(&datastore_dir).expect("datastore dir");
    let target_name = "registry-relay.yaml";
    let target_path = source_dir.join(target_name);
    std::fs::write(&target_path, config_yaml).expect("target config writes");

    let mut target = Target::from_path(&target_path)
        .await
        .expect("target metadata builds");
    let custom = json!({
        "product": "registry-relay",
        "instance_id": "relay-lab",
        "environment": "lab",
        "stream_id": "test-stream",
        "bundle_id": "test-bundle",
        "sequence": 1,
        "previous_config_hash": internal_config_hash(config_yaml.as_bytes()),
        "config_hash": sha256_uri(config_yaml.as_bytes()),
        "change_classes": ["public_metadata"],
        "signer_kids": [TUF_TARGETS_SIGNER_KID],
        "apply_policy": "live"
    });
    target.custom = custom
        .as_object()
        .expect("custom target metadata is an object")
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    let root_path = tough_fixture("simple-rsa").join("root.json");
    let key_path = tough_fixture("snakeoil.pem");
    let keys: Vec<Box<dyn KeySource>> = vec![Box::new(LocalKeySource { path: key_path })];
    let version = NonZeroU64::new(1).expect("nonzero version");
    let mut editor = RepositoryEditor::new(&root_path)
        .await
        .expect("repository editor builds");
    editor
        .targets_expires(Utc::now() + chrono::Duration::days(13))
        .expect("targets expiration");
    editor.targets_version(version).expect("targets version");
    editor.snapshot_expires(Utc::now() + chrono::Duration::days(21));
    editor.snapshot_version(version);
    editor.timestamp_expires(Utc::now() + chrono::Duration::days(3));
    editor.timestamp_version(version);
    editor
        .add_target(target_name, target)
        .expect("target added");
    let signed_repo = editor.sign(&keys).await.expect("repository signs");
    signed_repo
        .write(&metadata_dir)
        .await
        .expect("metadata writes");
    signed_repo
        .copy_targets(&source_dir, &targets_dir, PathExists::Fail)
        .await
        .expect("targets write");

    SignedConfigFixture {
        root_path: metadata_dir.join("1.root.json"),
        metadata_dir,
        targets_dir,
        datastore_dir,
        target_name: target_name.to_string(),
    }
}

fn verify_bundle_command(config_path: &Path, signed: &SignedConfigFixture) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-relay"));
    command
        .arg("config")
        .arg("verify-bundle")
        .arg("--config")
        .arg(config_path)
        .arg("--root-path")
        .arg(&signed.root_path)
        .arg("--metadata-dir")
        .arg(&signed.metadata_dir)
        .arg("--targets-dir")
        .arg(&signed.targets_dir)
        .arg("--datastore-dir")
        .arg(&signed.datastore_dir)
        .arg("--target-name")
        .arg(&signed.target_name);
    command
}

#[tokio::test]
async fn config_verify_bundle_cli_reports_verified_signed_bundle() {
    let tmp = TempDir::new().expect("tempdir");
    let current_config = write_current_config(&tmp, TUF_TARGETS_SIGNER_KID);
    let candidate_yaml = candidate_config_yaml(&tmp);
    let signed = write_signed_config_tuf_fixture(&tmp, &candidate_yaml).await;

    let output = verify_bundle_command(&current_config, &signed)
        .output()
        .expect("verify-bundle command runs");

    assert!(
        output.status.success(),
        "verify-bundle failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("verify-bundle emits JSON report");
    assert_eq!(report["result"], "verified");
    assert_eq!(report["source"], "signed_bundle_file");
    assert_eq!(report["bundle_id"], "test-bundle");
    assert_eq!(report["stream_id"], "test-stream");
    assert_eq!(report["sequence"], 1);
    assert_eq!(report["target_name"], signed.target_name);
    assert_eq!(report["change_classes"], json!(["public_metadata"]));
    assert_eq!(report["signer_kids"], json!([TUF_TARGETS_SIGNER_KID]));
    assert_eq!(
        report["config_hash"],
        internal_config_hash(candidate_yaml.as_bytes())
    );
}

#[tokio::test]
async fn config_verify_bundle_cli_rejects_unauthorized_local_trust_root() {
    let tmp = TempDir::new().expect("tempdir");
    let current_config = write_current_config(&tmp, "unauthorized-signer");
    let candidate_yaml = candidate_config_yaml(&tmp);
    let signed = write_signed_config_tuf_fixture(&tmp, &candidate_yaml).await;

    let output = verify_bundle_command(&current_config, &signed)
        .output()
        .expect("verify-bundle command runs");

    assert!(
        !output.status.success(),
        "verify-bundle unexpectedly succeeded: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("not authorized"),
        "stderr did not explain authorization failure:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
