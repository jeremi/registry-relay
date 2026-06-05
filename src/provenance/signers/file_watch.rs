// SPDX-License-Identifier: Apache-2.0
//! Local file-backed provenance signer with on-use reload.

use std::fs;
use std::sync::RwLock;

use registry_platform_crypto::KeyReadiness;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::config::FileWatchSignerConfig;

use super::super::signer::{Signer, SignerError, SigningAlgorithm};
use super::software::SoftwareSigner;

struct FileWatchState {
    signer: SoftwareSigner,
    readiness: KeyReadiness,
}

/// Signer backed by a local private JWK file.
///
/// The file is re-read on signer use. A valid replacement for the same public
/// key identity becomes active for new requests without process restart. A
/// malformed or different-key replacement degrades readiness but keeps the last
/// good signer available.
pub struct FileWatchSigner {
    algorithm: SigningAlgorithm,
    verification_method_id: String,
    path: std::path::PathBuf,
    expected_public_jwk: Value,
    state: RwLock<FileWatchState>,
}

impl std::fmt::Debug for FileWatchSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileWatchSigner")
            .field("algorithm", &self.algorithm)
            .field("verification_method_id", &self.verification_method_id)
            .field("readiness", &self.readiness())
            .finish_non_exhaustive()
    }
}

impl FileWatchSigner {
    pub fn from_config(
        cfg: &FileWatchSignerConfig,
        verification_method_id: String,
    ) -> Result<Self, SignerError> {
        let algorithm = cfg.signing_algorithm.into();
        let raw = read_key_file(&cfg.path)?;
        let signer = SoftwareSigner::from_jwk_str(&raw, algorithm, verification_method_id.clone())?;
        let expected_public_jwk = signer.public_jwk();
        Ok(Self {
            algorithm,
            verification_method_id,
            path: cfg.path.clone(),
            expected_public_jwk,
            state: RwLock::new(FileWatchState {
                signer,
                readiness: KeyReadiness::Ready,
            }),
        })
    }

    fn refresh(&self) {
        let Ok(raw) = read_key_file(&self.path) else {
            if let Ok(mut state) = self.state.write() {
                state.readiness = KeyReadiness::Degraded;
            }
            return;
        };
        match SoftwareSigner::from_jwk_str(
            &raw,
            self.algorithm,
            self.verification_method_id.clone(),
        ) {
            Ok(signer) if signer.public_jwk() == self.expected_public_jwk => {
                if let Ok(mut state) = self.state.write() {
                    state.signer = signer;
                    state.readiness = KeyReadiness::Ready;
                }
            }
            Ok(_) | Err(_) => {
                if let Ok(mut state) = self.state.write() {
                    state.readiness = KeyReadiness::Degraded;
                }
            }
        }
    }
}

fn read_key_file(path: &std::path::Path) -> Result<Zeroizing<String>, SignerError> {
    fs::read_to_string(path)
        .map(Zeroizing::new)
        .map_err(|_| SignerError::KeyLoad {
            reason: "file_watch key file could not be read",
        })
}

impl Signer for FileWatchSigner {
    fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    fn verification_method_id(&self) -> &str {
        &self.verification_method_id
    }

    fn sign(&self, header: Value, payload: Value) -> Result<String, SignerError> {
        self.refresh();
        let state = self.state.read().map_err(|_| SignerError::Unavailable)?;
        state.signer.sign(header, payload)
    }

    fn public_jwk(&self) -> Value {
        self.refresh();
        self.state
            .read()
            .map(|state| state.signer.public_jwk())
            .unwrap_or(Value::Null)
    }

    fn readiness(&self) -> KeyReadiness {
        self.refresh();
        self.state
            .read()
            .map(|state| state.readiness)
            .unwrap_or(KeyReadiness::NotReady)
    }
}
