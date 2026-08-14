use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QuarantineMetadata {
    pub id: String,
    pub original_path: String,
    pub original_permissions: u32,
    pub hash_sha256: String,
    pub triggered_rule_id: String,
    pub quarantine_timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedManifest {
    pub metadata: QuarantineMetadata,
    pub file_key: Vec<u8>,
    pub file_nonce: Vec<u8>,
    pub hmac_tag: Vec<u8>,
}

#[derive(Clone)]
pub struct QuarantineManager {
    pub quarantine_dir: PathBuf,
    pub master_key: Vec<u8>,
}

fn encrypt_aes_gcm(key: &[u8], nonce_bytes: &[u8], plaintext: &[u8]) -> io::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to init AES cipher: {}", e),
        )
    })?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.encrypt(nonce, plaintext).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("AES encrypt error: {}", e),
        )
    })
}

fn decrypt_aes_gcm(key: &[u8], nonce_bytes: &[u8], ciphertext: &[u8]) -> io::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to init AES cipher: {}", e),
        )
    })?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("AES decrypt error (tampering or invalid key): {}", e),
        )
    })
}

fn compute_hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn verify_hmac(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.verify_slice(tag).is_ok()
}

impl QuarantineManager {
    pub fn new<P: AsRef<Path>>(dir: P) -> io::Result<Self> {
        let path = dir.as_ref().to_path_buf();
        if !path.exists() {
            fs::create_dir_all(&path)?;
            let mut perms = fs::metadata(&path)?.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(&path, perms)?;
        }

        // Load or generate master key
        let master_key_path = path.join("master.key");
        let master_key = if master_key_path.exists() {
            let mut file = File::open(&master_key_path)?;
            let mut key = vec![0u8; 32];
            file.read_exact(&mut key)?;
            key
        } else {
            let mut key = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            let mut file = File::create(&master_key_path)?;
            file.write_all(&key)?;

            // Set 0400 permissions (read-only by owner)
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o400);
            fs::set_permissions(&master_key_path, perms)?;
            key
        };

        Ok(Self {
            quarantine_dir: path,
            master_key,
        })
    }

    /// Quarantine a file. Encrypts the content using a unique key with AES-256-GCM,
    /// computes an HMAC-SHA256, stores the encrypted manifest (including key, nonce, hmac tag)
    /// encrypted with the master key, and removes the original file.
    pub fn quarantine_file<P: AsRef<Path>>(
        &self,
        file_path: P,
        sha256: &str,
        rule_id: &str,
    ) -> io::Result<String> {
        let file_path_ref = file_path.as_ref();
        if !file_path_ref.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "File to quarantine does not exist",
            ));
        }

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let id = format!("{}_{}", sha256, now);

        // Read original permissions
        let metadata = fs::metadata(file_path_ref)?;
        let original_permissions = metadata.permissions().mode();

        // Read file content
        let mut file = File::open(file_path_ref)?;
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;
        drop(file);

        // Generate unique key and nonce for the file
        let mut file_key = [0u8; 32];
        let mut file_nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut file_key);
        rand::thread_rng().fill_bytes(&mut file_nonce_bytes);

        // Encrypt content with AES-256-GCM
        let encrypted_content = encrypt_aes_gcm(&file_key, &file_nonce_bytes, &content)?;

        // Compute HMAC-SHA256 of the ciphertext to verify file integrity
        let hmac_tag = compute_hmac(&file_key, &encrypted_content);

        // Paths for quarantined files
        let quarantined_file_path = self.quarantine_dir.join(format!("{}.quarantined", id));
        let metadata_file_path = self.quarantine_dir.join(format!("{}.metadata", id));

        // Write encrypted file
        let mut q_file = File::create(&quarantined_file_path)?;
        q_file.write_all(&encrypted_content)?;
        let mut q_perms = q_file.metadata()?.permissions();
        q_perms.set_mode(0o600);
        fs::set_permissions(&quarantined_file_path, q_perms)?;

        // Create metadata
        let meta = QuarantineMetadata {
            id: id.clone(),
            original_path: file_path_ref.to_string_lossy().into_owned(),
            original_permissions,
            hash_sha256: sha256.to_string(),
            triggered_rule_id: rule_id.to_string(),
            quarantine_timestamp: now,
        };

        // Encrypt the metadata manifest using the master key and a random manifest nonce
        let mut manifest_nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut manifest_nonce_bytes);

        let manifest_info = EncryptedManifest {
            metadata: meta,
            file_key: file_key.to_vec(),
            file_nonce: file_nonce_bytes.to_vec(),
            hmac_tag,
        };
        let serialized_manifest = serde_json::to_vec(&manifest_info)?;
        let encrypted_manifest = encrypt_aes_gcm(
            &self.master_key,
            &manifest_nonce_bytes,
            &serialized_manifest,
        )?;

        // Write encrypted manifest: 12 bytes nonce + encrypted bytes
        let mut m_file = File::create(&metadata_file_path)?;
        m_file.write_all(&manifest_nonce_bytes)?;
        m_file.write_all(&encrypted_manifest)?;

        // Remove original file
        fs::remove_file(file_path_ref)?;

        Ok(id)
    }

    /// Restore a quarantined file to its original location
    pub fn restore_file(&self, id: &str) -> io::Result<()> {
        let quarantined_file_path = self.quarantine_dir.join(format!("{}.quarantined", id));
        let metadata_file_path = self.quarantine_dir.join(format!("{}.metadata", id));

        if !quarantined_file_path.exists() || !metadata_file_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Quarantine file or metadata not found",
            ));
        }

        // Read and decrypt metadata manifest
        let mut m_file = File::open(&metadata_file_path)?;
        let mut raw_manifest = Vec::new();
        m_file.read_to_end(&mut raw_manifest)?;
        drop(m_file);

        if raw_manifest.len() < 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid metadata size",
            ));
        }
        let (manifest_nonce, encrypted_manifest) = raw_manifest.split_at(12);
        let decrypted_manifest =
            decrypt_aes_gcm(&self.master_key, manifest_nonce, encrypted_manifest)?;
        let manifest_info: EncryptedManifest = serde_json::from_slice(&decrypted_manifest)?;

        // Read quarantined file ciphertext
        let mut q_file = File::open(&quarantined_file_path)?;
        let mut encrypted_content = Vec::new();
        q_file.read_to_end(&mut encrypted_content)?;
        drop(q_file);

        // Verify ciphertext integrity check via HMAC
        if !verify_hmac(
            &manifest_info.file_key,
            &encrypted_content,
            &manifest_info.hmac_tag,
        ) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Quarantine file integrity check failed (file might have been tampered with or modified)",
            ));
        }

        // Decrypt quarantined file content
        let decrypted_content = decrypt_aes_gcm(
            &manifest_info.file_key,
            &manifest_info.file_nonce,
            &encrypted_content,
        )?;

        // Recreate original file path directories if they were deleted
        let original_path = Path::new(&manifest_info.metadata.original_path);
        if let Some(parent) = original_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Write decrypted file back
        let mut restored_file = File::create(original_path)?;
        restored_file.write_all(&decrypted_content)?;

        // Restore original permissions
        let mut perms = restored_file.metadata()?.permissions();
        perms.set_mode(manifest_info.metadata.original_permissions);
        fs::set_permissions(original_path, perms)?;

        // Clean up quarantine folder files
        fs::remove_file(&quarantined_file_path)?;
        fs::remove_file(&metadata_file_path)?;

        Ok(())
    }

    /// Lists all currently quarantined files by decrypting each manifest
    pub fn list_quarantined(&self) -> io::Result<Vec<QuarantineMetadata>> {
        let mut list = Vec::new();
        let entries = fs::read_dir(&self.quarantine_dir)?;

        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_file()
                && path.extension().is_some_and(|ext| ext == "metadata")
                && let Ok(mut file) = File::open(&path)
            {
                let mut raw_manifest = Vec::new();
                if file.read_to_end(&mut raw_manifest).is_ok() && raw_manifest.len() >= 12 {
                    let (manifest_nonce, encrypted_manifest) = raw_manifest.split_at(12);
                    if let Ok(decrypted_manifest) =
                        decrypt_aes_gcm(&self.master_key, manifest_nonce, encrypted_manifest)
                        && let Ok(manifest_info) =
                            serde_json::from_slice::<EncryptedManifest>(&decrypted_manifest)
                    {
                        list.push(manifest_info.metadata);
                    }
                }
            }
        }
        Ok(list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_quarantine_and_restore() {
        let test_dir = Path::new("test_quarantine_dir");
        let q_dir = test_dir.join("q_dir");
        let target_file = test_dir.join("test_malware.txt");

        // Setup
        let _ = fs::remove_dir_all(test_dir);
        fs::create_dir_all(test_dir).unwrap();
        fs::write(&target_file, "MALWARE_CONTENT_TEST_123").unwrap();

        let manager = QuarantineManager::new(&q_dir).unwrap();

        // Test quarantine
        let id = manager
            .quarantine_file(&target_file, "fake_sha256_hash", "TEST-RULE")
            .unwrap();

        assert!(!target_file.exists());

        let q_file_path = q_dir.join(format!("{}.quarantined", id));
        let m_file_path = q_dir.join(format!("{}.metadata", id));
        assert!(q_file_path.exists());
        assert!(m_file_path.exists());

        // Check if content is encrypted (not equal to original content)
        let enc_content = fs::read(&q_file_path).unwrap();
        assert_ne!(enc_content, b"MALWARE_CONTENT_TEST_123");

        // Test list
        let list = manager.list_quarantined().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, id);
        assert_eq!(list[0].triggered_rule_id, "TEST-RULE");

        // Test restore
        manager.restore_file(&id).unwrap();

        assert!(target_file.exists());
        assert!(!q_file_path.exists());
        assert!(!m_file_path.exists());

        let restored_content = fs::read_to_string(&target_file).unwrap();
        assert_eq!(restored_content, "MALWARE_CONTENT_TEST_123");

        // Cleanup
        let _ = fs::remove_dir_all(test_dir);
    }
}
