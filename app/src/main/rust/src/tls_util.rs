use anyhow::{anyhow, Result};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys, ec_private_keys};
use std::{fs::File, io::BufReader};

pub fn load_server_config(cert_path: &str, key_path: &str) -> Result<ServerConfig> {
    // --- Load certificates ---
    let mut cert_reader = BufReader::new(File::open(cert_path)?);
    let certs: Vec<CertificateDer> = certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .map(CertificateDer::from)
        .collect();

    if certs.is_empty() {
        return Err(anyhow!("no certificates found in {}", cert_path));
    }

    // --- Load private key (PKCS#1 RSA, PKCS#8, EC) ---
    let mut key_reader = BufReader::new(File::open(key_path)?);

    // Try PKCS#1 RSA first (your case)
    let mut keys: Vec<PrivateKeyDer> = rsa_private_keys(&mut key_reader)
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .map(PrivateKeyDer::from)
        .collect();

    // Try PKCS#8 next
    if keys.is_empty() {
        key_reader = BufReader::new(File::open(key_path)?);
        keys = pkcs8_private_keys(&mut key_reader)
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .map(PrivateKeyDer::from)
            .collect();
    }

    // Try EC last
    if keys.is_empty() {
        key_reader = BufReader::new(File::open(key_path)?);
        keys = ec_private_keys(&mut key_reader)
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .map(PrivateKeyDer::from)
            .collect();
    }

    if keys.is_empty() {
        return Err(anyhow!(
            "no usable private key found in {} (expected RSA PKCS#1, PKCS#8, or EC)",
            key_path
        ));
    }

    let key = keys.remove(0);

    // --- Build TLS config ---
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(cfg)
}
