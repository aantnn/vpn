use rustls::pki_types::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use anyhow::Result;

/// Create a TUN interface using tokio-tun
pub fn create_client_tun(name: &str, addr:Ipv4Addr, mask: Ipv4Addr) -> Result<Tun> {
    let tun = TunBuilder::new()
        .name(name)
        .address(addr)
        .netmask(mask)
        .up()
        .try_build()?;
    Ok(tun)
}
// ---------- Client upgrade handler ----------

async fn client_upgraded_io(upgraded: Upgraded, tun: Tun) -> Result<()> {
    let upgraded = TokioIo::new(upgraded);
    pump_tun_and_tls_client(upgraded, tun).await
}

pub async fn client_upgrade_request(addr: SocketAddr, tun: Tun) -> Result<()> {
    let uri = format!("https://{}/", addr).parse::<hyper::Uri>()?;

    // TLS config
    let mut root_store = rustls::RootCertStore::empty();
    let mut cert_reader = std::io::BufReader::new(std::fs::File::open("ca.crt")?);
    use rustls::pki_types::CertificateDer;
    use rustls_pemfile::certs;
    let mut certs: Vec<CertificateDer> = certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    root_store.add(certs.pop().unwrap())?;

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_config));

    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let server_name = rustls::pki_types::ServerName::try_from("localhost".to_string())?;
    let tls = connector.connect(server_name, tcp).await?;
    let io = TokioIo::new(tls);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });

    let req = Request::builder()
        .method("CONNECT")
        .uri(uri)
        .header(UPGRADE, "vpn")
        .body(Empty::<Bytes>::new())?;

    let res = sender.send_request(req).await?;
    if res.status() != StatusCode::SWITCHING_PROTOCOLS {
        panic!("server refused upgrade: {}", res.status());
    }

    match hyper::upgrade::on(res).await {
        Ok(upgraded) => client_upgraded_io(upgraded, tun).await?,
        Err(e) => eprintln!("upgrade error: {e}"),
    }

    Ok(())
}


/// Pump packets between TLS-upgraded connection and local TUN
pub async fn pump_tun_and_tls_client(
    upgraded: Upgraded,
    tun: Tun,
) -> Result<()> {
    let upgraded = TokioIo::new(upgraded);

    let (mut tls_r, mut tls_w) = tokio::io::split(upgraded);
    let (mut tun_r, mut tun_w) = tokio::io::split(tun);

    let tls_to_tun = async {
        let mut buf = [0u8; 2000];
        loop {
            let n = tls_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            tun_w.write_all(&buf[..n]).await?;
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    };

    let tun_to_tls = async {
        let mut buf = [0u8; 2000];
        loop {
            let n = tun_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            tls_w.write_all(&buf[..n]).await?;
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    };

    tokio::select! {
        r = tls_to_tun => { r?; }
        r = tun_to_tls => { r?; }
    }

    Ok(())
}
