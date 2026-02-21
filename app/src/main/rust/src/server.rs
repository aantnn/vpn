// src/server.rs
use anyhow::Result;
use clap::Parser;
use tokio::{net::TcpListener, io::{AsyncReadExt, AsyncWriteExt}};
use hyper::server::conn::Http;
use hyper::{Request, Response, Body, Method, StatusCode};
use hyper::service::service_fn;
use tokio_rustls::TlsAcceptor;
use rustls::{ServerConfig, Certificate, PrivateKey};
use std::{sync::Arc, fs::File, io::BufReader};
use bytes::BytesMut;

mod tun_util;
use tun_util::{create_tun, read_framed, write_framed};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "0.0.0.0:8443")]
    listen: String,
    #[arg(long, default_value = "server.crt")]
    cert: String,
    #[arg(long, default_value = "server.key")]
    key: String,
    #[arg(long, default_value = "vpn0")]
    tun_name: String,
    #[arg(long, default_value = "10.0.0.1")]
    tun_addr: String,
    #[arg(long, default_value = "255.255.255.0")]
    tun_netmask: String,
}

fn load_certs(path: &str) -> Result<Vec<Certificate>> {
    let mut reader = BufReader::new(File::open(path)?);
    let certs = rustls_pemfile::certs(&mut reader)?
        .into_iter()
        .map(Certificate)
        .collect();
    Ok(certs)
}

fn load_key(path: &str) -> Result<PrivateKey> {
    let mut reader = BufReader::new(File::open(path)?);
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)?;
    Ok(PrivateKey(keys[0].clone()))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let certs = load_certs(&args.cert)?;
    let key = load_key(&args.key)?;

    let mut cfg = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols.push(b"http/1.1".to_vec());

    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind(&args.listen).await?;

    println!("Server listening on {}", args.listen);

    loop {
        let (tcp, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let args = args.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_conn(tcp, acceptor, args).await {
                eprintln!("conn error: {:?}", e);
            }
        });
    }
}

async fn handle_conn(
    tcp: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    args: Args,
) -> Result<()> {
    let tls = acceptor.accept(tcp).await?;
    let tun = create_tun(&args.tun_name, &args.tun_addr, &args.tun_netmask)?;

    let service = service_fn(move |req: Request<Body>| {
        let tun = tun.try_clone().expect("clone tun");
        async move {
            if req.method() == Method::CONNECT && req.uri().path() == "/vpn" {
                // Upgrade to raw tunnel
                let mut resp = Response::new(Body::empty());
                *resp.status_mut() = StatusCode::OK;
                Ok::<_, hyper::Error>(resp)
            } else {
                let mut resp = Response::new(Body::from("Not found"));
                *resp.status_mut() = StatusCode::NOT_FOUND;
                Ok::<_, hyper::Error>(resp)
            }
        }
    });

    // Hyper HTTP over the TLS stream
    Http::new().serve_connection(tls, service).await?;
    // NOTE: For a real tunnel, you’d use hyper’s upgrade API to get the underlying
    // TCP stream after CONNECT and then run the TUN <-> framed I/O loops here.

    Ok(())
}
