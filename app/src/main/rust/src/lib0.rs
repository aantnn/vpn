mod lib2;

use anyhow::Result;
use bytes::Bytes;
use http_body_util::Empty;
use hyper::{Request, StatusCode};

use std::io::{Read, Write};
use std::mem::ManuallyDrop;
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::{Arc, OnceLock, RwLock};

use hyper::header::UPGRADE;
use hyper_util::rt::TokioIo;

use tokio::io::unix::AsyncFd;
use tokio::runtime::Runtime;
use tokio::net::TcpSocket;
use tokio::spawn;
use tokio_util::sync::{CancellationToken};
use tokio_rustls::TlsConnector;

use jni::strings::JNIString;
use jni::sys::{jint, JNI_VERSION_1_6};
use jni::errors::{ThrowRuntimeExAndDefault};
use jni::objects::{JClass, JObject, JString};
use jni::{errors, jni_sig, jni_str, Env, EnvUnowned, JValue, JavaVM};

use android_logger::Config;
use log::{debug, error, info, LevelFilter};






static JVM: OnceLock<JavaVM> = OnceLock::new();
static VPN_SERVICE_INSTANCE: OnceLock<RwLock<jni::refs::Global<JClass>>> = OnceLock::new();

#[unsafe(no_mangle)]
pub unsafe extern "C" fn JNI_OnLoad(vm: *mut jni::sys::JavaVM, _reserved: *mut std::ffi::c_void) -> i32 {
    let jvm = JavaVM::from_raw(vm);
    JVM.set(jvm).ok();
    JNI_VERSION_1_6
}

static CANCEL_TOKEN: OnceLock<RwLock<CancellationToken>> = OnceLock::new();
fn get_lock() -> &'static RwLock<CancellationToken> {
    CANCEL_TOKEN.get_or_init(|| RwLock::new(CancellationToken::new()))
}
fn renew_cancellation_token() -> Result<()> {
    match get_lock().write() {
        Ok(mut token) => {
            *token = CancellationToken::new();
        }
        Err(e) => {
            let msg = format!("Failed to get lock to cancellation token: {}", e);
            debug!("{}", msg);
            return Err(anyhow::anyhow!(msg));
        }
    };
    Ok(())
}
async fn is_canceled() -> Result<()> {
    let tok = match get_lock().read() {
        Ok(tok) => tok,
        Err(_) => {
            return Err(anyhow::anyhow!(
                "Cancellation token poisoned: is_canceled()"
            ));
        }
    };
    Ok(tok.cancelled().await)
}
#[unsafe(no_mangle)]
pub extern "C" fn Java_ru_valishin_vpn_MyVpnService_requestRustShutdown(
    mut unowned_env: EnvUnowned,
    _class: JClass,
) {
    let outcome = unowned_env.with_env(|env| -> jni::errors::Result<()> {
        let lock = get_lock();
        match lock.read() {
            Ok(token) => token.cancel(),
            Err(e) => {
                let msg = format!("Failed to get lock to cancellation token: {}", e);
                debug!("{}", msg);
                return env.throw_new(jni_str!("java/lang/RuntimeException"), JNIString::from(msg));
            }
        };
        renew_cancellation_token();
        Ok(())
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "C" fn Java_ru_valishin_vpn_MyVpnService_initRust<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    class: JClass<'caller>,
) {
    android_logger::init_once(
        Config::default()
            .with_max_level(LevelFilter::Trace) // Set global log level
            .with_tag("VPN_APP"), // The tag shown in logcat
    );

    let outcome = unowned_env.with_env(|env: &mut Env| -> Result<_, jni::errors::Error> {
        let global_class = match env.new_global_ref(class) {
            Ok(g) => g,
            Err(_) => {
                let msg = "Failed to create global reference of VPN class";
                debug!("{}", msg);
                return env.throw_new(jni_str!("java/lang/Exception"), JNIString::from(msg));
            }
        };
        let lock = VPN_SERVICE_INSTANCE.get_or_init(|| RwLock::new(jni::refs::Global::default()));
        match lock.write() {
            Ok(mut instance) => {
                *instance = global_class;
            }
            Err(_) => {
                debug!("Could not acquire write lock for VPN_SERVICE_INSTANCE");
            }
        };
        debug!("Rust initialized");
        Ok(())
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ru_valishin_vpn_MyVpnService_runRustVpnLoop<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    class: JClass<'caller>,
    tun_fd: jint,
) {
    let outcome = unowned_env.with_env(|env| -> jni::errors::Result<()> {
        match create_tokio_runtime(tun_fd) {
            Ok(r) => Ok(r),
            Err(e) => {
                let msg = format!("Failed to create tokio runtime: {}", e);
                env.throw_new(jni_str!("java/lang/Exception"), JNIString::from(msg))
            }
        }
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}
#[unsafe(no_mangle)]
pub fn protect_socket<'a>(env: &mut Env) -> Result<JObject<'a>> {
    let class = match VPN_SERVICE_INSTANCE.get() {
        Some(class) => match class.read() {
            Ok(class) => class,
            Err(e) => return Err(anyhow::anyhow!("Failed to acquire readlock for {}", e)),
        },
        None => {
            return Err(anyhow::anyhow!("Failed to get VPN class"));
        }
    };
    let class = &*class;
    // Create a dummy socket (your real code will pass an existing one)
    let socket = TcpSocket::new_v4().expect("Failed to create socket");
    let sock_fd = socket.as_raw_fd();

    // Call VpnService.protect(int fd)
    let protected = env
        .call_method(
            class,
            jni_str!("protect"),
            jni_sig!("(I)Z"),
            &[JValue::Int(sock_fd)],
        )?
        .z()?; // extract boolean

    if !protected {
        env.throw_new(
            jni_str!("java/lang/RuntimeException"),
            jni_str!("Failed to protect socket via VpnService.protect"),
        )?;
    }
    info!("TEST SOCKET PROTECTION Success");
    Ok(JObject::null())
}

fn test_socket<'a>() -> Result<JObject<'a>> {
    let vm = match JVM.get() {
        Some(jvm) => jvm,
        None => {
            error!("FAiled to get VM",);
            return Err(anyhow::anyhow!("Failed to get Java VM"));
        }
    };
    let class = match VPN_SERVICE_INSTANCE.get() {
        Some(class) => class,
        None => {
            error!("FAiled to get VM",);
            return Err(anyhow::anyhow!("Failed to get VPN class"));
        }
    };
    let env = vm.attach_current_thread(protect_socket)?;

    Ok(JObject::null())
}

async fn client_upgrade_request(tun_fd: AsyncFd<std::fs::File>, addr: SocketAddr) -> Result<()> {
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
    let socket = tcp.as_raw_fd();

    let vm = JVM.get().unwrap();
    let class = match VPN_SERVICE_INSTANCE.get() {
        Some(class) => match class.read() {
            Ok(class) => class,
            Err(e) => return Err(anyhow::anyhow!("Failed to acquire readlock for {}", e)),
        },
        None => {
            return Err(anyhow::anyhow!("Failed to get VPN class"));
        }
    };
    let class = &*class;

    let env = vm.attach_current_thread(|env| -> errors::Result<()> {
        let addr: core::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let socket = TcpSocket::new_v4().unwrap();
        let sock_fd = socket.as_raw_fd();
        let protected = env
            .call_method(
                class,
                jni_str!("protect"),
                jni_sig!("(I)Z"),
                &[jni::JValue::Int(sock_fd)],
            )?
            .z()?;
        if !protected {
            let msg = JNIString::from("Failed to protect socket VpnService.protect");
            env.throw_new(jni_str!("java/lang/RuntimeException"), msg)?
        }
        info!("Socket protected to {}", protected);
        Ok(())
    });

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
        Ok(upgraded) => client_upgraded_io(upgraded, tun_fd).await?,
        Err(e) => error!("upgrade error: {e}"),
    }

    Ok(())
}
fn create_tokio_runtime(fd: jint) -> Result<(), std::io::Error> {
    let rt = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            return Err(e);
        }
    };
    rt.block_on(async {
        tokio::select! {
            _ = is_canceled() => { // The token was cancelled, exit immediately
                info!("Tokio task shutting down gracefully.");
            }
            _ = async {
                spawn(async move {
                    test_socket();
                });
                match tun_read_loop(fd).await {
                    Ok(fd) => fd,
                    Err(e) => {
                        return error!("Rust loop error: {:?}", e)
                    }
                };
            } => {}
        }
    });
    Ok(())
}

pub struct ParcelFd {
    inner: ManuallyDrop<std::fs::File>,
}

impl ParcelFd {
    fn from_raw_fd(fd: RawFd) -> Self {
        ParcelFd {
            inner: unsafe { ManuallyDrop::new(std::fs::File::from_raw_fd(fd)) },
        }
    }
}
impl Drop for ParcelFd {
    fn drop(&mut self) {}
}
impl AsRawFd for ParcelFd {
    fn as_raw_fd(&self) -> RawFd {
        (&self.inner).as_raw_fd()
    }
}
impl<'a> std::io::Read for &'a ParcelFd {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        (&*self.inner).read(buf)
    }
}

impl<'a> std::io::Write for &'a ParcelFd {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (&*self.inner).write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        (&*self.inner).flush()
    }
}

pub fn tun_async_from_fd(fd: jint) -> Result<AsyncFd<ParcelFd>> {
    // Set non-blocking mode (required for Tokio AsyncFd)
    unsafe {
        let flags = libc::fcntl(fd as libc::c_int, libc::F_GETFL);
        libc::fcntl(fd as libc::c_int, libc::F_SETFL, flags | libc::O_NONBLOCK);
    };

    let file = unsafe { RawFd::from_raw_fd(fd) };
    Ok(AsyncFd::new(ParcelFd::from_raw_fd(file))?)
}

//
// 3. Async read loop with IPv4 header parsing
//
#[unsafe(no_mangle)]
pub async fn tun_read_loop(fd: jint) -> Result<()> {
    let mut buf = [0u8; 2048];

    let tun = tun_async_from_fd(fd)?;
    while let Ok(mut guard) = tun.readable().await {
        let n = match guard.try_io(|inner| {
            let mut file = inner.get_ref();
            file.read(&mut buf)
        }) {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),

            Err(_would_block) => continue,
        };
        if n < 20 {
            debug!("Packet too small for IPv4 header: {} bytes", n);
            continue;
        }

        let pkt = &mut buf[..n];

        let version = pkt[0] >> 4;
        let ihl = (pkt[0] & 0x0F) * 4;
        let tos = pkt[1];
        let total_len = u16::from_be_bytes([pkt[2], pkt[3]]);
        let id = u16::from_be_bytes([pkt[4], pkt[5]]);
        let flags_frag = u16::from_be_bytes([pkt[6], pkt[7]]);
        let ttl = pkt[8];
        let protocol = pkt[9];
        let checksum = u16::from_be_bytes([pkt[10], pkt[11]]);
        let src = std::net::Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        let dst = std::net::Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);

        debug!("IPv4 packet:");
        debug!("  version: {}", version);
        debug!("  ihl: {} bytes", ihl);
        debug!("  tos: {}", tos);
        debug!("  total_len: {}", total_len);
        debug!("  id: {}", id);
        debug!("  flags+frag: 0x{:04x}", flags_frag);
        debug!("  ttl: {}", ttl);
        debug!("  protocol: {}", protocol);
        debug!("  checksum: 0x{:04x}", checksum);
        debug!("  src: {}", src);
        debug!("  dst: {}", dst);
        let ihl = (pkt[0] & 0x0F) as usize * 4;
        if ihl < 20 || n < ihl + 8 {
            continue;
        }
        if protocol != 1 {
            continue;
        }

        if dst == std::net::Ipv4Addr::new(10, 10, 0, 3) {
            let icmp = &pkt[ihl..];
            if icmp[0] == 8 && icmp[1] == 0 {
                //handle_icmp_echo_reply(&tun, pkt, ihl).await?;
            }
        }
    }
    Ok(())
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);

    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    if let Some(&byte) = chunks.remainder().first() {
        sum += (byte as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

async fn handle_icmp_echo_reply(
    tun: &AsyncFd<std::fs::File>,
    pkt: &mut [u8],
    ihl: usize,
) -> Result<()> {
    // ICMP header starts after IPv4 header
    let icmp = &mut pkt[ihl..];

    // Convert Echo Request → Echo Reply
    icmp[0] = 0; // type = Echo Reply
    icmp[2] = 0;
    icmp[3] = 0;

    let icmp_checksum = checksum(icmp);
    icmp[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());

    // Swap IPv4 src/dst
    let src = [pkt[12], pkt[13], pkt[14], pkt[15]];
    let dst = [pkt[16], pkt[17], pkt[18], pkt[19]];

    pkt[12..16].copy_from_slice(&dst);
    pkt[16..20].copy_from_slice(&src);

    // Recompute IPv4 checksum
    pkt[10] = 0;
    pkt[11] = 0;

    let ipv4_checksum = checksum(&pkt[..ihl]);
    pkt[10..12].copy_from_slice(&ipv4_checksum.to_be_bytes());

    // Write reply back to TUN
    let mut guard = tun.writable().await?;
    match guard.try_io(|inner| inner.get_ref().write(pkt)) {
        Ok(Ok(_n)) => {
            // write succeeded
        }
        Ok(Err(e)) => return Err(e.into()), // write error
        Err(_would_block) => return Ok(()), // try again later
    }

    debug!("Sent ICMP Echo Reply to {}", std::net::Ipv4Addr::from(src));

    Ok(())
}

async fn client_upgraded_io(
    upgraded: hyper::upgrade::Upgraded,
    tun_fd: AsyncFd<std::fs::File>,
) -> Result<(), tokio::io::Error> {
    let mut upgraded_io = TokioIo::new(upgraded);
    // Create two tasks to pump data bidirectionally

    let (mut upgraded_read, mut upgraded_write) = tokio::io::split(upgraded_io);
    let mut guard = tun_fd.readable().await?;

    Ok(())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ru_valishin_vpn_MainActivity_stringFromJNI<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
) -> JString<'caller> {
    // Upgrade to full Env and run JNI code inside the closure
    let outcome = unowned_env.with_env(|env: &mut Env| -> Result<_, jni::errors::Error> {
        let output = "Hello from Rust";
        JString::from_str(env, output)
    });

    // Resolve errors/panics into a valid JNI return value
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}
//
// 4. Main
//
/*
#[tokio::main]
async fn main() -> Result<()> {
   debug!("Allocating TUN…");

    // empty name → kernel auto-assigns tun0, tun1, ...
    let mut name = [0u8; libc::IFNAMSIZ];

    let fd = tun_alloc(&mut name)?;

    let ifname = std::str::from_utf8(&name).unwrap().trim_end_matches('\0');

   debug!("Created TUN interface: {}", ifname);
   debug!("fd = {}", fd);
   debug!("Bring it up with:");
   debug!("  sudo ip addr add 10.0.0.1/24 dev {}", ifname);
   debug!("  sudo ip link set {} up", ifname);
   debug!("Then ping 10.0.0.2 to see packets.");

    let tun = tun_async(fd)?;

    tun_read_loop(tun).await?;

    Ok(())
}

use std::io::Write;

*/

/*use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};

use anyhow::Result as AnyResult;
use bytes::Bytes;
use clap::Parser;
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::header::{HeaderValue, UPGRADE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_tun::{Tun, TunBuilder};

mod tls_util;
mod client;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
type ClientMap = Arc<Mutex<HashMap<u64, mpsc::UnboundedSender<Vec<u8>>>>>;

#[derive(Parser, Debug, Clone)]
struct Args {
    #[arg(long, default_value = "0.0.0.0:8443")]
    listen: String,
    #[arg(long, default_value = "server.crt")]
    cert: String,
    #[arg(long, default_value = "server.key")]
    key: String,
    #[arg(long, default_value = "vpn0")]
    tun_name: String,
    #[arg(long)]
    tun_addr: Ipv4Addr,
    #[arg(long)]
    tun_mask: Ipv4Addr,

    #[arg(long)]
    client: bool,

    #[arg(long, default_value = "127.0.0.1:8443")]
    server: String,
}

// ---------- IPv4 helpers ----------

fn ipv4_to_u32(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

fn u32_to_ipv4(v: u32) -> Ipv4Addr {
    Ipv4Addr::from(v.to_be_bytes())
}

fn extract_ipv4_dst(pkt: &[u8]) -> Result<Ipv4Addr> {
    if pkt.len() < 20 {
        return Err("short IPv4 packet".into());
    }
    if pkt[0] >> 4 != 4 {
        return Err("not IPv4".into());
    }
    Ok(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
}

// ---------- tokio-tun helpers ----------

fn create_tun(name: &str, addr: Ipv4Addr, mask: Ipv4Addr) -> Result<Tun> {
    let tun = TunBuilder::new()
        .name(name)
        .address(addr)
        .netmask(mask)
        .up()
        .try_build()?;
    Ok(tun)
}


// ---------- Per-client server task ----------

async fn server_client_task(
    upgraded: Upgraded,
    clients: ClientMap,
    ip_alloc: Arc<AtomicU32>,
) -> Result<()> {
    let io = TokioIo::new(upgraded);
    //let (mut tls_r, mut tls_w) = tokio::io::split(io);

    let ip_u32 = ip_alloc.fetch_add(1, Ordering::Relaxed);
    ip_alloc.store(ip_u32, Ordering::Relaxed);
    let ip = u32_to_ipv4(ip_u32);
   debug!("Client assigned IP {}", ip);

    // Channel for TUN → this TLS
    let (tx_from_tun, mut rx_from_tun) = mpsc::unbounded_channel::<Vec<u8>>();

    // Register in routing table

    let mut map = clients.lock().await;
    map.insert(ip_u32, ClientHandle { tx_from_tun, io, ip_u32 });


    // TLS → TUN
    let tls_to_tun = async move {
        let mut buf = [0u8; 2000];
        loop {
            let n = tls_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            tx_to_client
                .send(buf[..n].to_vec())
                .map_err(|_| "tun_tx send failed")?;
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    };

    // TUN → TLS
    let tun_to_tls = async move {
        while let Some(pkt) = rx_from_tun.recv().await {
            tls_w.write_all(&pkt).await?;
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    };

    tokio::select! {
        r = tls_to_tun => { r?; }
        r = tun_to_tls => { r?; }
    }

    // Cleanup
    {
        let mut map = clients.lock().await;
        map.remove(&ip_u32);
    }

   debug!("Client {} disconnected", ip);
    Ok(())
}

// ---------- Server upgrade handler ----------

async fn server_upgrade(
    mut req: Request<Incoming>,
    tun_tx: mpsc::UnboundedSender<Vec<u8>>,
    clients: ClientMap,
    ip_alloc: Arc<AtomicU32>,
) -> Result<Response<Empty<Bytes>>> {
    let mut res = Response::new(Empty::new());

    if !req.headers().contains_key(UPGRADE) {
        *res.status_mut() = StatusCode::BAD_REQUEST;
        return Ok(res);
    }

    let tun_tx_clone = tun_tx.clone();
    let clients_clone = clients.clone();
    let ip_alloc_clone = ip_alloc.clone();

    tokio::spawn(async move {
        match hyper::upgrade::on(&mut req).await {
            Ok(upgraded) => {
                if let Err(e) =
                    server_client_task(upgraded, tun_tx_clone, clients_clone, ip_alloc_clone).await
                {
                    error!("client task error: {e}");
                }
            }
            Err(e) => error!("upgrade error: {e}"),
        }
    });

    *res.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    res.headers_mut().insert(UPGRADE, HeaderValue::from_static("vpn"));
    Ok(res)
}


// ---------- Main ----------

#[tokio::main]
async fn main() -> AnyResult<()> {
    let args = Args::parse();

    if args.client {
        let tun = create_tun(&args.tun_name, args.tun_addr, args.tun_mask)?;
        let server_addr: SocketAddr = args.server.parse()?;
        client::client_upgrade_request(server_addr, tun).await?;
        return Ok(());
    }

    // SERVER MODE
    let tun = create_tun(&args.tun_name, args.tun_addr, args.tun_mask)?;
    let tun = Arc::new(Mutex::new(tun));

    let cfg = tls_util::load_server_config(&args.cert, &args.key)?;
    let acceptor = TlsAcceptor::from(Arc::new(cfg));

    let addr: SocketAddr = args.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
   debug!("Server listening on {}", addr);

    let clients: ClientMap = Arc::new(Mutex::new(HashMap::new()));
    let base = ipv4_to_u32(args.tun_addr);
    let ip_alloc = Arc::new(AtomicU32::new(base));

    // Channel: clients → TUN writer
    let (tun_tx, mut tun_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // TUN writer
    {
        let tun_for_write = tun.clone();
        tokio::spawn(async move {
            while let Some(pkt) = tun_rx.recv().await {
                let mut t = tun_for_write.lock().await;
                if let Err(e) = t.write_all(&pkt).await {
                    error!("TUN write error: {e}");
                    break;
                }
            }
        });
    }

    // TUN reader
    {
        let tun_for_read = tun.clone();
        let clients_for_read = clients.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2000];
            loop {
                let n = {
                    let mut t = tun_for_read.lock().await;
                    match t.read(&mut buf).await {
                        Ok(n) => n,
                        Err(e) => {
                            error!("TUN read error: {e}");
                            break;
                        }
                    }
                };
                if n == 0 {
                    continue;
                }
                let pkt = &buf[..n];
                if let Ok(dst) = extract_ipv4_dst(pkt) {
                    let dst_u32 = ipv4_to_u32(dst);
                    let map = clients_for_read.lock().await;
                    if let Some(ch) = map.get(&dst_u32) {
                        let _ = ch.tx_to_client.send(pkt.to_vec());
                    }
                }
            }
        });
    }

    // Accept loop
    loop {
        let (tcp, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let tun_tx = tun_tx.clone();
        let clients = clients.clone();
        let ip_alloc = ip_alloc.clone();

        tokio::spawn(async move {
            let tls = match acceptor.accept(tcp).await {
                Ok(t) => t,
                Err(e) => {
                    error!("TLS error: {e}");
                    return;
                }
            };
            let io = TokioIo::new(tls);

            let conn = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        server_upgrade(
                            req,
                            tun_tx.clone(),
                            clients.clone(),
                            ip_alloc.clone(),
                        )
                    }),
                );
            let _ = conn.with_upgrades().await;
        });
    }
}
*/
