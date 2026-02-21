use std::error::Error;
use std::fmt::format;
use std::io::{Read, Write};
use std::mem::ManuallyDrop;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::pin::Pin;
use std::sync::{Arc, OnceLock, RwLock};
use std::task::{ready, Context, Poll};
use anyhow::{Result, anyhow, Context};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use jni::errors::{JniError, ThrowRuntimeExAndDefault};
use jni::objects::{Global, JClass, JObject, JValue};
use jni::strings::JNIString;
use jni::sys::{JNI_VERSION_1_6, jint};
use jni::{EnvUnowned, JavaVM, jni_sig, jni_str, errors};
use log::{LevelFilter, error};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::io::unix::AsyncFd;
use tokio::net::{TcpSocket, TcpStream};
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn JNI_OnLoad(
    vm: *mut jni::sys::JavaVM,
    _reserved: *mut std::ffi::c_void,
) -> i32 {
    let jvm = unsafe { JavaVM::from_raw(vm) };
    match JVM.set(jvm) {
        Ok(()) => 0,
        Err(e) => {
            log::error!("Failed to set java VM: JNI_Onload");
            return jni::sys::JNI_ERR;
        }
    };
    JNI_VERSION_1_6
}

// ---------- CancellationController ----------

pub struct CancellationController {
    token: RwLock<CancellationToken>,
}

impl CancellationController {
    pub fn new() -> Self {
        Self {
            token: RwLock::new(CancellationToken::new()),
        }
    }

    pub fn cancel(&self) -> Result<()> {
        let guard = self
            .token
            .read()
            .map_err(|_| anyhow!("Cancellation token poisoned (read)"))?;

        guard.cancel();
        Ok(())
    }

    pub fn renew(&self) -> Result<()> {
        let mut guard = self
            .token
            .write()
            .map_err(|_| anyhow!("Cancellation token poisoned (write)"))?;

        *guard = CancellationToken::new();
        Ok(())
    }

    pub async fn cancelled(&self) -> Result<()> {
        let guard = self
            .token
            .read()
            .map_err(|_| anyhow!("Cancellation token poisoned (read)"))?;

        guard.cancelled().await;
        Ok(())
    }
}

pub struct JvmVpnService {
    jvm: &'static JavaVM,
    vpn_class: RwLock<Global<JClass<'static>>>,
}

impl JvmVpnService {
    pub fn new(jvm: &'static JavaVM, class: Global<JClass>) -> Self {
        Self {
            jvm,
            vpn_class: RwLock::new(class),
        }
    }

    pub fn protect_fd(&self, fd: i32) -> Result<()> {
        let class_guard = self
            .vpn_class
            .read()
            .map_err(|_| anyhow!("Failed to read vpn_class"))?;

        // attach_current_thread returns jni::errors::Result<T>
        self.jvm.attach_current_thread(|env: &mut jni::Env| {
            Self::call_protect(env, &*class_guard, fd)
        })?;

        Ok(())
    }

    fn call_protect(env: &mut jni::Env, class: &Global<JClass>, fd: i32) -> Result<()> {
        let result = env
            .call_method(
                class,
                jni_str!("protect"),
                jni_sig!("(I)Z"),
                &[JValue::Int(fd)],
            )
            .map_err(|e| anyhow!("JNI protect() call failed: {e}"))?
            .z()
            .map_err(|e| anyhow!("JNI boolean extraction failed: {e}"))?;

        if !result {
            return Err(anyhow!("VpnService.protect returned false"));
        }

        Ok(())
    }
}

// ---------- VpnRuntime ----------

pub struct VpnRuntime {
    cancel: Arc<CancellationController>,
}

impl VpnRuntime {
    pub fn new(cancel: Arc<CancellationController>) -> Self {
        Self { cancel }
    }
    pub fn run<'a, F, Fut>(&self, f: F) -> jni::errors::Result<JObject<'a>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = jni::errors::Result<JObject<'a>>>,
    {
        let rt = Runtime::new().map_err(|e| jni::errors::Error::JavaException)?;
        rt.block_on(async {
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    log::info!("Shutdown requested"); Ok(JObject::null())
                }
                result = f() => { result }
            }
        })
    }
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

// ---------- Global runtime state + JNI entrypoints ----------
static JVM: OnceLock<JavaVM> = OnceLock::new();
static JVM_CTX: OnceLock<Arc<JvmVpnService>> = OnceLock::new();
static CANCEL: OnceLock<Arc<CancellationController>> = OnceLock::new();

#[unsafe(no_mangle)]
pub extern "C" fn Java_ru_valishin_vpn_MyVpnService_initRust<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    class: JClass<'caller>,
) -> JObject<'caller> {
    let outcome = unowned_env.with_env(|env: &mut jni::Env| -> jni::errors::Result<JObject<'_>> {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(LevelFilter::Trace) // Set global log level
                .with_tag("VPN_APP"), // The tag shown in logcat
        );
        let global = match env.new_global_ref(class) {
            Ok(g) => g,
            Err(e) => {
                let msg = format!("Couldn't get global reference for VpnService: initRust {}", e);
                log::error!("{}", msg);
                env.throw_new(jni_str!("java/lang/RuntimeException"), JNIString::from(msg));
                return Err(jni::errors::Error::JavaException)
            }
        };

        let jvm = match JVM.get() {
            Some(jvm) => jvm,
            None => {
                let msg = format!("Couldn't get global reference for JVM: initRust");
                log::error!("{}", msg);
                env.throw_new(jni_str!("java/lang/RuntimeException"), JNIString::from(msg));
                return Err(jni::errors::Error::JavaException)
            }
        };

        let ctx = Arc::new(JvmVpnService::new(jvm, global));
        let _ = match JVM_CTX.set(ctx){
            Ok(_) => (),
            Err(_) => {
                let msg = format!("Couldn't set JVM_CTX reference: initRust");
                log::error!("{}", msg);
                env.throw_new(jni_str!("java/lang/RuntimeException"), JNIString::from(msg));
                return Err(jni::errors::Error::JavaException)
            }
        };

        let cancel = Arc::new(CancellationController::new());
        let _ = match CANCEL.set(cancel) {
            Ok(_) => (),
            Err(_) => {
                let msg = format!("Couldn't set Cancelation token: initRust");
                log::error!("{}", msg);
                env.throw_new(jni_str!("java/lang/RuntimeException"), JNIString::from(msg));
                return Err(jni::errors::Error::JavaException)
            }
        };
        Ok(JObject::null())
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}


#[unsafe(no_mangle)]
pub extern "system" fn Java_ru_valishin_vpn_MyVpnService_runRustVpnLoop<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    tun_fd: jint,
) -> JObject<'caller>  {
    let outcome = unowned_env.with_env(|env| -> jni::errors::Result<_>  {
        let cancel = match CANCEL.get() {
            Some(cancel) => cancel,
            None => {
                let msg = "runRustVpnLoop called before initRust or CancellationController not initialized";
                log::error!("{}", msg);
                env.throw_new(jni_str!("java/lang/RuntimeException"), JNIString::from(msg));
                return Err(jni::errors::Error::JavaException)
            }
        };
        let runtime  = VpnRuntime::new(cancel.clone());
        runtime.run(async || -> jni::errors::Result<JObject> {
            log::info!("Running TUN loop on fd {tun_fd}");
           /* tokio::spawn(async move {
                test_socket();
            });*/
            match tun_read_loop(tun_fd).await {
                Ok(_) => Ok(JObject::null()),
                Err(e) => {
                    let msg = format!("Tun_read_loop failed: {:?}", e);
                    //log::error!("{}", msg);
                    env.throw_new(jni_str!("java/lang/RuntimeException"), JNIString::from(msg));
                    Err(jni::errors::Error::JavaException)
                },
            }
        })
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}



#[unsafe(no_mangle)]
pub extern "C" fn Java_ru_valishin_vpn_MyVpnService_requestRustShutdown(
    mut unowned_env: EnvUnowned,
    _class: JClass,
) {
    let outcome = unowned_env.with_env(|env| -> jni::errors::Result<()> {
        // Ensure CANCEL is initialized
        let cancel = match CANCEL.get() {
            Some(c) => c,
            None => {
                let msg = "CancellationController not initialized";
                log::error!("{msg}");
                return env.throw_new(jni_str!("java/lang/RuntimeException"), JNIString::from(msg));
            }
        };

        // Try to cancel
        if let Err(e) = cancel.cancel() {
            let msg = format!("Failed to cancel token: {}", e);
            log::error!("{msg}");
            return env.throw_new(jni_str!("java/lang/RuntimeException"), JNIString::from(msg));
        }

        // Try to renew
        if let Err(e) = cancel.renew() {
            let msg = format!("Failed to renew token: {}", e);
            log::error!("{msg}");
            return env.throw_new(jni_str!("java/lang/RuntimeException"), JNIString::from(msg));
        }

        Ok(())
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>();
}

fn tun_async_from_fd(fd: RawFd) -> Result<AsyncFd<ParcelFd>> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let parcel = ParcelFd::from_raw_fd(fd);
    AsyncFd::new(parcel).map_err(|e| anyhow!("AsyncFd error: {e}"))
}

fn test_socket() -> Result<()> {
    let vm = match JVM.get() {
        Some(jvm) => jvm,
        None => {
            error!("Failed to get VM",);
            return Err(anyhow::anyhow!("Failed to get Java VM"));
        }
    };
    let vpn_svc = match JVM_CTX.get() {
        Some(class) => class,
        None => {
            error!("FAiled to get VM",);
            return Err(anyhow::anyhow!("Failed to get VPN class"));
        }
    };
    let socket = TcpSocket::new_v4().expect("Failed to create socket");
    let sock_fd = socket.as_raw_fd();
    vpn_svc.protect_fd(sock_fd)?;

    Ok(())
}

//
// 3. Async read loop with IPv4 header parsing
//
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

async fn handle_icmp_echo_reply(tun: &AsyncFd<ParcelFd>, pkt: &mut [u8], ihl: usize) -> Result<()> {
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

    log::debug!("Sent ICMP Echo Reply to {}", std::net::Ipv4Addr::from(src));

    Ok(())
}

#[unsafe(no_mangle)]
pub async fn tun_read_loop(fd: jint) -> Result<()> {
    let mut buf = [0u8; 2048];
    // 2. Connect to server
    let mut stream = std::net::TcpStream::connect("192.168.1.169:8080").unwrap();
    let mut stream = AsyncTcpStream::new(stream).unwrap();
        stream.read(&mut buf).await.with_context(|| "Failed to connect to 192.168.1.169:8080 in tun_read_loop".to_string())?; // 3. Send a simple HTTP-ish header once
    let http_header = b"POST /tunnel HTTP/1.1\r\nHost: example\r\n\r\n";
    stream.set_nodelay(true)?;
    stream.write_all(http_header).await?;


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
            log::debug!("Packet too small for IPv4 header: {} bytes", n);
            continue;
        }

        let pkt = &mut buf[..n];

        let version = pkt[0] >> 4;
        if version != 4 {
            continue;
        }
        let ihl = (pkt[0] & 0x0F) * 4;
        let tos = pkt[1];
        let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        let id = u16::from_be_bytes([pkt[4], pkt[5]]);
        let flags_frag = u16::from_be_bytes([pkt[6], pkt[7]]);
        let ttl = pkt[8];
        let protocol = pkt[9];
        let checksum = u16::from_be_bytes([pkt[10], pkt[11]]);
        let src = std::net::Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        let dst = std::net::Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);

        log::debug!("IPv4 packet:");
        log::debug!("  version: {}", version);
        log::debug!("  ihl: {} bytes", ihl);
        log::debug!("  tos: {}", tos);
        log::debug!("  total_len: {}", total_len);
        log::debug!("  id: {}", id);
        log::debug!("  flags+frag: 0x{:04x}", flags_frag);
        log::debug!("  ttl: {}", ttl);
        log::debug!("  protocol: {}", protocol);
        log::debug!("  checksum: 0x{:04x}", checksum);
        log::debug!("  src: {}", src);
        log::debug!("  dst: {}", dst);
        let ihl = (pkt[0] & 0x0F) as usize * 4;
        if ihl < 20 || n < ihl + 8 {
            //continue;
        }

        stream.write_all(pkt).await?;

        if protocol != 1 {
            continue;
        }

        if dst == std::net::Ipv4Addr::new(10, 10, 0, 3) {
            let icmp = &pkt[ihl..];
            if icmp[0] == 8 && icmp[1] == 0 {
                handle_icmp_echo_reply(&tun, pkt, ihl).await?;
            }
        }
    }
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


use std::io::{self};
use tokio::io::{AsyncRead, AsyncWrite};

pub struct AsyncTcpStream {
    inner: AsyncFd<std::net::TcpStream>,
}

impl AsyncTcpStream {
    pub fn new(tcp: std::net::TcpStream) -> std::io::Result<Self> {
        tcp.set_nonblocking(true)?;
        Ok(Self {
            inner: AsyncFd::new(tcp)?,
        })
    }

    pub async fn read(&self, out: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let mut guard = self.inner.readable().await?;

            match guard.try_io(|inner| inner.get_ref().read(out)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;

            match guard.try_io(|inner| inner.get_ref().write(buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}


impl tokio::io::AsyncRead for AsyncTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>
    ) -> Poll<std::io::Result<()>> {
        loop {
            let mut guard = ready!(self.inner.poll_read_ready(cx))?;

            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|inner| inner.get_ref().read(unfilled)) {
                Ok(Ok(len)) => {
                    buf.advance(len);
                    return Poll::Ready(Ok(()));
                },
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl tokio::io::AsyncWrite for AsyncTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8]
    ) -> Poll<std::io::Result<usize>> {
        loop {
            let mut guard = ready!(self.inner.poll_write_ready(cx))?;

            match guard.try_io(|inner| inner.get_ref().write(buf)) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        // tcp flush is a no-op
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.inner.get_ref().shutdown(std::net::Shutdown::Write)?;
        Poll::Ready(Ok(()))
    }
}