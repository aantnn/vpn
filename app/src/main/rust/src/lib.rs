use std::error::Error;
use std::fmt::format;
use std::io::{Read, Write};
use std::mem::ManuallyDrop;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, RawFd};
use std::pin::Pin;
use std::sync::{Arc, OnceLock, RwLock};
use std::task::{ready, Context as stdContext, Poll};
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
use tokio::sync::mpsc;

// A global channel to send the newly generated file descriptor from Java (networkChange -> establish -> new FD)
// down into the async Rust loop so it seamlessly replaces the old tunnel.
static FD_CHANNEL: OnceLock<RwLock<tokio::sync::mpsc::Sender<jint>>> = OnceLock::new();
static JVM: OnceLock<JavaVM> = OnceLock::new();
static JVM_CTX: OnceLock<Arc<JvmVpnService>> = OnceLock::new();
static CANCEL: OnceLock<Arc<CancellationController>> = OnceLock::new();

fn get_static<T>(env: &mut jni::Env, cell: &'static OnceLock<T>, name: &str) -> jni::errors::Result<&'static T> {
    cell.get().ok_or_else(|| {
        let msg = format!("{name} uninitialized");
        throw_jni_error::<JObject>(env, &msg).unwrap_err()
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn JNI_OnLoad(
    vm: *mut jni::sys::JavaVM,
    _reserved: *mut std::ffi::c_void,
) -> i32 {
    let jvm = unsafe { JavaVM::from_raw(vm) };
    let _ = JVM.set(jvm);
    jni::sys::JNI_VERSION_1_6
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

    pub fn protect_fd(&self, fd: BorrowedFd ) -> Result<()> {
        let class_guard = self
            .vpn_class
            .read()
            .map_err(|_| anyhow!("Failed to read vpn_class"))?;

        // attach_current_thread returns jni::errors::Result<T>
        self.jvm.attach_current_thread(|env: &mut jni::Env| {
            Self::call_protect(env, &*class_guard, fd.as_raw_fd())
        })?;

        Ok(())
    }

    fn call_protect(env: &mut jni::Env, class: &Global<JClass>, fd: RawFd) -> Result<()> {
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

    fn flush(&mut self, ) -> std::io::Result<()> {
        (&*self.inner).flush()
    }
}

fn throw_jni_error<T>(env: &mut jni::Env, msg: &str) -> jni::errors::Result<T> {
    log::error!("{}", msg);
    env.throw_new(jni_str!("java/lang/RuntimeException"), JNIString::from(msg));
    Err(jni::errors::Error::JavaException)
}

// ---------- Global runtime state + JNI entrypoints ----------


fn init_vars<'a>(env:&mut jni::Env, class: JClass<'a>) -> jni::errors::Result<JObject<'a>> {
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Trace)
            .with_tag("VPN_APP"),
    );

    log::info!("initRust: STARTING INITIALIZATION...");

    // Initialize Cancellation Token
    CANCEL.get_or_init(|| Arc::new(CancellationController::new()));

    // Initialize JVM Context
    if JVM_CTX.get().is_none() {
        let jvm = get_static(env, &JVM, "JVM")?;
        let global = env.new_global_ref(class).map_err(|e| {
            let msg = format!("Failed to create global ref: {e}");
            throw_jni_error::<()>(env, &msg).unwrap_err()
        })?;

        let _ = JVM_CTX.set(Arc::new(JvmVpnService::new(jvm, global)));
        log::info!("initRust: JVM_CTX populated.");
    }

    log::info!("initRust: SUCCESS.");
    Ok(JObject::null())
}
#[unsafe(no_mangle)]
pub extern "C" fn Java_ru_valishin_vpn_MyVpnService_initRust<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    class: JClass<'caller>,
) -> JObject<'caller> {
    let outcome = unowned_env.with_env(|env: &mut jni::Env| { init_vars(env, class ) });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

fn get_cancellation_controller(env: &mut jni::Env) -> jni::errors::Result<Arc<CancellationController>> {
    match CANCEL.get() {
        Some(lock) => {
            Ok(lock.clone())
        },
        None => {
            let msg = format!("CANCEL token uninitialized: runRustVpnLoop");
            return throw_jni_error(env, &msg)
        }
    }
}
fn run_main_loop<'a>(env: &mut jni::Env, tun_fd: jint) -> jni::errors::Result<JObject<'a>> {
    log::info!("runRustVpnLoop: Starting with FD {tun_fd}");

    let cancel = get_static(env, &CANCEL, "CANCEL")?.clone();
    let runtime = VpnRuntime::new(cancel);

    runtime.run(async move || {
        let (tx, rx) = tokio::sync::mpsc::channel::<jint>(1);
        // Update or Set the FD_CHANNEL
        if let Some(lock) = FD_CHANNEL.get() {
            let mut guard = lock.write().map_err(|_| {
                let msg = "FD_CHANNEL lock poisoned";
                throw_jni_error::<()>(env, msg).unwrap_err()
            })?;
            *guard = tx;
        } else {
            FD_CHANNEL.set(RwLock::new(tx)).map_err(|_| {
                let msg = "Failed to set FD_CHANNEL";
                throw_jni_error::<()>(env, msg).unwrap_err()
            })?;
        }

        tun_reconnect_manager_loop(tun_fd, rx).await.map_err(|e| {
            let msg = format!("VPN Loop Error: {e:?}");
            throw_jni_error::<()>(env, &msg).unwrap_err()
        })?;

        Ok(JObject::null())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn Java_ru_valishin_vpn_MyVpnService_runRustVpnLoop<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    tun_fd: jint,
) -> JObject<'caller> {
    let outcome = unowned_env.with_env(|env| {
        run_main_loop(env, tun_fd)
    });
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}


fn request_shutdown<'a>(env: &mut jni::Env) -> jni::errors::Result<JObject<'a>> {
    let cancel = get_static(env, &CANCEL, "CANCEL")?;
    cancel.cancel()
        .and_then(|_| cancel.renew())
        .map_err(|e| {
            let msg = format!("Shutdown/Renew failed: {e}");
            throw_jni_error::<()>(env, &msg).unwrap_err()
        })?;
    Ok(JObject::null())
}
#[unsafe(no_mangle)]
pub extern "C" fn Java_ru_valishin_vpn_MyVpnService_requestRustShutdown<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
) -> JObject<'caller>{
    let outcome = unowned_env.with_env(request_shutdown);
    outcome.resolve::<ThrowRuntimeExAndDefault>()
}

// ----------------------------------------------------------------------
// JNI ENDPOINT for Network Changes
// Call this from Java when a ConnectivityManager detects a network change
// to seamlessly transition the networking background loop.
// ----------------------------------------------------------------------

fn handle_reconnection<'a>(env: &mut jni::Env, new_tun_fd: jint) -> jni::errors::Result<JObject<'a>> {
    log::info!("reconnectRustTunnel JNI CALL STARTED: Attempting to replace FD with new FD: {}", new_tun_fd);
    let lock = get_static(env, &FD_CHANNEL, "FD_CHANNEL")?;

    // 2. Access the channel
    let tx = lock.read().map_err(|_| {
        let msg = "FD_CHANNEL lock poisoned";
        throw_jni_error::<()>(env, msg).unwrap_err()
    })?;
    // 3. Send the FD
    tx.try_send(new_tun_fd).map_err(|e| {
        let msg = format!("Reconnect failed: {e}");
        throw_jni_error::<()>(env, &msg).unwrap_err()
    })?;
        log::info!("reconnectRustTunnel: SUCCESS - Sent new FD {} down the async pipeline!", new_tun_fd);
        Ok(JObject::null())
}

#[unsafe(no_mangle)]
pub extern "C" fn Java_ru_valishin_vpn_MyVpnService_reconnectRustTunnel<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    new_tun_fd: jint,
) -> JObject<'caller> {
    let outcome = unowned_env.with_env(|env| { handle_reconnection(env, new_tun_fd)});
    outcome.resolve::<ThrowRuntimeExAndDefault>()
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
        Some(jvm) => { jvm
        },
        None => {
            error!("Failed to get VM",);
            return Err(anyhow::anyhow!("Failed to get Java VM"));
        }
    };
    let vpn_svc = match JVM_CTX.get() {
        Some(vpn_svc) => {
           vpn_svc
        },
        None => {
            error!("FAiled to get VM",);
            return Err(anyhow::anyhow!("Failed to get VPN class"));
        }
    };
    let socket = TcpSocket::new_v4().expect("Failed to create socket");
    vpn_svc.protect_fd(socket.as_fd())?;

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

async fn handle_icmp_echo_reply<'a>(tun: Arc<BorrowedAsyncDevice<'a>>, pkt: &mut [u8], ihl: usize) -> Result<()> {
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
    let mut guard = tun.send(pkt).await?;
    log::debug!("Sent ICMP Echo Reply to {}", std::net::Ipv4Addr::from(src));

    Ok(())
}

// --- NETWORK CHANGE / RECONNECT MANAGER ---
// This acts as the outer wrapper. It spins up the `tun_read_loop` and listens for
// either (A) The loop failing due to Java closing the old FD natively, or (B) A new FD arriving from Java.
pub async fn tun_reconnect_manager_loop(initial_fd: jint, mut rx: tokio::sync::mpsc::Receiver<jint>) -> Result<()> {
    log::info!("tun_reconnect_manager_loop: ENTERED");
    let mut current_fd = initial_fd;

    loop {
        log::info!("tun_reconnect_manager_loop: Starting tracking block for inner VPN loop on FD: {}", current_fd);

        tokio::select! {
            loop_result = tun_read_loop(current_fd) => {
                match loop_result {
                    Ok(_) => {
                        log::info!("tun_reconnect_manager_loop: Inner loop exited natively cleanly (rare)");
                        break;
                    },
                    Err(e) => {
                        log::warn!("tun_reconnect_manager_loop: Inner loop CRASHED/ENDED! (EBADF usually means Android actively closed the connection via 'oldInterface?.close()'): {}", e);
                        log::info!("tun_reconnect_manager_loop: **PAUSED SLEEP STATE** -> Waiting securely inside select! for Java to call reconnectRustTunnel() and supply the new FD...");
                    }
                }
            },
            // This runs if Java catches the network change *before* the inner read loop throws an error.
            Some(new_fd) = rx.recv() => {
                log::info!("tun_reconnect_manager_loop: Preemptive network change triggered via JVM! select! is dropping the old read loop instantly. Applying FD {}", new_fd);
                current_fd = new_fd;
            }
        }
    }

    log::info!("tun_reconnect_manager_loop: FINISHED and EXITING fully.");
    Ok(())
}

#[unsafe(no_mangle)]
pub async fn tun_read_loop(fd: jint) -> Result<()> {
    log::info!("tun_read_loop: ENTERED with fd={}", fd);
    unsafe {
        log::info!("tun_read_loop: Setting libc::O_NONBLOCK flag on FD...");
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    use tun_rs::BorrowedAsyncDevice;
    log::info!("tun_read_loop: Borrowing raw AsyncDevice via tun-rs...");
    let dev = unsafe { BorrowedAsyncDevice::borrow_raw(fd)? };

    let mut buf = [0; 65535];
    let dev = Arc::new(dev);
    let read = dev.clone();
    let write = dev.clone();

    log::info!("tun_read_loop: Entering intensive async polling packet loop!!!");
    loop {
        let n = match read.recv(&mut buf).await {
            Ok(bytes) => {
                // log::info!("tun_read_loop: Successfully received {} bytes natively.", bytes);
                bytes
            },
            Err(e) => {
                log::warn!("tun_read_loop: dev.recv(&mut buf) THREW NATIVE ERROR: {}", e);
                return Err(anyhow::anyhow!("Failed to read from TUN: {}", e));
            }
        };

        if n < 20 {
            log::debug!("Packet too small for IPv4 header: {} bytes", n);
            continue;
        }

        let pkt = &mut buf[..n];

        let version = pkt[0] >> 4;
        if version != 4 {
            // log::debug!("tun_read_loop: Dropping completely non-v4 packet length {}", n);
            continue;
        }

        let protocol = pkt[9];
        let dst = std::net::Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        let src = std::net::Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);

        // Uncomment below strictly if making huge IP dumps
        // log::info!("tun_read_loop: INGRESS PACKET - proto: {}, src: {}, dst: {}, size: {}", protocol, src, dst, n);
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

        log::info!("IPv4 packet:");
        log::info!("  version: {}", version);
        log::info!("  ihl: {} bytes", ihl);
        log::info!("  tos: {}", tos);
        log::info!("  total_len: {}", total_len);
        log::info!("  id: {}", id);
        log::info!("  flags+frag: 0x{:04x}", flags_frag);
        log::info!("  ttl: {}", ttl);
        log::info!("  protocol: {}", protocol);
        log::info!("  checksum: 0x{:04x}", checksum);
        log::info!("  src: {}", src);
        log::info!("  dst: {}", dst);
        let ihl = (pkt[0] & 0x0F) as usize * 4;
        if ihl < 20 || n < ihl + 8 {
            //continue;
        }

        //stream.write_all(pkt).await?;

        if protocol != 1 {
            continue;
        }

        if dst == std::net::Ipv4Addr::new(10, 10, 0, 3) {
            let icmp = &pkt[ihl..];
            if icmp[0] == 8 && icmp[1] == 0 {
                handle_icmp_echo_reply(write.clone(), pkt, ihl).await?;
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
use std::ops::Deref;
use libc::write;
use tokio::io::{AsyncRead, AsyncWrite};
use tun_rs::BorrowedAsyncDevice;

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
        cx: &mut stdContext<'_>,
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
        cx: &mut stdContext<'_>,
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
        cx: &mut stdContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        // tcp flush is a no-op
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut stdContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.inner.get_ref().shutdown(std::net::Shutdown::Write)?;
        Poll::Ready(Ok(()))
    }
}
