use anyhow::Result;
use tun::{Configuration, Device};

pub fn create_tun(name: &str, addr: &str, mask: &str) -> Result<Device> {
    let mut cfg = Configuration::default();
    cfg.tun_name(name)
        .address(addr)
        .netmask(mask)
        .up();

    Ok(tun::create(&cfg)?)
}
