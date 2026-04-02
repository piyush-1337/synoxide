use std::io::Read;

use synoxide::parse_header;
use tun::Configuration;

fn main() {
    let mut config = Configuration::default();

    config
        .tun_name("tun0")
        .address((10, 0, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();

    config.platform_config(|config| {
        config.ensure_root_privileges(true);
    });

    let mut dev = tun::create(&config).expect("Failed to create TUN device");

    let mut buf = [0u8; 1504];

    loop {
        let n = dev.read(&mut buf).expect("Failed to read from device");
        let packet = &buf[..n];

        match parse_header(packet) {
            Ok(header) => {
                println!("{:?}", header);
            },
            Err(e) => {
                eprintln!("{e}");
            },
        }
    }
}
