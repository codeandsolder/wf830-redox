use std::{env, ffi::OsStr, io, process::ExitCode};

use gct_runtime::{Modem, discover_startup_interface, verify_startup_interface};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("gctd: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> io::Result<()> {
    let mut no_handshake = false;
    let mut interface = None;
    let mut path = None;
    let mut args = env::args_os().skip(1);
    while let Some(arg) = args.next() {
        if arg == OsStr::new("--help") {
            print_help();
            return Ok(());
        }
        if arg == OsStr::new("--no-startup-handshake") {
            if no_handshake {
                return Err(invalid_usage());
            }
            no_handshake = true;
        } else if arg == OsStr::new("--interface") {
            let Some(value) = args.next() else {
                return Err(invalid_usage());
            };
            let value = value.into_string().map_err(|_| invalid_usage())?;
            if interface.replace(value).is_some() {
                return Err(invalid_usage());
            }
        } else if path.replace(arg).is_some() {
            return Err(invalid_usage());
        }
    }

    let startup_interface = if no_handshake {
        None
    } else {
        Some(match interface.as_deref() {
            Some(name) => verify_startup_interface(name)?,
            None => discover_startup_interface()?,
        })
    };

    let mut modem = match path {
        Some(path) => Modem::open(path)?,
        None => Modem::open_default()?,
    };

    if let Some(interface) = startup_interface {
        eprintln!(
            "gctd: startup interface {} (modem index {})",
            interface.name, interface.modem_index
        );
        modem.send_startup_handshake()?;
    }

    loop {
        let outcome = modem.poll_events_once(|event| match event {
            Ok(event) => eprintln!("gctd: {event:?}"),
            Err(error) => eprintln!("gctd: malformed known event: {error:?}"),
        })?;
        if outcome.bytes_read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "GLIF returned EOF",
            ));
        }
    }
}

fn invalid_usage() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: gctd [--no-startup-handshake] [--interface IFACE] [GLIF_PATH]",
    )
}

fn print_help() {
    println!(
        "gctd [--interface IFACE] [GLIF_PATH]\n\
         gctd --no-startup-handshake [GLIF_PATH]\n\n\
         Opens /dev/glif0 (or GLIF_PATH). Before the normal live-P4 0x3337\n\
         startup handshake it discovers the first lteNpdn0 interface, or checks\n\
         IFACE when supplied. Then it continuously decodes typed P0 HCI events."
    );
}
