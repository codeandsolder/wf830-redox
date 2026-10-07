use std::{env, ffi::OsStr, io, process::ExitCode};

use gct_runtime::Modem;

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
    let mut path = None;
    for arg in env::args_os().skip(1) {
        if arg == OsStr::new("--help") {
            print_help();
            return Ok(());
        }
        if arg == OsStr::new("--no-startup-handshake") {
            if no_handshake {
                return Err(invalid_usage());
            }
            no_handshake = true;
        } else if path.replace(arg).is_some() {
            return Err(invalid_usage());
        }
    }

    let mut modem = match path {
        Some(path) => Modem::open(path)?,
        None => Modem::open_default()?,
    };

    if !no_handshake {
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
        "usage: gctd [--no-startup-handshake] [GLIF_PATH]",
    )
}

fn print_help() {
    println!(
        "gctd [GLIF_PATH]\n\
         gctd --no-startup-handshake\n\n\
         Opens /dev/glif0 (or GLIF_PATH), optionally emits the live P4 0x3337\n\
         startup handshake, then continuously decodes and logs typed P0 HCI events."
    );
}
