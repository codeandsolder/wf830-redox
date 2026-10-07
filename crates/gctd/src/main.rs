use std::{
    env,
    ffi::OsStr,
    fs::File,
    io::{self, Read},
    os::unix::net::UnixDatagram,
    process::ExitCode,
    thread::{self, JoinHandle},
};

use gct_runtime::{
    Modem, StartupInterface, decode_event, discover_startup_interface, verify_startup_interface,
};
use gct_transport::{HciStreamDecoder, OEM_READ_BUFFER_LEN};
use lted_bridge::DeviceBridge;
use lted_compat::{Error as CompatError, Server};
use lted_proto::{Event, Packet, SdkApiRequest, parse_api_close};
use rustix::event::{PollFd, PollFlags, poll};

const LOCAL_FRAME_MAX: usize = 4 + 65_535;
const GLIF_READER_STACK: usize = 128 * 1024;
const GLIF_MESSAGE_DATA: u8 = 0;
const GLIF_MESSAGE_EOF: u8 = 1;
const GLIF_MESSAGE_ERROR: u8 = 2;

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
    let mut explicit_device_id = None;
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
        } else if arg == OsStr::new("--device-id") {
            let Some(value) = args.next() else {
                return Err(invalid_usage());
            };
            let value = value.into_string().map_err(|_| invalid_usage())?;
            let parsed = value.parse::<u32>().map_err(|_| invalid_usage())?;
            if parsed == 0 || explicit_device_id.replace(parsed).is_some() {
                return Err(invalid_usage());
            }
        } else if path.replace(arg).is_some() {
            return Err(invalid_usage());
        }
    }

    if no_handshake && interface.is_some() {
        return Err(invalid_usage());
    }

    let startup_interface = if no_handshake {
        None
    } else {
        Some(match interface.as_deref() {
            Some(name) => verify_startup_interface(name)?,
            None => discover_startup_interface()?,
        })
    };
    let device_id = resolve_device_id(startup_interface.as_ref(), explicit_device_id)?;

    let mut modem = match path {
        Some(path) => Modem::open(path)?,
        None => Modem::open_default()?,
    };

    if let Some(interface) = startup_interface {
        eprintln!(
            "gctd: startup interface {} (modem index {}, OEM device id {device_id})",
            interface.name, interface.modem_index
        );
        modem.send_startup_handshake()?;
    } else {
        eprintln!("gctd: startup handshake disabled; OEM device id {device_id}");
    }

    let mut server = Server::bind_oem()?;
    let reader_file = modem.transport().inner().try_clone()?;
    let (glif_rx, glif_tx) = UnixDatagram::pair()?;
    let _reader = spawn_glif_reader(reader_file, glif_tx)?;
    let mut bridge = DeviceBridge::new(device_id);
    daemon_loop(&mut modem, &mut server, &mut bridge, &glif_rx)
}

fn resolve_device_id(
    startup_interface: Option<&StartupInterface>,
    explicit: Option<u32>,
) -> io::Result<u32> {
    let derived = startup_interface
        .map(|interface| {
            interface.modem_index.checked_add(1).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "OEM modem index overflows device ID",
                )
            })
        })
        .transpose()?;

    match (derived, explicit) {
        (Some(derived), Some(explicit)) if derived != explicit => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("--device-id {explicit} disagrees with OEM lteNpdn0 mapping ({derived})"),
        )),
        (Some(derived), _) => Ok(derived),
        (None, Some(explicit)) => Ok(explicit),
        (None, None) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--device-id is required with --no-startup-handshake",
        )),
    }
}

fn spawn_glif_reader<R>(mut reader: R, notify: UnixDatagram) -> io::Result<JoinHandle<()>>
where
    R: Read + Send + 'static,
{
    thread::Builder::new()
        .name("gctd-glif-rx".to_owned())
        .stack_size(GLIF_READER_STACK)
        .spawn(move || {
            let mut message = vec![0_u8; OEM_READ_BUFFER_LEN + 1];
            loop {
                match reader.read(&mut message[1..]) {
                    Ok(0) => {
                        message[0] = GLIF_MESSAGE_EOF;
                        let _ = notify.send(&message[..1]);
                        break;
                    }
                    Ok(bytes_read) => {
                        message[0] = GLIF_MESSAGE_DATA;
                        if notify.send(&message[..=bytes_read]).is_err() {
                            break;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => {
                        message[0] = GLIF_MESSAGE_ERROR;
                        let errno = error.raw_os_error().unwrap_or(0).to_be_bytes();
                        message[1..5].copy_from_slice(&errno);
                        let _ = notify.send(&message[..5]);
                        break;
                    }
                }
            }
        })
}

#[derive(Debug, Default, Eq, PartialEq)]
struct ReadySources {
    common: bool,
    glif: bool,
    clients: Vec<u8>,
}

fn wait_ready(server: &Server, glif_rx: &UnixDatagram) -> io::Result<ReadySources> {
    let client_ids = server.client_ids();
    let mut fds = Vec::with_capacity(client_ids.len() + 2);
    fds.push(PollFd::new(server.common_socket(), PollFlags::IN));
    fds.push(PollFd::new(glif_rx, PollFlags::IN));
    for id in &client_ids {
        fds.push(PollFd::new(server.client_socket(*id)?, PollFlags::IN));
    }

    poll(&mut fds, None).map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?;
    for fd in &fds {
        let events = fd.revents();
        if events.intersects(PollFlags::ERR | PollFlags::NVAL)
            || (events.contains(PollFlags::HUP) && !events.contains(PollFlags::IN))
        {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("poll reported terminal fd state {events:?}"),
            ));
        }
    }

    let common = fds[0].revents().contains(PollFlags::IN);
    let glif = fds[1].revents().contains(PollFlags::IN);
    let clients = client_ids
        .into_iter()
        .zip(fds.iter().skip(2))
        .filter_map(|(id, fd)| fd.revents().contains(PollFlags::IN).then_some(id))
        .collect();
    Ok(ReadySources {
        common,
        glif,
        clients,
    })
}

fn daemon_loop(
    modem: &mut Modem<File>,
    server: &mut Server,
    bridge: &mut DeviceBridge,
    glif_rx: &UnixDatagram,
) -> io::Result<()> {
    let mut client_frame = vec![0_u8; LOCAL_FRAME_MAX];
    let mut glif_message = vec![0_u8; OEM_READ_BUFFER_LEN + 1];
    let mut decoder = HciStreamDecoder::new();

    loop {
        let ready = wait_ready(server, glif_rx)?;
        if ready.common {
            match server.accept_open_once() {
                Ok(Some(client)) => eprintln!(
                    "gctd: stock lted client {} opened ({:?})",
                    client.id, client.identity
                ),
                Ok(None) => eprintln!("gctd: rejected stock lted client: all slots occupied"),
                Err(CompatError::Protocol | CompatError::UnnamedPeer) => {
                    eprintln!("gctd: rejected malformed API-open datagram");
                }
                Err(CompatError::Io(error)) => return Err(error),
            }
        }

        for client_id in ready.clients {
            if let Err(error) =
                handle_client_datagram(modem, server, bridge, client_id, &mut client_frame)
            {
                eprintln!("gctd: client {client_id} datagram error: {error}");
                let _ = server.remove_client(client_id);
            }
        }

        if ready.glif {
            handle_glif_message(glif_rx, &mut glif_message, &mut decoder, server, bridge)?;
        }
    }
}

fn handle_client_datagram(
    modem: &mut Modem<File>,
    server: &mut Server,
    bridge: &mut DeviceBridge,
    client_id: u8,
    frame: &mut [u8],
) -> io::Result<()> {
    let len = server.recv_from_client(client_id, frame)?;
    let packet = Packet::parse(&frame[..len])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("{error:?}")))?;
    let event = match Event::try_from(packet.header.event) {
        Ok(event) => event,
        Err(error) => {
            eprintln!(
                "gctd: client {client_id} sent unknown event {:#06x}",
                error.0
            );
            return Ok(());
        }
    };

    match event {
        Event::ApiClose => {
            parse_api_close(packet).map_err(|error| {
                io::Error::new(io::ErrorKind::InvalidData, format!("{error:?}"))
            })?;
            let _ = server.remove_client(client_id);
            eprintln!("gctd: stock lted client {client_id} closed");
        }
        Event::SdkApi => {
            let request = SdkApiRequest::parse(packet).map_err(|error| {
                io::Error::new(io::ErrorKind::InvalidData, format!("{error:?}"))
            })?;
            match bridge.handle_sdk_api(server, modem, client_id, request) {
                Ok(call) => eprintln!(
                    "gctd: client {client_id} SDK command {} -> {} HCI bytes",
                    call.command as u16, call.bytes_written
                ),
                Err(error) => {
                    eprintln!("gctd: client {client_id} SDK request rejected: {error}");
                }
            }
        }
        other => {
            eprintln!("gctd: client {client_id} event {other:?} not implemented");
        }
    }
    Ok(())
}

fn handle_glif_message(
    glif_rx: &UnixDatagram,
    message: &mut [u8],
    decoder: &mut HciStreamDecoder,
    server: &mut Server,
    bridge: &mut DeviceBridge,
) -> io::Result<()> {
    let len = glif_rx.recv(message)?;
    let Some((&kind, payload)) = message[..len].split_first() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty GLIF reader notification",
        ));
    };
    match kind {
        GLIF_MESSAGE_DATA => {
            let mut route_error = None;
            decoder.feed(payload, |packet| match decode_event(packet) {
                Ok(event) => {
                    eprintln!("gctd: {event:?}");
                    if let Err(error) = bridge.handle_modem_event(server, &event) {
                        route_error = Some(io::Error::other(error.to_string()));
                    }
                }
                Err(error) => eprintln!("gctd: malformed known event: {error:?}"),
            });
            if let Some(error) = route_error {
                return Err(error);
            }
            Ok(())
        }
        GLIF_MESSAGE_EOF if payload.is_empty() => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "GLIF returned EOF",
        )),
        GLIF_MESSAGE_ERROR if payload.len() == 4 => {
            let errno = i32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            if errno == 0 {
                Err(io::Error::other("GLIF reader failed without an OS errno"))
            } else {
                Err(io::Error::from_raw_os_error(errno))
            }
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid GLIF reader notification",
        )),
    }
}

fn invalid_usage() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: gctd [--interface IFACE] [--device-id ID] [GLIF_PATH] | gctd --no-startup-handshake --device-id ID [GLIF_PATH]",
    )
}

fn print_help() {
    println!(
        "gctd [--interface IFACE] [--device-id ID] [GLIF_PATH]\n\
         gctd --no-startup-handshake --device-id ID [GLIF_PATH]\n\n\
         Opens /dev/glif0 (or GLIF_PATH), performs the recovered live-P4\n\
         startup handshake, binds the stock /var/tmp/lted-daemon ABI, and\n\
         routes proven SDK calls and modem callbacks. With a normal startup\n\
         interface, OEM device ID is derived as modem_index + 1; an explicit\n\
         ID must agree. Disabling startup discovery requires --device-id."
    );
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, os::unix::net::UnixDatagram};

    use gct_runtime::StartupInterface;
    use lted_compat::Server;

    use super::{
        GLIF_MESSAGE_DATA, GLIF_MESSAGE_EOF, ReadySources, resolve_device_id, spawn_glif_reader,
        wait_ready,
    };

    #[test]
    fn oem_device_id_is_one_based_modem_index() {
        let interface = StartupInterface {
            name: "lte0pdn0".to_owned(),
            modem_index: 0,
        };
        assert_eq!(resolve_device_id(Some(&interface), None).ok(), Some(1));

        let interface = StartupInterface {
            name: "lte7pdn0".to_owned(),
            modem_index: 7,
        };
        assert_eq!(resolve_device_id(Some(&interface), Some(8)).ok(), Some(8));
        assert!(resolve_device_id(Some(&interface), Some(7)).is_err());
        assert!(resolve_device_id(None, None).is_err());
        assert_eq!(resolve_device_id(None, Some(3)).ok(), Some(3));
    }

    #[test]
    fn glif_reader_preserves_read_boundaries_and_reports_eof() {
        let (rx, tx) = UnixDatagram::pair().unwrap_or_else(|_| std::process::abort());
        let reader = Cursor::new(vec![0x31, 0x2f, 0x00, 0x04, 0, 0, 0, 1]);
        let handle = spawn_glif_reader(reader, tx).unwrap_or_else(|_| std::process::abort());
        let mut frame = [0_u8; 32];

        let len = rx
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(frame[0], GLIF_MESSAGE_DATA);
        assert_eq!(&frame[1..len], &[0x31, 0x2f, 0x00, 0x04, 0, 0, 0, 1]);

        let len = rx
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(&frame[..len], &[GLIF_MESSAGE_EOF]);
        if handle.join().is_err() {
            std::process::abort();
        }
    }

    #[test]
    fn readiness_poll_distinguishes_common_and_glif_sources() {
        let base = std::env::temp_dir().join(format!("wf830-gctd-poll-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir(&base).unwrap_or_else(|_| std::process::abort());
        let mut server = Server::bind_paths(base.join("daemon"), base.join("client-"))
            .unwrap_or_else(|_| std::process::abort());
        let (glif_rx, glif_tx) = UnixDatagram::pair().unwrap_or_else(|_| std::process::abort());

        glif_tx
            .send(&[GLIF_MESSAGE_EOF])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            wait_ready(&server, &glif_rx).unwrap_or_else(|_| std::process::abort()),
            ReadySources {
                common: false,
                glif: true,
                clients: Vec::new(),
            }
        );

        let mut discard = [0_u8; 1];
        glif_rx
            .recv(&mut discard)
            .unwrap_or_else(|_| std::process::abort());
        let peer_path = base.join("peer");
        let peer = UnixDatagram::bind(&peer_path).unwrap_or_else(|_| std::process::abort());
        peer.send_to(&[0x01, 0x00, 0x00, 0x00], server.common_path())
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            wait_ready(&server, &glif_rx).unwrap_or_else(|_| std::process::abort()),
            ReadySources {
                common: true,
                glif: false,
                clients: Vec::new(),
            }
        );
        let _ = server.accept_open_once();

        drop(peer);
        drop(server);
        let _ = std::fs::remove_dir_all(base);
    }
}
