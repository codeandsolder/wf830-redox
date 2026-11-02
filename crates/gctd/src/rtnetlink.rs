use std::{
    fs, io,
    os::{
        fd::{AsFd, BorrowedFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
};

use rustix::net::{self, AddressFamily, SocketType, netlink::SocketAddrNetlink};

const NETLINK_BUFFER_LEN: usize = 4096;
const NLMSG_HEADER_LEN: usize = 16;
const PREFIX_MESSAGE_LEN: usize = 12;
const RTATTR_HEADER_LEN: usize = 4;

const NLMSG_ERROR: u16 = 2;
const RTM_NEWLINK: u16 = 16;
const RTM_NEWPREFIX: u16 = 52;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const IFINFO_MESSAGE_LEN: usize = 16;
const IFLA_MTU: u16 = 4;
const SET_MTU_SEQUENCE: u32 = 1;
const SET_MTU_REQUEST_LEN: usize = NLMSG_HEADER_LEN + IFINFO_MESSAGE_LEN + 8;
const RTMGRP_IPV6_PREFIX: u32 = 0x0002_0000;
const AF_INET6: u8 = 10;
const ND_OPT_PREFIX_INFORMATION: u8 = 3;
const PREFIX_ADDRESS: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Ipv6PrefixEvent {
    pub(crate) interface_index: u32,
    pub(crate) prefix_length: u8,
    pub(crate) prefix: [u8; 16],
}

pub(crate) struct Ipv6PrefixSource {
    socket: OwnedFd,
    buffer: [u8; NETLINK_BUFFER_LEN],
}

impl Ipv6PrefixSource {
    /// Subscribe to the same rtnetlink IPv6-prefix multicast group as the live
    /// P4 SDK's `ipv6_evt_init` helper.
    pub(crate) fn bind() -> io::Result<Self> {
        let socket =
            net::socket(AddressFamily::NETLINK, SocketType::RAW, None).map_err(errno_to_io)?;
        net::bind(&socket, &SocketAddrNetlink::new(0, RTMGRP_IPV6_PREFIX)).map_err(errno_to_io)?;
        Ok(Self {
            socket,
            buffer: [0; NETLINK_BUFFER_LEN],
        })
    }

    /// Receive one rtnetlink datagram and return every proven IPv6 prefix
    /// notification it contains.
    pub(crate) fn receive(&mut self) -> io::Result<Vec<Ipv6PrefixEvent>> {
        let len = rustix::io::read(&self.socket, &mut self.buffer).map_err(errno_to_io)?;
        decode_ipv6_prefix_events(&self.buffer[..len])
    }
}

impl AsFd for Ipv6PrefixSource {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }
}

pub(crate) fn interface_name(interface_index: u32) -> io::Result<Option<String>> {
    for entry in fs::read_dir("/sys/class/net")? {
        let entry = entry?;
        let path = entry.path();
        let index = match fs::read_to_string(path.join("ifindex")) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let Ok(index) = index.trim().parse::<u32>() else {
            continue;
        };
        if index != interface_index {
            continue;
        }
        return Ok(entry.file_name().into_string().ok());
    }
    Ok(None)
}

fn interface_index(interface_name: &[u8]) -> io::Result<u32> {
    for entry in fs::read_dir("/sys/class/net")? {
        let entry = entry?;
        if entry.file_name().as_bytes() != interface_name {
            continue;
        }
        let text = fs::read_to_string(entry.path().join("ifindex"))?;
        let index = text
            .trim()
            .parse::<u32>()
            .map_err(|_| invalid_data("invalid sysfs interface index"))?;
        if index == 0 {
            return Err(invalid_data("zero sysfs interface index"));
        }
        return Ok(index);
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "network interface not found",
    ))
}

/// Set one link MTU directly through rtnetlink and require the kernel ACK.
///
/// The stock SDK command is host-local, so this stays in `gctd`: no iproute2
/// process or shell is involved and kernel errno values are preserved.
pub(crate) fn set_link_mtu(interface_name: &[u8], mtu: u16) -> io::Result<()> {
    let interface_index = interface_index(interface_name)?;
    let request = encode_set_mtu_request(interface_index, u32::from(mtu))?;
    let socket = net::socket(AddressFamily::NETLINK, SocketType::RAW, None).map_err(errno_to_io)?;
    net::bind(&socket, &SocketAddrNetlink::new(0, 0)).map_err(errno_to_io)?;
    net::connect(&socket, &SocketAddrNetlink::new(0, 0)).map_err(errno_to_io)?;

    let written = rustix::io::write(&socket, &request).map_err(errno_to_io)?;
    if written != request.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short rtnetlink MTU request write",
        ));
    }

    let mut ack = [0_u8; NETLINK_BUFFER_LEN];
    let len = rustix::io::read(&socket, &mut ack).map_err(errno_to_io)?;
    decode_netlink_ack(&ack[..len], SET_MTU_SEQUENCE)
}

fn encode_set_mtu_request(interface_index: u32, mtu: u32) -> io::Result<[u8; SET_MTU_REQUEST_LEN]> {
    let signed_index = i32::try_from(interface_index)
        .map_err(|_| invalid_data("interface index exceeds rtnetlink i32 range"))?;
    let mut bytes = [0_u8; SET_MTU_REQUEST_LEN];

    bytes[0..4].copy_from_slice(
        &u32::try_from(SET_MTU_REQUEST_LEN)
            .map_err(|_| invalid_data("rtnetlink request length exceeds u32"))?
            .to_ne_bytes(),
    );
    bytes[4..6].copy_from_slice(&RTM_NEWLINK.to_ne_bytes());
    bytes[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    bytes[8..12].copy_from_slice(&SET_MTU_SEQUENCE.to_ne_bytes());
    // nlmsg_pid stays zero: the kernel identifies the socket by its bound port ID.

    // ifinfomsg: family/pad/type are zero; only ifi_index is required for this update.
    bytes[20..24].copy_from_slice(&signed_index.to_ne_bytes());

    let attr = NLMSG_HEADER_LEN + IFINFO_MESSAGE_LEN;
    bytes[attr..attr + 2].copy_from_slice(&8_u16.to_ne_bytes());
    bytes[attr + 2..attr + 4].copy_from_slice(&IFLA_MTU.to_ne_bytes());
    bytes[attr + 4..attr + 8].copy_from_slice(&mtu.to_ne_bytes());
    Ok(bytes)
}

fn decode_netlink_ack(bytes: &[u8], expected_sequence: u32) -> io::Result<()> {
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let remaining = &bytes[offset..];
        if remaining.len() < NLMSG_HEADER_LEN {
            return Err(invalid_data("truncated rtnetlink ACK header"));
        }
        let message_len = usize::try_from(native_u32(&remaining[0..4]))
            .map_err(|_| invalid_data("rtnetlink ACK length does not fit usize"))?;
        if message_len < NLMSG_HEADER_LEN || message_len > remaining.len() {
            return Err(invalid_data("invalid rtnetlink ACK length"));
        }

        let message_type = native_u16(&remaining[4..6]);
        let sequence = native_u32(&remaining[8..12]);
        if message_type == NLMSG_ERROR && sequence == expected_sequence {
            if message_len < NLMSG_HEADER_LEN + 4 {
                return Err(invalid_data("truncated rtnetlink NLMSG_ERROR payload"));
            }
            let status = i32::from_ne_bytes(
                remaining[NLMSG_HEADER_LEN..NLMSG_HEADER_LEN + 4]
                    .try_into()
                    .map_err(|_| invalid_data("invalid rtnetlink ACK status"))?,
            );
            if status == 0 {
                return Ok(());
            }
            let errno = status
                .checked_neg()
                .filter(|errno| *errno > 0)
                .ok_or_else(|| invalid_data("invalid positive rtnetlink error status"))?;
            return Err(io::Error::from_raw_os_error(errno));
        }

        let aligned_len =
            align4(message_len).ok_or_else(|| invalid_data("rtnetlink ACK alignment overflow"))?;
        if aligned_len > remaining.len() {
            if message_len == remaining.len() {
                break;
            }
            return Err(invalid_data("truncated rtnetlink ACK padding"));
        }
        offset += aligned_len;
    }
    Err(invalid_data("matching rtnetlink ACK not received"))
}

fn decode_ipv6_prefix_events(bytes: &[u8]) -> io::Result<Vec<Ipv6PrefixEvent>> {
    let mut events = Vec::new();
    let mut offset = 0_usize;

    while offset < bytes.len() {
        let remaining = &bytes[offset..];
        if remaining.len() < NLMSG_HEADER_LEN {
            return Err(invalid_data("truncated rtnetlink message header"));
        }

        let message_len = usize::try_from(native_u32(&remaining[0..4]))
            .map_err(|_| invalid_data("rtnetlink message length does not fit usize"))?;
        if message_len < NLMSG_HEADER_LEN || message_len > remaining.len() {
            return Err(invalid_data("invalid rtnetlink message length"));
        }

        if native_u16(&remaining[4..6]) == RTM_NEWPREFIX
            && let Some(event) = decode_new_prefix(&remaining[NLMSG_HEADER_LEN..message_len])?
        {
            events.push(event);
        }

        let aligned_len = align4(message_len)
            .ok_or_else(|| invalid_data("rtnetlink message alignment overflow"))?;
        if aligned_len > remaining.len() {
            if message_len == remaining.len() {
                break;
            }
            return Err(invalid_data("truncated rtnetlink message padding"));
        }
        offset += aligned_len;
    }

    Ok(events)
}

fn decode_new_prefix(payload: &[u8]) -> io::Result<Option<Ipv6PrefixEvent>> {
    if payload.len() < PREFIX_MESSAGE_LEN {
        return Err(invalid_data("truncated RTM_NEWPREFIX prefixmsg"));
    }
    if payload[0] != AF_INET6 || payload[8] != ND_OPT_PREFIX_INFORMATION {
        return Ok(None);
    }

    let signed_index = i32::from_ne_bytes(
        payload[4..8]
            .try_into()
            .map_err(|_| invalid_data("invalid prefix interface index"))?,
    );
    let interface_index = u32::try_from(signed_index)
        .ok()
        .filter(|index| *index != 0)
        .ok_or_else(|| invalid_data("invalid prefix interface index"))?;

    let mut prefix = None;
    let mut attrs = &payload[PREFIX_MESSAGE_LEN..];
    while !attrs.is_empty() {
        if attrs.len() < RTATTR_HEADER_LEN {
            return Err(invalid_data("truncated prefix rtattr header"));
        }
        let attr_len = usize::from(native_u16(&attrs[0..2]));
        if attr_len < RTATTR_HEADER_LEN || attr_len > attrs.len() {
            return Err(invalid_data("invalid prefix rtattr length"));
        }
        if native_u16(&attrs[2..4]) == PREFIX_ADDRESS {
            let value = &attrs[RTATTR_HEADER_LEN..attr_len];
            let address: [u8; 16] = value
                .try_into()
                .map_err(|_| invalid_data("PREFIX_ADDRESS is not 16 bytes"))?;
            prefix = Some(address);
        }

        let aligned_len =
            align4(attr_len).ok_or_else(|| invalid_data("prefix rtattr alignment overflow"))?;
        if aligned_len > attrs.len() {
            if attr_len == attrs.len() {
                attrs = &[];
                continue;
            }
            return Err(invalid_data("truncated prefix rtattr padding"));
        }
        attrs = &attrs[aligned_len..];
    }

    Ok(prefix.map(|prefix| Ipv6PrefixEvent {
        interface_index,
        prefix_length: payload[9],
        prefix,
    }))
}

fn native_u16(bytes: &[u8]) -> u16 {
    u16::from_ne_bytes([bytes[0], bytes[1]])
}

fn native_u32(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

const fn align4(value: usize) -> Option<usize> {
    match value.checked_add(3) {
        Some(value) => Some(value & !3),
        None => None,
    }
}

fn errno_to_io(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::{
        AF_INET6, IFINFO_MESSAGE_LEN, IFLA_MTU, ND_OPT_PREFIX_INFORMATION, NLM_F_ACK,
        NLM_F_REQUEST, NLMSG_ERROR, NLMSG_HEADER_LEN, PREFIX_ADDRESS, RTATTR_HEADER_LEN,
        RTM_NEWLINK, RTM_NEWPREFIX, SET_MTU_REQUEST_LEN, SET_MTU_SEQUENCE,
        decode_ipv6_prefix_events, decode_netlink_ack, encode_set_mtu_request, native_u16,
        native_u32,
    };

    fn message(family: u8, prefix_type: u8, address_len: usize) -> Vec<u8> {
        let attr_len = RTATTR_HEADER_LEN + address_len;
        let message_len = 16 + 12 + attr_len;
        let mut bytes = vec![0_u8; message_len];
        bytes[0..4].copy_from_slice(
            &u32::try_from(message_len)
                .unwrap_or_else(|_| std::process::abort())
                .to_ne_bytes(),
        );
        bytes[4..6].copy_from_slice(&RTM_NEWPREFIX.to_ne_bytes());
        bytes[16] = family;
        bytes[20..24].copy_from_slice(&7_i32.to_ne_bytes());
        bytes[24] = prefix_type;
        bytes[25] = 64;
        bytes[28..30].copy_from_slice(
            &u16::try_from(attr_len)
                .unwrap_or_else(|_| std::process::abort())
                .to_ne_bytes(),
        );
        bytes[30..32].copy_from_slice(&PREFIX_ADDRESS.to_ne_bytes());
        for (index, byte) in bytes[32..].iter_mut().enumerate() {
            *byte = u8::try_from(index + 1).unwrap_or_else(|_| std::process::abort());
        }
        bytes
    }

    fn ack(status: i32, sequence: u32) -> Vec<u8> {
        let message_len = NLMSG_HEADER_LEN + 4;
        let mut bytes = vec![0_u8; message_len];
        bytes[0..4].copy_from_slice(
            &u32::try_from(message_len)
                .unwrap_or_else(|_| std::process::abort())
                .to_ne_bytes(),
        );
        bytes[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        bytes[8..12].copy_from_slice(&sequence.to_ne_bytes());
        bytes[NLMSG_HEADER_LEN..NLMSG_HEADER_LEN + 4].copy_from_slice(&status.to_ne_bytes());
        bytes
    }

    #[test]
    fn mtu_update_encodes_exact_newlink_request() {
        let bytes = encode_set_mtu_request(7, 1_428).unwrap_or_else(|_| std::process::abort());
        assert_eq!(bytes.len(), SET_MTU_REQUEST_LEN);
        assert_eq!(
            usize::try_from(native_u32(&bytes[0..4])).unwrap_or_else(|_| std::process::abort()),
            SET_MTU_REQUEST_LEN
        );
        assert_eq!(native_u16(&bytes[4..6]), RTM_NEWLINK);
        assert_eq!(native_u16(&bytes[6..8]), NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(native_u32(&bytes[8..12]), SET_MTU_SEQUENCE);
        assert_eq!(
            i32::from_ne_bytes(
                bytes[20..24]
                    .try_into()
                    .unwrap_or_else(|_| std::process::abort())
            ),
            7
        );

        let attr = NLMSG_HEADER_LEN + IFINFO_MESSAGE_LEN;
        assert_eq!(native_u16(&bytes[attr..attr + 2]), 8);
        assert_eq!(native_u16(&bytes[attr + 2..attr + 4]), IFLA_MTU);
        assert_eq!(native_u32(&bytes[attr + 4..attr + 8]), 1_428);
    }

    #[test]
    fn mtu_ack_decoder_accepts_success_and_preserves_kernel_errno() {
        assert!(decode_netlink_ack(&ack(0, SET_MTU_SEQUENCE), SET_MTU_SEQUENCE).is_ok());

        let error = decode_netlink_ack(&ack(-1, SET_MTU_SEQUENCE), SET_MTU_SEQUENCE)
            .err()
            .unwrap_or_else(|| std::process::abort());
        assert_eq!(error.raw_os_error(), Some(1));

        let error = decode_netlink_ack(&ack(0, SET_MTU_SEQUENCE + 1), SET_MTU_SEQUENCE)
            .err()
            .unwrap_or_else(|| std::process::abort());
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn decodes_exact_kernel_ipv6_prefix_notification() {
        let bytes = message(AF_INET6, ND_OPT_PREFIX_INFORMATION, 16);
        let events = decode_ipv6_prefix_events(&bytes).unwrap_or_else(|_| std::process::abort());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].interface_index, 7);
        assert_eq!(events[0].prefix_length, 64);
        assert_eq!(
            events[0].prefix,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
    }

    #[test]
    fn ignores_other_families_and_prefix_option_types() {
        let mut bytes = message(2, ND_OPT_PREFIX_INFORMATION, 16);
        let second = message(AF_INET6, 4, 16);
        bytes.extend_from_slice(&second);
        assert_eq!(
            decode_ipv6_prefix_events(&bytes).unwrap_or_else(|_| std::process::abort()),
            Vec::new()
        );
    }

    #[test]
    fn rejects_malformed_prefix_address_attribute() {
        let bytes = message(AF_INET6, ND_OPT_PREFIX_INFORMATION, 8);
        let error = decode_ipv6_prefix_events(&bytes)
            .err()
            .unwrap_or_else(|| std::process::abort());
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
