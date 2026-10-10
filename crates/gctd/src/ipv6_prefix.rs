use std::{
    fs, io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};

use rustix::net::{self, AddressFamily, SocketType, netlink::SocketAddrNetlink};

const NETLINK_BUFFER_LEN: usize = 4096;
const NLMSG_HEADER_LEN: usize = 16;
const PREFIX_MESSAGE_LEN: usize = 12;
const RTATTR_HEADER_LEN: usize = 4;

const RTM_NEWPREFIX: u16 = 52;
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
        AF_INET6, ND_OPT_PREFIX_INFORMATION, PREFIX_ADDRESS, RTATTR_HEADER_LEN, RTM_NEWPREFIX,
        decode_ipv6_prefix_events,
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
