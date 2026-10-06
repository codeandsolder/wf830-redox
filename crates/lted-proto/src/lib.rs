#![no_std]

//! Minimal, audited representation of the OEM `lted` local IPC protocol.
//!
//! The original daemon uses UNIX datagram sockets with a four-byte big-endian
//! header. This crate models the framing and the small critical command subset
//! needed by a replacement daemon; it intentionally does not preserve every
//! historical OEM command.

pub const HEADER_LEN: usize = 4;

/// Top-level `lted` client event identifiers recovered from the OEM daemon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Event {
    ApiOpen = 0x0100,
    ApiClose = 0x0102,
    HciToClient = 0x0105,
    SdkApi = 0x0106,
    CliCommand = 0x010a,
}

impl TryFrom<u16> for Event {
    type Error = UnknownEvent;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0100 => Ok(Self::ApiOpen),
            0x0102 => Ok(Self::ApiClose),
            0x0105 => Ok(Self::HciToClient),
            0x0106 => Ok(Self::SdkApi),
            0x010a => Ok(Self::CliCommand),
            _ => Err(UnknownEvent(value)),
        }
    }
}

/// An event value not recognized by the replacement protocol surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnknownEvent(pub u16);

/// Critical SDK API subcommands recovered from `clnt_req_sdk_send_api_handler`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SdkCommand {
    Attach = 0x18,
    AttachExt = 0x1a,
    Detach = 0x1c,
    PdnConnect = 0x1f,
    PdnConnectExt = 0x21,
    PdnDisconnect = 0x23,
    PlmnSearch = 0x27,
    PlmnList = 0x2b,
    Online = 0x3b,
    Offline = 0x3d,
    PlmnSearchStop = 0x42,
    PsInit = 0x46,
    AtCommand = 0x82,
    AtCommandExt = 0x84,
    UiccRequest = 0x98,
}

impl TryFrom<u8> for SdkCommand {
    type Error = UnknownSdkCommand;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x18 => Ok(Self::Attach),
            0x1a => Ok(Self::AttachExt),
            0x1c => Ok(Self::Detach),
            0x1f => Ok(Self::PdnConnect),
            0x21 => Ok(Self::PdnConnectExt),
            0x23 => Ok(Self::PdnDisconnect),
            0x27 => Ok(Self::PlmnSearch),
            0x2b => Ok(Self::PlmnList),
            0x3b => Ok(Self::Online),
            0x3d => Ok(Self::Offline),
            0x42 => Ok(Self::PlmnSearchStop),
            0x46 => Ok(Self::PsInit),
            0x82 => Ok(Self::AtCommand),
            0x84 => Ok(Self::AtCommandExt),
            0x98 => Ok(Self::UiccRequest),
            _ => Err(UnknownSdkCommand(value)),
        }
    }
}

/// An SDK subcommand not implemented by the replacement protocol surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnknownSdkCommand(pub u8);

/// Four-byte big-endian local IPC header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub event: u16,
    pub payload_len: u16,
}

impl Header {
    #[must_use]
    pub const fn encode(self) -> [u8; HEADER_LEN] {
        let event = self.event.to_be_bytes();
        let len = self.payload_len.to_be_bytes();
        [event[0], event[1], len[0], len[1]]
    }

    #[must_use]
    pub const fn decode(bytes: [u8; HEADER_LEN]) -> Self {
        Self {
            event: u16::from_be_bytes([bytes[0], bytes[1]]),
            payload_len: u16::from_be_bytes([bytes[2], bytes[3]]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Event, Header, SdkCommand};

    #[test]
    fn sdk_api_header_uses_big_endian_length() {
        let header = Header {
            event: Event::SdkApi as u16,
            payload_len: 0x123,
        };
        assert_eq!(header.encode(), [0x01, 0x06, 0x01, 0x23]);
        assert_eq!(Header::decode(header.encode()), header);
    }

    #[test]
    fn critical_sdk_commands_are_stable() {
        assert_eq!(SdkCommand::try_from(0x18), Ok(SdkCommand::Attach));
        assert_eq!(SdkCommand::try_from(0x82), Ok(SdkCommand::AtCommand));
        assert!(SdkCommand::try_from(0xff).is_err());
    }
}
