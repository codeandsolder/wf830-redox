use gct_lapi::{
    AttachResponse, AttachTailDecodeError, AttachTailField, PdnConnectResponse,
    PdnConnectTailDecodeError, PdnConnectTailField, PdnInfoContainers, PdnInfoField,
    PdnInfoFieldLengthError,
};

pub(crate) const CONNECTION_INFO_LEN: usize = 0x0a0e;
const NIC_RECORD_LEN: usize = 0x0202;
const NIC_SLOT_COUNT: usize = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApnStateError {
    InvalidConfiguredType(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SpecialTidRecord {
    pub(super) message_id: u16,
    pub(super) default_eps_id: u16,
    tid_type: u8,
    pub(super) requested_apn_type: u8,
    pub(super) ip_allocation: u8,
}

impl SpecialTidRecord {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, usize> {
        let bytes: [u8; 7] = bytes.try_into().map_err(|_| bytes.len())?;
        Ok(Self {
            message_id: u16::from_be_bytes([bytes[0], bytes[1]]),
            default_eps_id: u16::from_be_bytes([bytes[2], bytes[3]]),
            tid_type: bytes[4],
            requested_apn_type: bytes[5],
            ip_allocation: bytes[6],
        })
    }

    pub(crate) const fn requested_apn_type(self) -> u8 {
        self.requested_apn_type
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TidStateEntry {
    pub(super) tid: u8,
    pub(super) record: SpecialTidRecord,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ApnState {
    configured_type: u8,
    pub(super) tids: Vec<TidStateEntry>,
}

impl ApnState {
    pub(crate) const fn new() -> Self {
        Self {
            configured_type: 0,
            tids: Vec::new(),
        }
    }

    pub(crate) const fn configured_type(&self) -> u8 {
        self.configured_type
    }

    pub(crate) fn set_configured_type(&mut self, value: u32) -> Result<(), ApnStateError> {
        let narrowed =
            u8::try_from(value).map_err(|_| ApnStateError::InvalidConfiguredType(value))?;
        if narrowed <= 7 || narrowed == 0xff {
            self.configured_type = narrowed;
            Ok(())
        } else {
            Err(ApnStateError::InvalidConfiguredType(value))
        }
    }

    pub(crate) fn apn_type_by_default_eps_id(&self, default_eps_id: u16) -> u8 {
        self.tids
            .iter()
            .find(|entry| entry.record.default_eps_id == default_eps_id)
            .map_or(0xff, |entry| entry.record.requested_apn_type)
    }

    pub(crate) fn resolved_apn_type_for_tid(&self, tid: u8) -> u8 {
        self.tids
            .iter()
            .find(|entry| entry.tid == tid)
            .map_or(self.configured_type, |entry| {
                entry.record.requested_apn_type
            })
    }

    pub(crate) fn contains_tid(&self, tid: u8) -> bool {
        self.tids.iter().any(|entry| entry.tid == tid)
    }

    pub(crate) fn add_special_tid(&mut self, tid: u8, mut record: SpecialTidRecord) {
        if record.tid_type == 1
            && let Some(index) = self.tids.iter().position(|entry| entry.tid == 0)
        {
            let normal = self.tids.remove(index).record;
            record.default_eps_id = normal.default_eps_id;
            record.requested_apn_type = normal.requested_apn_type;
            record.ip_allocation = normal.ip_allocation;
        }
        debug_assert!(!self.contains_tid(tid));
        self.tids.push(TidStateEntry { tid, record });
    }

    pub(crate) fn add_normal_tid(
        &mut self,
        tid: u8,
        message_id: u16,
        requested_apn_type: u8,
        default_eps_id: u16,
        ip_allocation: u8,
    ) {
        debug_assert!(!self.contains_tid(tid));
        self.tids.push(TidStateEntry {
            tid,
            record: SpecialTidRecord {
                message_id,
                default_eps_id,
                tid_type: 0,
                requested_apn_type,
                ip_allocation,
            },
        });
    }

    pub(crate) fn update_default_eps_id(&mut self, tid: u8, default_eps_id: u16) {
        if let Some(entry) = self.tids.iter_mut().find(|entry| entry.tid == tid) {
            entry.record.default_eps_id = default_eps_id;
        }
    }

    pub(crate) fn delete_by_tid(&mut self, tid: u8) {
        if let Some(index) = self.tids.iter().position(|entry| entry.tid == tid) {
            self.tids.remove(index);
        }
    }

    pub(crate) fn clear_tids(&mut self) {
        self.tids.clear();
    }

    pub(crate) fn delete_by_apn_type(&mut self, apn_type: u8) {
        if let Some(index) = self
            .tids
            .iter()
            .position(|entry| entry.record.requested_apn_type == apn_type)
        {
            self.tids.remove(index);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionStateError {
    PdnContainerTlv,
    PdnInnerTlv,
    PdnField(PdnInfoFieldLengthError),
    AttachTail(AttachTailDecodeError),
    PdnTail(PdnConnectTailDecodeError),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct NetworkConfig {
    pdn_type: u8,
    ipv4: [u8; 4],
    ipv4_dns_primary: [u8; 4],
    ipv4_dns_secondary: [u8; 4],
    ipv6_dns_primary: [u8; 16],
    ipv6_dns_secondary: [u8; 16],
    ipv6_interface_id: [u8; 8],
    mtu: u16,
}

impl NetworkConfig {
    fn apply_field(&mut self, field: PdnInfoField<'_>) -> bool {
        match field {
            PdnInfoField::PdnType(value) => self.pdn_type = value,
            PdnInfoField::Ipv4Address(value) => self.ipv4 = value,
            PdnInfoField::Ipv4DnsPrimary(value) => self.ipv4_dns_primary = value,
            PdnInfoField::Ipv4DnsSecondary(value) => self.ipv4_dns_secondary = value,
            PdnInfoField::Ipv6DnsPrimary(value) => self.ipv6_dns_primary = value,
            PdnInfoField::Ipv6DnsSecondary(value) => self.ipv6_dns_secondary = value,
            PdnInfoField::Ipv6InterfaceId(value) => self.ipv6_interface_id = value,
            PdnInfoField::AccessPointName(_)
            | PdnInfoField::PdnTypeCause(_)
            | PdnInfoField::PcscfIpv6 { .. }
            | PdnInfoField::PcscfIpv4 { .. }
            | PdnInfoField::Qos { .. } => {}
            PdnInfoField::Unknown(_) => return false,
        }
        true
    }

    fn apply_containers(
        &mut self,
        mut containers: PdnInfoContainers<'_>,
    ) -> Result<(), ConnectionStateError> {
        let mut stop_after_unknown = false;
        while let Some(container) = containers
            .next_container()
            .map_err(|_| ConnectionStateError::PdnContainerTlv)?
        {
            if stop_after_unknown {
                break;
            }
            let mut fields = container.fields();
            while let Some(tlv) = fields
                .next_tlv()
                .map_err(|_| ConnectionStateError::PdnInnerTlv)?
            {
                let field = PdnInfoField::parse(tlv).map_err(ConnectionStateError::PdnField)?;
                if !self.apply_field(field) {
                    stop_after_unknown = true;
                    break;
                }
            }
        }
        Ok(())
    }
}

struct ConnectionUpdate<'a> {
    event_bit: u32,
    apn_type: u8,
    data_path: u8,
    ip_alloc: u8,
    apn: &'a [u8],
    network: NetworkConfig,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct NicState {
    records: [[u8; NIC_RECORD_LEN]; NIC_SLOT_COUNT],
}

impl NicState {
    pub(crate) const fn new() -> Self {
        let mut records = [[0_u8; NIC_RECORD_LEN]; NIC_SLOT_COUNT];
        let mut index = 0;
        while index < NIC_SLOT_COUNT {
            records[index][0x107] = 0xff;
            index += 1;
        }
        Self { records }
    }

    fn default_eps_id(record: &[u8; NIC_RECORD_LEN]) -> u16 {
        u16::from_be_bytes([record[0x111], record[0x112]])
    }

    fn index_by_default_eps_id(&self, default_eps_id: u16) -> Option<usize> {
        self.records
            .iter()
            .position(|record| Self::default_eps_id(record) == default_eps_id)
    }

    fn index_by_name(&self, interface_name: &str) -> Option<usize> {
        self.records.iter().position(|record| {
            let end = record[..0x100]
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(0x100);
            record[..end] == *interface_name.as_bytes()
        })
    }

    fn init_index(&mut self, default_eps_id: u16) -> Option<usize> {
        if let Some(index) = self.index_by_default_eps_id(default_eps_id) {
            return Some(index);
        }
        let index = self
            .records
            .iter()
            .position(|record| Self::default_eps_id(record) == 0)?;
        self.records[index][0x111..0x113].copy_from_slice(&default_eps_id.to_be_bytes());
        Some(index)
    }

    fn clear_index(&mut self, index: usize) {
        self.records[index].fill(0);
        self.records[index][0x107] = 0xff;
    }

    pub(crate) fn clear_by_default_eps_id(&mut self, default_eps_id: u16) {
        if let Some(index) = self.index_by_default_eps_id(default_eps_id) {
            self.clear_index(index);
        }
    }

    pub(crate) fn snapshot(&self) -> [u8; CONNECTION_INFO_LEN] {
        let mut output = [0_u8; CONNECTION_INFO_LEN];
        let mut count = 0_usize;
        for record in &self.records {
            if Self::default_eps_id(record) == 0 {
                continue;
            }
            let offset = 4 + count * NIC_RECORD_LEN;
            output[offset..offset + NIC_RECORD_LEN].copy_from_slice(record);
            count += 1;
        }
        output[..4].copy_from_slice(&u32::try_from(count).unwrap_or(0).to_be_bytes());
        output
    }

    fn write_u32(record: &mut [u8; NIC_RECORD_LEN], offset: usize, value: u32) {
        record[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn apply_common(record: &mut [u8; NIC_RECORD_LEN], update: &ConnectionUpdate<'_>) {
        let status = u32::from_be_bytes(record[0x100..0x104].try_into().unwrap_or([0; 4]));
        Self::write_u32(record, 0x100, status | update.event_bit);
        Self::write_u32(record, 0x104, u32::from(update.apn_type));
        record[0x10d] = update.data_path;
        record[0x10e] = update.network.pdn_type;
        record[0x10f] = update.ip_alloc;
        record[0x110] = 9;
        record[0x168..0x16a].copy_from_slice(&update.network.mtu.to_be_bytes());
        let apn_len = update.apn.len().min(0x41);
        record[0x113..0x113 + apn_len].copy_from_slice(&update.apn[..apn_len]);

        if update.data_path != 0 {
            record[0x1bc] = 1;
            if record[0] == 0 && update.apn_type != 0xff {
                let name = format!("lte0pdn{}", update.apn_type);
                let bytes = name.as_bytes();
                record[..bytes.len()].copy_from_slice(bytes);
            }
        }

        record[0x160..0x164].copy_from_slice(&update.network.ipv4_dns_primary);
        record[0x164..0x168].copy_from_slice(&update.network.ipv4_dns_secondary);
        record[0x172..0x17a].copy_from_slice(&update.network.ipv6_interface_id);
        record[0x18a..0x19a].copy_from_slice(&update.network.ipv6_dns_primary);
        record[0x19a..0x1aa].copy_from_slice(&update.network.ipv6_dns_secondary);
        Self::apply_ipv4(record, update.network.ipv4);
    }

    fn apply_ipv4(record: &mut [u8; NIC_RECORD_LEN], ipv4: [u8; 4]) {
        record[0x154..0x158].copy_from_slice(&ipv4);
        let Some((gateway, subnet)) = stock_ipv4_gateway_and_mask(ipv4) else {
            return;
        };
        record[0x158..0x15c].copy_from_slice(&subnet);
        record[0x15c..0x160].copy_from_slice(&gateway);
    }

    pub(crate) fn apply_attach(
        &mut self,
        response: AttachResponse<'_>,
        apn_type: u8,
    ) -> Result<bool, ConnectionStateError> {
        let mut network = NetworkConfig::default();
        network.apply_containers(response.pdn_info_containers())?;
        let mut tail = response.trailing_fields();
        while let Some(field) = tail
            .next_field()
            .map_err(ConnectionStateError::AttachTail)?
        {
            if let AttachTailField::Ipv4LinkMtu(value) = field {
                network.mtu = value;
            }
        }

        let Some(index) = self.init_index(response.default_eps_id) else {
            return Ok(false);
        };
        let update = ConnectionUpdate {
            event_bit: 8,
            apn_type,
            data_path: response.data_path,
            ip_alloc: response.ip_alloc,
            apn: response.apn_ni.payload,
            network,
        };
        Self::apply_common(&mut self.records[index], &update);
        Ok(true)
    }

    pub(crate) fn apply_pdn_connect(
        &mut self,
        response: PdnConnectResponse<'_>,
        apn_type: u8,
    ) -> Result<bool, ConnectionStateError> {
        let mut network = NetworkConfig::default();
        network.apply_containers(response.pdn_info_containers())?;
        let mut tail = response.trailing_fields();
        while let Some(field) = tail.next_field().map_err(ConnectionStateError::PdnTail)? {
            match field {
                PdnConnectTailField::Ipv4LinkMtu(value) => network.mtu = value,
                PdnConnectTailField::PdnInfo(_) => {
                    let Some(mut fields) = field.pdn_info_fields() else {
                        continue;
                    };
                    while let Some(tlv) = fields
                        .next_tlv()
                        .map_err(|_| ConnectionStateError::PdnInnerTlv)?
                    {
                        let parsed =
                            PdnInfoField::parse(tlv).map_err(ConnectionStateError::PdnField)?;
                        if !network.apply_field(parsed) {
                            break;
                        }
                    }
                }
                PdnConnectTailField::OperatorPco(_)
                | PdnConnectTailField::ApnAmbr { .. }
                | PdnConnectTailField::Unknown(_) => {}
            }
        }

        let Some(index) = self.init_index(response.default_eps_id) else {
            return Ok(false);
        };
        let update = ConnectionUpdate {
            event_bit: 64,
            apn_type,
            data_path: response.data_path,
            ip_alloc: response.ip_alloc,
            apn: response.apn_ni.payload,
            network,
        };
        Self::apply_common(&mut self.records[index], &update);
        Ok(true)
    }

    pub(crate) fn apply_ipv6_prefix(&mut self, interface_name: &str, prefix: [u8; 16]) -> bool {
        let Some(index) = self.index_by_name(interface_name) else {
            return false;
        };
        let record = &mut self.records[index];
        record[0x16a..0x172].copy_from_slice(&prefix[..8]);
        record[0x1aa..0x1b2].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0]);

        let address: [u8; 16] = record[0x16a..0x17a].try_into().unwrap_or([0; 16]);
        let dns1: [u8; 16] = record[0x18a..0x19a].try_into().unwrap_or([0; 16]);
        let dns2: [u8; 16] = record[0x19a..0x1aa].try_into().unwrap_or([0; 16]);
        let gateway: [u8; 16] = record[0x1aa..0x1ba].try_into().unwrap_or([0; 16]);
        record[0x1be..0x1ce].copy_from_slice(&address);
        record[0x1ce..0x1de].copy_from_slice(&dns1);
        record[0x1de..0x1ee].copy_from_slice(&dns2);
        record[0x1ee..0x1fe].copy_from_slice(&gateway);
        record[0x1bd] = 1;
        true
    }
}

fn stock_ipv4_gateway_and_mask(ipv4: [u8; 4]) -> Option<([u8; 4], [u8; 4])> {
    let prefix_bytes = if ipv4[0] < 0x80 {
        1
    } else if ipv4[0] & 0xc0 == 0x80 {
        2
    } else if ipv4[0] & 0xe0 == 0xc0 {
        3
    } else {
        return None;
    };

    let mut gateway = [0_u8; 4];
    let mut subnet = [0_u8; 4];
    gateway[..prefix_bytes].copy_from_slice(&ipv4[..prefix_bytes]);
    subnet[..prefix_bytes].fill(0xff);
    gateway[3] = if ipv4[3] == 0xff { 1 } else { !ipv4[3] };
    Some((gateway, subnet))
}
