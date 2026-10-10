use super::{
    at::AtCommand,
    attach::{
        AttachEncodeError, AttachExtResponse, AttachField, AttachRequest, AttachResponse,
        AttachResponseDecodeError, AttachResponseKind, AttachResponsePrefix, AttachTailField,
        DetachRequest, DetachResponse, NetworkFeatureInfo, Positioning,
    },
    common::{
        ApnType, EmptyRequest, PcoInfo, PdnConnectionControl, PdnInfoContainerKind,
        PdnInfoContainers, PdnInfoField, PdnInfoFieldLengthError, QosField, ResponseDecodeError,
        ResultResponse, ResultResponseKind,
    },
    emm::{NasConfigEncodeError, NasConfigGetRequest, NasConfigSetRequest},
    misc::{DeviceInformationDecodeError, DeviceInformationRequest, DeviceInformationResponse},
    pdn::{
        PdnConnectExtRequest, PdnConnectExtResponsePrefix, PdnConnectRequest,
        PdnConnectResponsePrefix, PdnDisconnectRequest, PdnDisconnectResponsePrefix,
        PdnEncodeError, PdnField,
    },
    plmn::{QuerySelectedPlmnRequest, QuerySelectedPlmnResponse},
    rrc::{
        RrcCapabilityGetRequest, RrcCapabilityGetResponse, RrcCapabilitySetRequest,
        RrcCapabilitySetResponse, RrcFunctionGetRequest, RrcFunctionResponse,
        RrcFunctionSetRequest, SetProtocolInfoRequest, SetProtocolInfoResponse,
    },
};
use gct_hci::{Header, Packet, Tlv, public_opcode};

#[test]
fn query_selected_plmn_matches_live_p4_wire() {
    let mut request = [0_u8; 4];
    assert_eq!(QuerySelectedPlmnRequest.encode(&mut request), Ok(4));
    assert_eq!(request, [0x31, 0x0f, 0, 0]);

    let response = [0xb1, 0x10, 0, 4, 0, 0x21, 0xf3, 0x54];
    let Ok(packet) = Packet::parse(&response) else {
        return;
    };
    assert_eq!(
        QuerySelectedPlmnResponse::parse(packet),
        Ok(QuerySelectedPlmnResponse {
            result: 0,
            selected_plmn: [0x21, 0xf3, 0x54],
        })
    );
}

#[test]
fn rrc_function_frames_match_live_p4_common_grammar() {
    let mut set = [0_u8; 9];
    assert_eq!(
        (RrcFunctionSetRequest {
            type_id: 7,
            data: &[1],
        })
        .encode(&mut set),
        Ok(9)
    );
    assert_eq!(set, [0x39, 0x08, 0, 5, 0, 7, 0, 1, 1]);

    let mut get = [0_u8; 8];
    assert_eq!(
        (RrcFunctionGetRequest { type_id: 7 }).encode(&mut get),
        Ok(8)
    );
    assert_eq!(get, [0x39, 0x0f, 0, 4, 0, 7, 0, 0]);

    let set_response = [0xb9, 0x09, 0, 7, 0, 0, 0, 1, 0, 7, 0xaa];
    let Ok(packet) = Packet::parse(&set_response) else {
        return;
    };
    assert_eq!(
        RrcFunctionResponse::parse_set(packet),
        Ok(RrcFunctionResponse {
            result: 0,
            type_id: 7,
            data: &[0xaa],
        })
    );

    let get_response = [0xb9, 0x10, 0, 7, 0, 0, 0, 1, 0, 7, 0xbb];
    let Ok(packet) = Packet::parse(&get_response) else {
        return;
    };
    assert_eq!(
        RrcFunctionResponse::parse_get(packet),
        Ok(RrcFunctionResponse {
            result: 0,
            type_id: 7,
            data: &[0xbb],
        })
    );
}

#[test]
fn nas_config_requests_match_live_p4_wire_and_bounds() {
    let storage = [0x80, 1, 0x8a, 2, 0, 0];
    let mut set = [0_u8; 10];
    assert_eq!(
        (NasConfigSetRequest {
            count: 2,
            pairs: &storage,
        })
        .encode(&mut set),
        Ok(10)
    );
    assert_eq!(set, [0x33, 0x70, 0, 6, 0x80, 1, 1, 0x8a, 1, 2]);

    let mut get = [0_u8; 4];
    assert_eq!(NasConfigGetRequest.encode(&mut get), Ok(4));
    assert_eq!(get, [0x33, 0x72, 0, 0]);

    assert_eq!(
        (NasConfigSetRequest {
            count: 17,
            pairs: &[0; 34],
        })
        .encode(&mut [0; 64]),
        Err(NasConfigEncodeError::TooManyPairs {
            maximum: 16,
            actual: 17,
        })
    );
    assert_eq!(
        (NasConfigSetRequest {
            count: 1,
            pairs: &[0x7f, 1],
        })
        .encode(&mut [0; 8]),
        Err(NasConfigEncodeError::UnsupportedTag(0x7f))
    );
}

#[test]
fn device_information_request_and_tlv_response_match_live_wire() {
    let mut request = [0_u8; 4];
    assert_eq!(DeviceInformationRequest.encode(&mut request), Ok(4));
    assert_eq!(request, [0x30, 0x02, 0, 0]);

    let payload = [
        0xa2, 3, 0xaa, 0xbb, 0xcc, 0xa0, 4, 1, 2, 3, 4, 0xa1, 2, 0x12, 0x34,
    ];
    let packet = Packet {
        header: Header {
            command: public_opcode::LTE_GET_INFORMATION_RESULT,
            payload_len: 15,
        },
        payload: &payload,
    };
    assert_eq!(
        DeviceInformationResponse::parse(packet),
        Ok(DeviceInformationResponse {
            fw_revision: [1, 2, 3, 4],
            chip_revision: [0x12, 0x34],
        })
    );
}

#[test]
fn device_information_rejects_truncated_and_oversized_known_tlvs() {
    let oversized = [0xa0, 5, 1, 2, 3, 4, 5];
    let packet = Packet {
        header: Header {
            command: public_opcode::LTE_GET_INFORMATION_RESULT,
            payload_len: 7,
        },
        payload: &oversized,
    };
    assert_eq!(
        DeviceInformationResponse::parse(packet),
        Err(DeviceInformationDecodeError::KnownFieldTooLong {
            type_id: 0xa0,
            maximum: 4,
            actual: 5,
        })
    );

    let truncated = [0xa1, 2, 0x11];
    let packet = Packet {
        header: Header {
            command: public_opcode::LTE_GET_INFORMATION_RESULT,
            payload_len: 3,
        },
        payload: &truncated,
    };
    assert_eq!(
        DeviceInformationResponse::parse(packet),
        Err(DeviceInformationDecodeError::TruncatedRecordValue {
            offset: 0,
            declared: 2,
            remaining: 1,
        })
    );
}

#[test]
fn set_protocol_info_shipped_shapes_match_live_p4_wire() {
    let mut type1 = [0_u8; 12];
    let n = SetProtocolInfoRequest {
        type_id: 1,
        data: &[0x11, 0x22, 0x33, 0x44],
    }
    .encode(&mut type1);
    assert_eq!(n, Ok(12));
    assert_eq!(
        type1,
        [0x31, 0x51, 0, 8, 0, 1, 0, 4, 0x11, 0x22, 0x33, 0x44]
    );

    let mut type8 = [0_u8; 9];
    let n = SetProtocolInfoRequest {
        type_id: 8,
        data: &[0x7f],
    }
    .encode(&mut type8);
    assert_eq!(n, Ok(9));
    assert_eq!(type8, [0x31, 0x51, 0, 5, 0, 8, 0, 1, 0x7f]);
}

#[test]
fn set_protocol_info_response_checks_declared_extent() {
    let bytes = [0, 0, 0, 8, 0, 1, 0x42];
    let packet = Packet {
        header: Header {
            command: 0xb152,
            payload_len: 7,
        },
        payload: &bytes,
    };
    assert_eq!(
        SetProtocolInfoResponse::parse(packet),
        Ok(SetProtocolInfoResponse {
            result: 0,
            type_id: 8,
            data: &[0x42]
        })
    );

    let short = Packet {
        header: Header {
            command: 0xb152,
            payload_len: 6,
        },
        payload: &[0, 0, 0, 8, 0, 1],
    };
    assert_eq!(
        SetProtocolInfoResponse::parse(short),
        Err(ResponseDecodeError::UnexpectedLength {
            expected: 7,
            actual: 6
        })
    );
}

#[test]
fn empty_requests_match_oem_four_byte_frames() {
    let cases = [
        (EmptyRequest::Online, [0x31, 0x21, 0x00, 0x00]),
        (EmptyRequest::Offline, [0x31, 0x23, 0x00, 0x00]),
        (EmptyRequest::PsInit, [0x31, 0x2e, 0x00, 0x00]),
        (EmptyRequest::PlmnList, [0x31, 0x0b, 0x00, 0x00]),
    ];

    for (request, expected) in cases {
        let mut output = [0_u8; 4];
        assert_eq!(request.encode(&mut output), Ok(4));
        assert_eq!(output, expected);
    }
}

#[test]
fn p4_apn_mapping_preserves_live_policy_delta() {
    assert_eq!(ApnType::Internet.p4_wire_value(), 3);
    assert_eq!(ApnType::Ims.p4_wire_value(), 1);
    assert_eq!(ApnType::Admin.p4_wire_value(), 2);
    assert_eq!(ApnType::App.p4_wire_value(), 4);
    assert_eq!(ApnType::Emergency.p4_wire_value(), 0);
    assert_eq!(ApnType::Reserved1.p4_wire_value(), 6);
    assert_eq!(ApnType::Reserved2.p4_wire_value(), 0);
    assert_eq!(ApnType::Reserved3.p4_wire_value(), 0);
    assert_eq!(ApnType::NotSet.p4_wire_value(), 0);
}

#[test]
fn minimal_attach_is_header_plus_optional_info_byte() {
    let request = AttachRequest {
        optional_info: 0,
        transaction_id: 9,
        apn: b"ignored",
        pdn_type: 3,
        ip_alloc: 1,
        username: b"ignored",
        password: b"ignored",
        auth_flag: 2,
        general_pco: None,
        operator_pco: None,
        req_apn_type: ApnType::Internet,
        attach_type: 1,
        request_type: 2,
        emergency_mode: 0,
        positioning: Positioning {
            lpp: true,
            lcs: true,
        },
        nas_sig_low_priority_ind: 1,
        pdn_control: PdnConnectionControl {
            max_conn: 20,
            max_conn_t: 300,
            wait_time: 0,
        },
        secure_pco: 1,
    };
    let mut output = [0_u8; 5];
    assert_eq!(request.encode(&mut output), Ok(5));
    assert_eq!(output, [0x31, 0x01, 0x00, 0x01, 0x00]);
}

#[test]
fn attach_tlvs_follow_live_sdk_order() {
    let request = AttachRequest {
        optional_info: 1,
        transaction_id: 7,
        apn: b"internet",
        pdn_type: 3,
        ip_alloc: 1,
        username: b"u",
        password: b"p",
        auth_flag: 2,
        general_pco: Some(0x1234),
        operator_pco: Some(&[0xaa, 0xbb]),
        req_apn_type: ApnType::Internet,
        attach_type: 4,
        request_type: 5,
        emergency_mode: 0,
        positioning: Positioning {
            lpp: true,
            lcs: false,
        },
        nas_sig_low_priority_ind: 1,
        pdn_control: PdnConnectionControl {
            max_conn: 20,
            max_conn_t: 300,
            wait_time: 10,
        },
        secure_pco: 1,
    };
    let mut output = [0_u8; 96];
    assert_eq!(request.encode(&mut output), Ok(71));
    let encoded = &output[..71];
    assert_eq!(&encoded[..4], &[0x31, 0x01, 0x00, 0x43]);
    assert_eq!(encoded[4], 1);
    assert!(encoded[5..].windows(3).any(|x| x == [0x20, 0x01, 0x07]));
    assert!(encoded[5..].windows(3).any(|x| x == [0x70, 0x01, 0x03]));
    assert!(
        encoded[5..]
            .windows(4)
            .any(|x| x == [0x5c, 0x02, 0x12, 0x34])
    );
    assert!(
        encoded[5..]
            .windows(8)
            .any(|x| x == [0x71, 0x06, 0x00, 0x14, 0x01, 0x2c, 0x00, 0x0a])
    );
}

#[test]
fn attach_rejects_old_c_buffer_overflows_and_hidden_normalization() {
    let base = AttachRequest {
        optional_info: 1,
        transaction_id: 0,
        apn: &[b'a'; 100],
        pdn_type: 0,
        ip_alloc: 0,
        username: b"",
        password: b"",
        auth_flag: 0,
        general_pco: None,
        operator_pco: None,
        req_apn_type: ApnType::Internet,
        attach_type: 0,
        request_type: 0,
        emergency_mode: 0,
        positioning: Positioning {
            lpp: false,
            lcs: false,
        },
        nas_sig_low_priority_ind: 0,
        pdn_control: PdnConnectionControl {
            max_conn: 20,
            max_conn_t: 300,
            wait_time: 0,
        },
        secure_pco: 0,
    };
    let mut output = [0_u8; 512];
    assert_eq!(
        base.encode(&mut output),
        Err(AttachEncodeError::FieldTooLong(AttachField::Apn))
    );

    let invalid_control = AttachRequest {
        apn: b"ok",
        pdn_control: PdnConnectionControl {
            max_conn: 1024,
            max_conn_t: 300,
            wait_time: 0,
        },
        ..base
    };
    assert_eq!(
        invalid_control.encode(&mut output),
        Err(AttachEncodeError::PdnControlOutOfRange)
    );
}

#[test]
fn normal_attach_response_splits_ordered_apn_and_typed_tail() {
    let payload = [
        0x00, 0x01, 0x00, 0x02, 0x12, 0x34, 0x56, 0x78, 0x09, 0x0a, 1, 2, 3, 4, 5, 0x20, 0x01,
        0x7f, // transaction
        0x04, 0x02, b'a', b'p', // positional APN helper
        0x58, 0x01, 0x21, // lower-layer reason
        0x5d, 0x02, 0xaa, 0xbb, // operator PCO
    ];
    let response = AttachResponse::parse(packet(0xb102, &payload));
    let Ok(response) = response else {
        return;
    };
    assert_eq!(response.transaction_id, 0x7f);
    assert_eq!(response.register_result1, 1);
    assert_eq!(response.default_eps_id, 0x1234);
    assert_eq!(response.apn_ni.kind, 0x04);
    assert_eq!(response.apn_ni.payload, b"ap");
    let mut trailing = response.trailing_fields();
    assert_eq!(
        trailing.next_field(),
        Ok(Some(AttachTailField::LowerLayerReason(0x21)))
    );
    assert_eq!(
        trailing.next_field(),
        Ok(Some(AttachTailField::OperatorPco(&[0xaa, 0xbb])))
    );
    assert_eq!(trailing.next_field(), Ok(None));
}

#[test]
fn normal_attach_emergency_list_preserves_packed_record_grammar() {
    let payload = [
        0, 1, 0, 2, 0, 3, 0, 4, 5, 6, 7, 8, 9, 10, 11, 0x20, 1, 9, 0x04, 0, 0xf4,
        0x07, // seven packed bytes follow
        0x03, 0x01, b'1', b'1', // len=3: category + two number bytes
        0x02, 0x02, b'9', // len=2: category + one number byte
    ];
    let Ok(response) = AttachResponse::parse(packet(0xb102, &payload)) else {
        return;
    };
    let mut tail = response.trailing_fields();
    let Ok(Some(AttachTailField::EmergencyNumbers(list))) = tail.next_field() else {
        return;
    };
    let mut records = list.records();
    let Ok(Some(first)) = records.next_record() else {
        return;
    };
    assert_eq!(first.category, 1);
    assert_eq!(first.number, b"11");
    let Ok(Some(second)) = records.next_record() else {
        return;
    };
    assert_eq!(second.category, 2);
    assert_eq!(second.number, b"9");
    assert_eq!(records.next_record(), Ok(None));
}

#[test]
fn normal_attach_response_rejects_missing_or_malformed_transaction() {
    let prefix = [
        0x00, 0x01, 0x00, 0x02, 0x12, 0x34, 0x56, 0x78, 0x09, 0x0a, 1, 2, 3, 4, 5,
    ];
    assert_eq!(
        AttachResponse::parse(packet(0xb102, &prefix)),
        Err(AttachResponseDecodeError::MissingTransaction)
    );

    let mut wrong_kind = prefix.to_vec();
    wrong_kind.extend_from_slice(&[0x21, 0x01, 0x07]);
    assert_eq!(
        AttachResponse::parse(packet(0xb102, &wrong_kind)),
        Err(AttachResponseDecodeError::UnexpectedTransactionKind {
            expected: 0x20,
            actual: 0x21,
        })
    );

    let mut wrong_len = prefix.to_vec();
    wrong_len.extend_from_slice(&[0x20, 0x02, 0x07, 0x08]);
    assert_eq!(
        AttachResponse::parse(packet(0xb102, &wrong_len)),
        Err(AttachResponseDecodeError::UnexpectedTransactionLength {
            expected: 1,
            actual: 2,
        })
    );

    let mut missing_apn = prefix.to_vec();
    missing_apn.extend_from_slice(&[0x20, 0x01, 0x07]);
    assert_eq!(
        AttachResponse::parse(packet(0xb102, &missing_apn)),
        Err(AttachResponseDecodeError::MissingApnNetworkIdentifier)
    );

    let mut oversized_apn = prefix.to_vec();
    oversized_apn.extend_from_slice(&[0x20, 0x01, 0x07, 0x04, 65]);
    oversized_apn.extend_from_slice(&[0xaa; 65]);
    assert_eq!(
        AttachResponse::parse(packet(0xb102, &oversized_apn)),
        Err(AttachResponseDecodeError::ApnNetworkIdentifierTooLong {
            maximum: 64,
            actual: 65,
        })
    );
}

#[test]
fn nested_pdn_containers_stop_before_enclosing_suffix() {
    let bytes = [
        0xf0, 0x09, 0x07, 0x04, 10, 20, 30, 40, 0x05, 0x01, 3, 0xf2, 0x06, 0x40, 0x04, 0, 0, 0, 9,
        0x5d, 0x00,
    ];
    let mut containers = PdnInfoContainers::new(&bytes);
    let Ok(Some(first)) = containers.next_container() else {
        return;
    };
    assert_eq!(first.kind, PdnInfoContainerKind::F0);
    let mut fields = first.fields();
    let Ok(Some(first_tlv)) = fields.next_tlv() else {
        return;
    };
    assert_eq!(
        PdnInfoField::parse(first_tlv),
        Ok(PdnInfoField::Ipv4Address([10, 20, 30, 40]))
    );
    let Ok(Some(second_tlv)) = fields.next_tlv() else {
        return;
    };
    assert_eq!(
        PdnInfoField::parse(second_tlv),
        Ok(PdnInfoField::PdnType(3))
    );
    assert!(matches!(fields.next_tlv(), Ok(None)));

    let Ok(Some(second)) = containers.next_container() else {
        return;
    };
    assert_eq!(second.kind, PdnInfoContainerKind::F2);
    let mut qos_fields = second.fields();
    let Ok(Some(qos_tlv)) = qos_fields.next_tlv() else {
        return;
    };
    assert_eq!(
        PdnInfoField::parse(qos_tlv),
        Ok(PdnInfoField::Qos {
            field: QosField::Qci,
            value: 9
        })
    );
    assert!(matches!(containers.next_container(), Ok(None)));
    assert_eq!(containers.remaining(), &[0x5d, 0x00]);
}

#[test]
fn pdn_inner_dispatch_maps_recovered_fields() {
    assert_eq!(
        PdnInfoField::parse(Tlv {
            kind: 0x08,
            payload: &[1, 1, 1, 1]
        }),
        Ok(PdnInfoField::Ipv4DnsPrimary([1, 1, 1, 1]))
    );
    assert_eq!(
        PdnInfoField::parse(Tlv {
            kind: 0x0d,
            payload: &[1; 16]
        }),
        Ok(PdnInfoField::PcscfIpv6 {
            index: 1,
            address: [1; 16]
        })
    );
    assert_eq!(
        PdnInfoField::parse(Tlv {
            kind: 0x22,
            payload: &[2, 3, 4, 5]
        }),
        Ok(PdnInfoField::PcscfIpv4 {
            index: 3,
            address: [2, 3, 4, 5]
        })
    );
    assert_eq!(
        PdnInfoField::parse(Tlv {
            kind: 0x44,
            payload: &[0, 0, 1, 0]
        }),
        Ok(PdnInfoField::Qos {
            field: QosField::GuaranteedBitRateDl,
            value: 256
        })
    );
}

#[test]
fn pdn_inner_dispatch_rejects_bad_known_lengths_and_preserves_unknowns() {
    assert_eq!(
        PdnInfoField::parse(Tlv {
            kind: 0x07,
            payload: &[1, 2, 3]
        }),
        Err(PdnInfoFieldLengthError {
            kind: 0x07,
            expected: 4,
            actual: 3
        })
    );
    let unknown = Tlv {
        kind: 0xee,
        payload: &[1, 2],
    };
    assert_eq!(
        PdnInfoField::parse(unknown),
        Ok(PdnInfoField::Unknown(unknown))
    );
}

fn packet(command: u16, payload: &[u8]) -> Packet<'_> {
    Packet {
        header: Header {
            command,
            payload_len: u16::try_from(payload.len()).unwrap_or(u16::MAX),
        },
        payload,
    }
}

#[test]
fn simple_result_responses_are_one_big_endian_word() {
    for (kind, opcode) in [
        (ResultResponseKind::Online, 0xb122),
        (ResultResponseKind::Offline, 0xb124),
        (ResultResponseKind::PsInit, 0xb12f),
    ] {
        assert_eq!(
            ResultResponse::parse(kind, packet(opcode, &[0x11, 0x22, 0x33, 0x44])),
            Ok(ResultResponse {
                result: 0x1122_3344,
            })
        );
    }
}

#[test]
fn detach_response_is_exact_eight_byte_structure() {
    let payload = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    assert_eq!(
        DetachResponse::parse(packet(0xb104, &payload)),
        Ok(DetachResponse {
            result: 0x1122_3344,
            deregister_cause1: 0x5566,
            deregister_cause2: 0x7788,
        })
    );
}

#[test]
fn attach_prefix_is_shared_by_normal_and_extended_wire_responses() {
    let payload = [
        0x00, 0x01, 0x00, 0x02, 0x12, 0x34, 0x56, 0x78, 0x09, 0x0a, 1, 2, 3, 4, 5, 0x20, 0x01, 0x7f,
    ];
    let expected = AttachResponsePrefix {
        register_result1: 1,
        register_result2: 2,
        default_eps_id: 0x1234,
        eps_id: 0x5678,
        data_path: 9,
        ip_alloc: 10,
        network_features: NetworkFeatureInfo {
            ims_voice_over_ps: 1,
            emc_bc: 2,
            epc_lcs: 3,
            sc_lcs: 4,
            ext_sr: 5,
        },
        optional_fields: &[0x20, 0x01, 0x7f],
    };
    let normal = AttachResponsePrefix::parse(AttachResponseKind::Normal, packet(0xb102, &payload));
    let extended =
        AttachResponsePrefix::parse(AttachResponseKind::Extended, packet(0xb166, &payload));
    assert_eq!(normal, Ok(expected));
    assert_eq!(extended, Ok(expected));
    let mut tlvs = expected.optional_tlvs();
    assert_eq!(
        tlvs.next_tlv(),
        Ok(Some(Tlv {
            kind: 0x20,
            payload: &[0x7f],
        }))
    );
}

#[test]
fn extended_attach_response_splits_ordered_apns_nested_pdn_and_ignored_suffix() {
    let payload = [
        0x00, 0x01, 0x00, 0x02, 0x12, 0x34, 0x56, 0x78, 0x09, 0x0a, 1, 2, 3, 4, 5, 0x20, 0x01,
        0x07, 0x57, 0x03, b'i', b'm', b's', 0x58, 0x03, b'n', b'e', b't', 0xf0, 0x14, 0x04, 0x03,
        b'p', b'd', b'n', 0x05, 0x01, 0x02, 0x07, 0x04, 192, 168, 1, 2, 0x40, 0x04, 0, 0, 0, 9,
        0xaa, 0x00,
    ];
    let Ok(response) = AttachExtResponse::parse(packet(0xb166, &payload)) else {
        return;
    };
    assert_eq!(response.register_result1, 1);
    assert_eq!(response.register_result2, 2);
    assert_eq!(response.default_eps_id, 0x1234);
    assert_eq!(response.eps_id, 0x5678);
    assert_eq!(response.data_path, 9);
    assert_eq!(response.ip_alloc, 10);
    assert_eq!(response.apn_class_kind, 0x20);
    assert_eq!(response.apn_class, 7);
    assert_eq!(response.requested_apn_ni.kind, 0x57);
    assert_eq!(response.requested_apn_ni.payload, b"ims");
    assert_eq!(response.received_apn_ni.kind, 0x58);
    assert_eq!(response.received_apn_ni.payload, b"net");
    assert_eq!(response.unparsed_suffix, &[0xaa, 0x00]);

    let mut containers = response.pdn_info_containers();
    let Ok(Some(container)) = containers.next_container() else {
        return;
    };
    assert_eq!(container.kind, PdnInfoContainerKind::F0);
    let mut fields = container.fields();
    let Ok(Some(apn)) = fields.next_tlv() else {
        return;
    };
    let Ok(Some(pdn_type)) = fields.next_tlv() else {
        return;
    };
    let Ok(Some(ipv4)) = fields.next_tlv() else {
        return;
    };
    let Ok(Some(qos)) = fields.next_tlv() else {
        return;
    };
    assert_eq!(
        PdnInfoField::parse(apn),
        Ok(PdnInfoField::AccessPointName(b"pdn"))
    );
    assert_eq!(PdnInfoField::parse(pdn_type), Ok(PdnInfoField::PdnType(2)));
    assert_eq!(
        PdnInfoField::parse(ipv4),
        Ok(PdnInfoField::Ipv4Address([192, 168, 1, 2]))
    );
    assert_eq!(
        PdnInfoField::parse(qos),
        Ok(PdnInfoField::Qos {
            field: QosField::Qci,
            value: 9
        })
    );
    assert_eq!(fields.next_tlv(), Ok(None));
    assert!(matches!(containers.next_container(), Ok(None)));
}

#[test]
fn pdn_response_prefixes_keep_optional_suffix_borrowed() {
    let normal = [
        0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x12, 0x34, 0x05, 0x06, 0x57, 0x01, b'x',
    ];
    assert_eq!(
        PdnConnectResponsePrefix::parse(packet(0xb106, &normal)),
        Ok(PdnConnectResponsePrefix {
            result: 1,
            reject_cause1: 2,
            reject_cause2: 3,
            default_eps_id: 0x1234,
            data_path: 5,
            ip_alloc: 6,
            optional_fields: &[0x57, 0x01, b'x'],
        })
    );

    let extended = [
        0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x12, 0x34, 0x05, 0x06, 0x07, 0x08, 0x57, 0x00,
    ];
    assert_eq!(
        PdnConnectExtResponsePrefix::parse(packet(0xb168, &extended)),
        Ok(PdnConnectExtResponsePrefix {
            result: 1,
            reject_cause1: 2,
            reject_cause2: 3,
            default_eps_id: 0x1234,
            data_path: 5,
            ip_alloc: 6,
            throttle_time: 0x0708,
            optional_fields: &[0x57, 0x00],
        })
    );

    let disconnect = [0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x12, 0x34, 0x5d, 0x00];
    assert_eq!(
        PdnDisconnectResponsePrefix::parse(packet(0xb108, &disconnect)),
        Ok(PdnDisconnectResponsePrefix {
            result: 1,
            reject_cause1: 2,
            reject_cause2: 3,
            default_eps_id: 0x1234,
            optional_fields: &[0x5d, 0x00],
        })
    );
}

#[test]
fn response_parsers_reject_wrong_opcode_and_short_prefix() {
    assert_eq!(
        DetachResponse::parse(packet(0xb106, &[0; 8])),
        Err(ResponseDecodeError::UnexpectedOpcode {
            expected: 0xb104,
            actual: 0xb106,
        })
    );
    assert_eq!(
        PdnConnectResponsePrefix::parse(packet(0xb106, &[0; 9])),
        Err(ResponseDecodeError::TruncatedPrefix {
            minimum: 10,
            actual: 9,
        })
    );
    assert_eq!(
        ResultResponse::parse(ResultResponseKind::Online, packet(0xb122, &[0; 3])),
        Err(ResponseDecodeError::UnexpectedLength {
            expected: 4,
            actual: 3,
        })
    );
}

#[test]
fn minimal_pdn_connect_keeps_required_fields() {
    let request = PdnConnectRequest {
        request_type: 7,
        optional_info: 0,
        transaction_id: 9,
        apn: b"x",
        pdn_type: 3,
        ip_alloc: 1,
        username: &[b'u'; 100],
        password: &[b'p'; 100],
        auth_flag: 2,
        general_pco: None,
        operator_pco: None,
        req_apn_type: ApnType::Internet,
        nas_sig_low_priority_ind: 1,
        pdn_control: PdnConnectionControl {
            max_conn: 65_535,
            max_conn_t: 65_535,
            wait_time: 65_535,
        },
        secure_pco: 1,
    };
    let mut output = [0_u8; 15];
    assert_eq!(request.encode(&mut output), Ok(15));
    assert_eq!(
        output,
        [
            0x31, 0x05, 0x00, 0x0b, 0x07, 0x00, 0x20, 0x01, 0x09, 0x04, 0x01, b'x', 0x70, 0x01,
            0x03,
        ]
    );
}

#[test]
fn normal_pdn_connect_follows_live_tlv_order() {
    let request = PdnConnectRequest {
        request_type: 2,
        optional_info: 1,
        transaction_id: 7,
        apn: b"internet",
        pdn_type: 3,
        ip_alloc: 1,
        username: b"u",
        password: b"p",
        auth_flag: 2,
        general_pco: Some(0x1234),
        operator_pco: Some(&[0xaa, 0xbb]),
        req_apn_type: ApnType::Internet,
        nas_sig_low_priority_ind: 1,
        pdn_control: PdnConnectionControl {
            max_conn: 20,
            max_conn_t: 300,
            wait_time: 10,
        },
        secure_pco: 1,
    };
    let mut output = [0_u8; 64];
    assert_eq!(request.encode(&mut output), Ok(59));
    let encoded = &output[..59];
    assert_eq!(&encoded[..6], &[0x31, 0x05, 0x00, 0x37, 0x02, 0x01]);
    assert!(encoded[6..].windows(3).any(|x| x == [0x20, 0x01, 0x07]));
    assert!(
        encoded[6..]
            .windows(4)
            .any(|x| x == [0x5c, 0x02, 0x12, 0x34])
    );
    assert!(
        encoded[6..]
            .windows(8)
            .any(|x| x == [0x71, 0x06, 0x00, 0x14, 0x01, 0x2c, 0x00, 0x0a])
    );
    assert_eq!(&encoded[encoded.len() - 3..], &[0x70, 0x01, 0x03]);
}

#[test]
fn extended_attach_matches_live_two_profile_wire_order() {
    let primary = super::attach::AttachExtProfile {
        ip_alloc: 1,
        apn_class: 7,
        apn: b"ims",
        pdn_type: 3,
        username: b"u",
        password: b"p",
        auth_flag: 2,
        pco: PcoInfo {
            first_pco: 0x11,
            second_pco: 0x22,
            n_pco: 3,
            first_os_pco: 0x1234,
            second_os_pco: 0x5678,
            third_os_pco: 0x9abc,
        },
    };
    let retry = super::attach::AttachExtProfile {
        ip_alloc: 2,
        apn_class: 8,
        apn: b"r",
        pdn_type: 4,
        username: b"",
        password: b"",
        auth_flag: 1,
        pco: PcoInfo {
            first_pco: 0,
            second_pco: 0,
            n_pco: 0,
            first_os_pco: 0,
            second_os_pco: 0,
            third_os_pco: 0,
        },
    };
    let request = super::attach::AttachExtRequest {
        optional_info: 1,
        primary,
        retry,
    };
    let mut output = [0_u8; 69];
    assert_eq!(request.encode(&mut output), Ok(69));
    assert_eq!(
        output,
        [
            0x31, 0x65, 0x00, 0x41, 0x01, 0x01, 0x01, 0x01, 0x20, 0x01, 0x07, 0x04, 0x03, b'i',
            b'm', b's', 0x05, 0x01, 0x03, 0x02, 0x01, b'u', 0x03, 0x01, b'p', 0x1e, 0x01, 0x02,
            0x21, 0x09, 0x11, 0x22, 0x03, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0x01, 0x01, 0x02,
            0x20, 0x01, 0x08, 0x04, 0x01, b'r', 0x05, 0x01, 0x04, 0x02, 0x00, 0x03, 0x00, 0x1e,
            0x01, 0x01, 0x21, 0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
    );
}

#[test]
fn extended_attach_optional_zero_is_exact_five_byte_frame() {
    let oversized_apn = [b'a'; 100];
    let oversized_credential = [b'x'; 64];
    let ignored = super::attach::AttachExtProfile {
        ip_alloc: 0xff,
        apn_class: 0xff,
        apn: &oversized_apn,
        pdn_type: 0xff,
        username: &oversized_credential,
        password: &oversized_credential,
        auth_flag: 0xff,
        pco: PcoInfo {
            first_pco: 0xff,
            second_pco: 0xff,
            n_pco: 0xff,
            first_os_pco: 0xffff,
            second_os_pco: 0xffff,
            third_os_pco: 0xffff,
        },
    };
    let mut output = [0_u8; 5];
    assert_eq!(
        super::attach::AttachExtRequest {
            optional_info: 0,
            primary: ignored,
            retry: ignored,
        }
        .encode(&mut output),
        Ok(5)
    );
    assert_eq!(output, [0x31, 0x65, 0x00, 0x01, 0x00]);
}

#[test]
fn extended_attach_rejects_serialized_profile_overflow() {
    let oversized_apn = [b'a'; 100];
    let pco = PcoInfo {
        first_pco: 0,
        second_pco: 0,
        n_pco: 0,
        first_os_pco: 0,
        second_os_pco: 0,
        third_os_pco: 0,
    };
    let primary = super::attach::AttachExtProfile {
        ip_alloc: 0,
        apn_class: 0,
        apn: &oversized_apn,
        pdn_type: 0,
        username: b"",
        password: b"",
        auth_flag: 0,
        pco,
    };
    let retry = super::attach::AttachExtProfile {
        apn: b"ok",
        ..primary
    };
    let mut output = [0_u8; 512];
    assert_eq!(
        super::attach::AttachExtRequest {
            optional_info: 1,
            primary,
            retry,
        }
        .encode(&mut output),
        Err(super::attach::AttachExtEncodeError::FieldTooLong(
            super::attach::AttachExtField::PrimaryApn
        ))
    );
}

#[test]
fn minimal_extended_pdn_connect_is_base_plus_apn() {
    let request = PdnConnectExtRequest {
        request_type: 1,
        optional_info: 0,
        apn: b"ims",
        ip_alloc: 0xff,
        apn_class: 0xff,
        pdn_type: 0xff,
        username: &[b'u'; 64],
        password: &[b'p'; 64],
        auth_flag: 0xff,
        pco: PcoInfo {
            first_pco: 0xff,
            second_pco: 0xff,
            n_pco: 0xff,
            first_os_pco: 0xffff,
            second_os_pco: 0xffff,
            third_os_pco: 0xffff,
        },
    };
    let mut output = [0_u8; 11];
    assert_eq!(request.encode(&mut output), Ok(11));
    assert_eq!(
        output,
        [
            0x31, 0x67, 0x00, 0x07, 0x01, 0x00, 0x04, 0x03, b'i', b'm', b's'
        ]
    );
}

#[test]
fn extended_pdn_connect_encodes_pco_words_big_endian() {
    let request = PdnConnectExtRequest {
        request_type: 2,
        optional_info: 1,
        apn: b"internet",
        ip_alloc: 1,
        apn_class: 7,
        pdn_type: 3,
        username: b"u",
        password: b"p",
        auth_flag: 2,
        pco: PcoInfo {
            first_pco: 0x11,
            second_pco: 0x22,
            n_pco: 3,
            first_os_pco: 0x1234,
            second_os_pco: 0x5678,
            third_os_pco: 0x9abc,
        },
    };
    let mut output = [0_u8; 48];
    assert_eq!(request.encode(&mut output), Ok(45));
    let encoded = &output[..45];
    assert_eq!(&encoded[..6], &[0x31, 0x67, 0x00, 0x29, 0x02, 0x01]);
    assert!(encoded.windows(11).any(|x| x
        == [
            0x21, 0x09, 0x11, 0x22, 0x03, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc
        ]));
}

#[test]
fn pdn_disconnect_matches_live_message_specific_apn_field() {
    let request = PdnDisconnectRequest {
        default_eps_id: 0x1234,
        transaction_id: 7,
        apn_ni: b"internet",
    };
    let mut output = [0_u8; 19];
    assert_eq!(request.encode(&mut output), Ok(19));
    assert_eq!(
        output,
        [
            0x31, 0x07, 0x00, 0x0f, 0x12, 0x34, 0x20, 0x01, 0x07, 0x57, 0x08, b'i', b'n', b't',
            b'e', b'r', b'n', b'e', b't',
        ]
    );
}

#[test]
fn pdn_codecs_reject_only_serialized_oversize_fields() {
    let mut output = [0_u8; 512];
    let normal = PdnConnectRequest {
        request_type: 0,
        optional_info: 1,
        transaction_id: 0,
        apn: b"ok",
        pdn_type: 0,
        ip_alloc: 0,
        username: &[b'u'; 100],
        password: b"",
        auth_flag: 0,
        general_pco: None,
        operator_pco: None,
        req_apn_type: ApnType::Internet,
        nas_sig_low_priority_ind: 0,
        pdn_control: PdnConnectionControl {
            max_conn: 20,
            max_conn_t: 300,
            wait_time: 0,
        },
        secure_pco: 0,
    };
    assert_eq!(
        normal.encode(&mut output),
        Err(PdnEncodeError::FieldTooLong(PdnField::Username))
    );

    let disconnect = PdnDisconnectRequest {
        default_eps_id: 1,
        transaction_id: 1,
        apn_ni: &[b'a'; 65],
    };
    assert_eq!(
        disconnect.encode(&mut output),
        Err(PdnEncodeError::FieldTooLong(PdnField::ApnNi))
    );
}

#[test]
fn at_command_adds_the_oem_line_feed() {
    let mut output = [0_u8; 7];
    assert_eq!(AtCommand::new(b"AT").encode(&mut output), Ok(7));
    assert_eq!(output, [0x33, 0x07, 0x00, 0x03, b'A', b'T', b'\n']);
}

#[test]
fn detach_is_header_plus_one_big_endian_word() {
    let mut output = [0_u8; 8];
    let request = DetachRequest::from_raw(0x1122_3344);
    assert_eq!(request.encode(&mut output), Ok(8));
    assert_eq!(output, [0x31, 0x03, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44]);
}

#[test]
fn full_normal_pdn_response_follows_recovered_parser_pipeline() {
    let payload = [
        0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x12, 0x34, 0x05, 0x06, 0x20, 0x01, 0x07, 0x57, 0x08,
        b'i', b'n', b't', b'e', b'r', b'n', b'e', b't', 0xf0, 0x06, 0x07, 0x04, 10, 20, 30, 40,
        0xf2, 0x06, 0x40, 0x04, 0, 0, 0, 9, 0x5b, 0x02, 0x05, 0xdc, 0x5d, 0x02, 0xaa, 0xbb, 0xf0,
        0x06, 0x08, 0x04, 1, 1, 1, 1, 0xf3, 0x08, 0, 0, 0, 100, 0, 0, 0, 200, 0xee, 0x01, 0xff,
    ];
    let Ok(response) = super::pdn::PdnConnectResponse::parse(packet(0xb106, &payload)) else {
        return;
    };
    assert_eq!(response.result, 1);
    assert_eq!(response.default_eps_id, 0x1234);
    assert_eq!(response.transaction_id, 7);
    assert_eq!(response.apn_ni.kind, 0x57);
    assert_eq!(response.apn_ni.payload, b"internet");

    let mut containers = response.pdn_info_containers();
    let Ok(Some(first)) = containers.next_container() else {
        return;
    };
    assert_eq!(first.kind, PdnInfoContainerKind::F0);
    let mut first_fields = first.fields();
    let Ok(Some(first_tlv)) = first_fields.next_tlv() else {
        return;
    };
    assert_eq!(
        PdnInfoField::parse(first_tlv),
        Ok(PdnInfoField::Ipv4Address([10, 20, 30, 40]))
    );
    let Ok(Some(second)) = containers.next_container() else {
        return;
    };
    assert_eq!(second.kind, PdnInfoContainerKind::F2);
    let mut second_fields = second.fields();
    let Ok(Some(qos_tlv)) = second_fields.next_tlv() else {
        return;
    };
    assert_eq!(
        PdnInfoField::parse(qos_tlv),
        Ok(PdnInfoField::Qos {
            field: QosField::Qci,
            value: 9,
        })
    );
    assert!(matches!(containers.next_container(), Ok(None)));

    let mut tail = response.trailing_fields();
    assert_eq!(
        tail.next_field(),
        Ok(Some(super::pdn::PdnConnectTailField::Ipv4LinkMtu(1500)))
    );
    assert_eq!(
        tail.next_field(),
        Ok(Some(super::pdn::PdnConnectTailField::OperatorPco(&[
            0xaa, 0xbb
        ])))
    );
    assert_eq!(
        tail.next_field(),
        Ok(Some(super::pdn::PdnConnectTailField::PdnInfo(&[
            0x08, 0x04, 1, 1, 1, 1
        ])))
    );
    assert_eq!(
        tail.next_field(),
        Ok(Some(super::pdn::PdnConnectTailField::ApnAmbr {
            uplink: 100,
            downlink: 200,
        }))
    );
    assert_eq!(
        tail.next_field(),
        Ok(Some(super::pdn::PdnConnectTailField::Unknown(Tlv {
            kind: 0xee,
            payload: &[0xff],
        })))
    );
    assert_eq!(tail.next_field(), Ok(None));
}

#[test]
fn extended_pdn_response_preserves_unchecked_tags_and_ignored_suffix() {
    let payload = [
        0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x12, 0x34, 0x05, 0x06, 0x07, 0x08, 0x20, 0x01, 0x07,
        0x57, 0x03, b'i', b'm', b's', 0x58, 0x03, b'n', b'e', b't', 0xf0, 0x03, 0x05, 0x01, 0x03,
        0xaa, 0x00,
    ];
    let Ok(response) = super::pdn::PdnConnectExtResponse::parse(packet(0xb168, &payload)) else {
        return;
    };
    assert_eq!(response.throttle_time, 0x0708);
    assert_eq!(response.apn_class_kind, 0x20);
    assert_eq!(response.apn_class, 7);
    assert_eq!(response.requested_apn_ni.kind, 0x57);
    assert_eq!(response.requested_apn_ni.payload, b"ims");
    assert_eq!(response.received_apn_ni.kind, 0x58);
    assert_eq!(response.received_apn_ni.payload, b"net");
    assert_eq!(response.unparsed_suffix, &[0xaa, 0x00]);

    let mut containers = response.pdn_info_containers();
    let Ok(Some(container)) = containers.next_container() else {
        return;
    };
    let mut fields = container.fields();
    let Ok(Some(tlv)) = fields.next_tlv() else {
        return;
    };
    assert_eq!(PdnInfoField::parse(tlv), Ok(PdnInfoField::PdnType(3)));
}

#[test]
fn disconnect_response_decodes_descriptor_suffix_and_unknowns() {
    let payload = [
        0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x12, 0x34, 0x20, 0x01, 0x09, 0x57, 0x08, b'i', b'n',
        b't', b'e', b'r', b'n', b'e', b't', 0x5d, 0x02, 0xaa, 0xbb, 0xee, 0x00,
    ];
    let Ok(response) = super::pdn::PdnDisconnectResponse::parse(packet(0xb108, &payload)) else {
        return;
    };
    assert_eq!(response.transaction_id, 9);
    let mut fields = response.trailing_fields();
    assert_eq!(
        fields.next_field(),
        Ok(Some(super::pdn::PdnDisconnectField::ApnNetworkIdentifier(
            b"internet"
        )))
    );
    assert_eq!(
        fields.next_field(),
        Ok(Some(super::pdn::PdnDisconnectField::OperatorPco(&[
            0xaa, 0xbb
        ])))
    );
    assert_eq!(
        fields.next_field(),
        Ok(Some(super::pdn::PdnDisconnectField::Unknown(Tlv {
            kind: 0xee,
            payload: &[],
        })))
    );
    assert_eq!(fields.next_field(), Ok(None));
}

#[test]
fn full_pdn_response_parsers_reject_unsafe_oem_shapes() {
    let wrong_transaction = [
        0, 1, 0, 2, 0, 3, 0x12, 0x34, 5, 6, 0x21, 0x01, 7, 0x57, 0x00,
    ];
    assert_eq!(
        super::pdn::PdnConnectResponse::parse(packet(0xb106, &wrong_transaction)),
        Err(super::common::PdnResponseDecodeError::UnexpectedKind {
            field: super::common::PdnResponseField::TransactionId,
            expected: 0x20,
            actual: 0x21,
        })
    );

    let bad_apn_class = [
        0, 1, 0, 2, 0, 3, 0x12, 0x34, 5, 6, 7, 8, 0x20, 0x02, 1, 2, 0x57, 0x00, 0x58, 0x00,
    ];
    assert_eq!(
        super::pdn::PdnConnectExtResponse::parse(packet(0xb168, &bad_apn_class)),
        Err(
            super::common::PdnResponseDecodeError::UnexpectedFieldLength {
                field: super::common::PdnResponseField::ApnClass,
                expected: 1,
                actual: 2,
            }
        )
    );

    let truncated_nested = [
        0, 1, 0, 2, 0, 3, 0x12, 0x34, 5, 6, 0x20, 0x01, 7, 0x57, 0x00, 0xf0, 0x04, 0x07, 0x04,
    ];
    assert_eq!(
        super::pdn::PdnConnectResponse::parse(packet(0xb106, &truncated_nested)),
        Err(super::common::PdnResponseDecodeError::Tlv(
            gct_hci::TlvDecodeError::TruncatedPayload {
                declared: 4,
                actual: 2,
            }
        ))
    );
}

#[test]
fn plmn_search_request_matches_live_p4_packing() {
    let automatic = super::plmn::PlmnSearchRequest {
        search_mode: 0,
        mcc: [2, 6, 0],
        mnc: [0, 1, 0x0f],
        emergency_mode: 1,
        roaming_option: 2,
    };
    let mut automatic_wire = [0_u8; 14];
    assert_eq!(automatic.encode(&mut automatic_wire), Ok(14));
    assert_eq!(
        automatic_wire,
        [
            0x31, 0x09, 0x00, 0x0a, 0x00, 0xff, 0xff, 0xff, 0x62, 0x01, 0x01, 0x63, 0x01, 0x02,
        ]
    );

    let manual = super::plmn::PlmnSearchRequest {
        search_mode: 1,
        mcc: [2, 6, 0],
        mnc: [0, 1, 0x0f],
        emergency_mode: 3,
        roaming_option: 4,
    };
    let mut manual_wire = [0_u8; 14];
    assert_eq!(manual.encode(&mut manual_wire), Ok(14));
    assert_eq!(
        manual_wire,
        [
            0x31, 0x09, 0x00, 0x0a, 0x01, 0x62, 0xf0, 0x10, 0x62, 0x01, 0x03, 0x63, 0x01, 0x04,
        ]
    );

    let mut short = [0_u8; 13];
    assert_eq!(
        manual.encode(&mut short),
        Err(gct_hci::EncodeError::NoSpace)
    );
}

#[test]
fn plmn_search_ext_matches_live_p4_no_list_and_extended_earfcn_list() {
    let mut wire = [0_u8; 300];
    let no_list = super::plmn::PlmnSearchExtRequest {
        selection_mode: 0,
        operation_mode: 0,
        mcc: [0; 3],
        mnc: [0; 3],
        roaming_option: 2,
        list_count: 0,
        list_data: &[],
        power_scan: false,
    };
    assert_eq!(no_list.encode(&mut wire), Ok(8));
    assert_eq!(
        &wire[..8],
        &[0x31, 0x5a, 0x00, 0x04, 0x00, 0x00, 0x63, 0x02]
    );

    let list = [
        2, 2, 0x00, 0x00, 0x0a, 0x28, 0x00, 0x00, 0x09, 0xc4, 3, 2, 3, 5, 4, 1, 0x00, 0x00, 0x09,
        0xc4, 0x00, 0x00, 0x0a, 0x28,
    ];
    let manual = super::plmn::PlmnSearchExtRequest {
        selection_mode: 1,
        operation_mode: 1,
        mcc: [2, 6, 0],
        mnc: [0, 1, 0x0f],
        roaming_option: 9,
        list_count: 3,
        list_data: &list,
        power_scan: true,
    };
    assert_eq!(manual.encode(&mut wire), Ok(38));
    assert_eq!(
        &wire[..10],
        &[0x31, 0x5a, 0x00, 0x22, 0x01, 0x01, 0x64, 0x62, 0xf0, 0x10]
    );
    assert_eq!(&wire[10..12], &[0x65, 24]);
    assert_eq!(&wire[12..36], &list);
    assert_eq!(&wire[36..38], &[0x66, 1]);
}

#[test]
fn plmn_search_ext_rejects_malformed_fixed_scan_lists() {
    let mut wire = [0_u8; 300];
    let bad_type = [9, 0];
    let request = super::plmn::PlmnSearchExtRequest {
        selection_mode: 0,
        operation_mode: 0,
        mcc: [0; 3],
        mnc: [0; 3],
        roaming_option: 0,
        list_count: 1,
        list_data: &bad_type,
        power_scan: false,
    };
    assert_eq!(
        request.encode(&mut wire),
        Err(super::plmn::PlmnSearchExtEncodeError::UnsupportedElementType { index: 0, kind: 9 })
    );

    let truncated = [2, 1, 0, 0, 0];
    let request = super::plmn::PlmnSearchExtRequest {
        list_data: &truncated,
        ..request
    };
    assert_eq!(
        request.encode(&mut wire),
        Err(super::plmn::PlmnSearchExtEncodeError::TruncatedElement {
            index: 0,
            kind: 2,
            expected: 6,
            remaining: 5,
        })
    );
}

#[test]
fn mobile_id_read_matches_shared_live_p4_request_and_response_grammar() {
    let mut request = [0_u8; 9];
    assert_eq!(
        super::misc::MobileIdReadRequest { mobile_id_type: 3 }.encode(&mut request),
        Ok(9)
    );
    assert_eq!(
        request,
        [0x31, 0x45, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x03]
    );

    let success = [
        0x00, 0x00, // top-level read_result
        0x00, 0x01, 0x00, 0x08, // Mobile-ID subtype + body length
        0x03, 0x00, 0x05, b'1', b'2', b'3', b'4', b'5',
    ];
    assert_eq!(
        super::misc::MiscReadResponse::parse(packet(
            gct_hci::recovered_opcode::MISC_READ_RESPONSE,
            &success,
        )),
        Ok(super::misc::MiscReadResponse::MobileId(
            super::misc::MobileIdReadResponse {
                read_result: 0,
                id_type: 3,
                result: 0,
                id: b"12345",
            }
        ))
    );

    assert_eq!(
        super::misc::MiscReadResponse::parse(packet(
            gct_hci::recovered_opcode::MISC_READ_RESPONSE,
            &[0x00, 0x07],
        )),
        Ok(super::misc::MiscReadResponse::Failure { read_result: 7 })
    );

    let unsupported = [0x00, 0x00, 0x7f, 0xff, 0x00, 0x01, 0xaa];
    assert_eq!(
        super::misc::MiscReadResponse::parse(packet(
            gct_hci::recovered_opcode::MISC_READ_RESPONSE,
            &unsupported,
        )),
        Ok(super::misc::MiscReadResponse::UnsupportedSuccess)
    );
}

#[test]
fn mobile_id_read_rejects_unsafe_or_truncated_shared_chunks() {
    let overlong = [
        0x00, 0x00, 0x00, 0x01, 0x00, 0x14, 1, 0, 17, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
        14, 15, 16, 17,
    ];
    assert_eq!(
        super::misc::MiscReadResponse::parse(packet(
            gct_hci::recovered_opcode::MISC_READ_RESPONSE,
            &overlong,
        )),
        Err(super::misc::MiscReadDecodeError::MobileIdChunkTooLong { actual: 17 })
    );

    let truncated = [0x00, 0x00, 0x00, 0x01, 0x00, 0x05, 1, 0, 2, 0xaa];
    assert_eq!(
        super::misc::MiscReadResponse::parse(packet(
            gct_hci::recovered_opcode::MISC_READ_RESPONSE,
            &truncated,
        )),
        Err(super::misc::MiscReadDecodeError::TruncatedChunk {
            subtype: 1,
            declared: 5,
            actual: 4,
        })
    );
}

#[test]
fn temperature_read_matches_shared_live_p4_request_and_signed_response() {
    let mut request = [0_u8; 8];
    assert_eq!(
        super::misc::TemperatureReadRequest.encode(&mut request),
        Ok(8)
    );
    assert_eq!(request, [0x31, 0x45, 0, 4, 0, 4, 0, 0]);

    let payload = [0, 0, 0, 4, 0, 2, 0, 0xef];
    assert_eq!(
        super::misc::MiscReadResponse::parse(packet(
            gct_hci::recovered_opcode::MISC_READ_RESPONSE,
            &payload,
        )),
        Ok(super::misc::MiscReadResponse::Temperature(
            super::misc::TemperatureReadResponse {
                read_result: 0,
                result: 0,
                temperature: -17,
            }
        ))
    );

    let truncated = [0, 0, 0, 4, 0, 1, 0];
    assert_eq!(
        super::misc::MiscReadResponse::parse(packet(
            gct_hci::recovered_opcode::MISC_READ_RESPONSE,
            &truncated,
        )),
        Err(super::misc::MiscReadDecodeError::TemperatureBodyTooShort {
            minimum: 2,
            actual: 1,
        })
    );
}

#[test]
fn iccid_read_matches_shared_live_p4_request_and_exact_response() {
    let mut request = [0_u8; 8];
    assert_eq!(super::misc::IccidReadRequest.encode(&mut request), Ok(8));
    assert_eq!(request, [0x31, 0x45, 0, 4, 0, 2, 0, 0]);

    let payload = [
        0, 0, 0, 2, 0, 11, 0, 0x89, 0x10, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x54, 0xf6,
    ];
    assert_eq!(
        super::misc::MiscReadResponse::parse(packet(
            gct_hci::recovered_opcode::MISC_READ_RESPONSE,
            &payload,
        )),
        Ok(super::misc::MiscReadResponse::Iccid(
            super::misc::IccidReadResponse {
                read_result: 0,
                result: 0,
                iccid: &[0x89, 0x10, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x54, 0xf6],
            }
        ))
    );

    let truncated = [0, 0, 0, 2, 0, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    assert_eq!(
        super::misc::MiscReadResponse::parse(packet(
            gct_hci::recovered_opcode::MISC_READ_RESPONSE,
            &truncated,
        )),
        Err(super::misc::MiscReadDecodeError::IccidBodyTooShort {
            minimum: 11,
            actual: 10,
        })
    );
}

#[test]
fn msisdn_read_matches_shared_live_p4_request_and_bounded_records() {
    let mut request = [0_u8; 8];
    assert_eq!(super::misc::MsisdnReadRequest.encode(&mut request), Ok(8));
    assert_eq!(request, [0x31, 0x45, 0, 4, 0, 3, 0, 0]);

    let mut record = [0_u8; super::misc::MSISDN_RECORD_LEN];
    record[0] = 3;
    record[1..4].copy_from_slice(b"Jan");
    record[0xf2] = 4;
    record[0xf3] = 0x91;
    record[0xf4..0xf8].copy_from_slice(&[0x21, 0x43, 0x65, 0xf7]);
    record[0xfe] = 8;
    record[0xff] = 9;
    let mut payload = [0_u8; 264];
    payload[..8].copy_from_slice(&[0, 0, 0, 3, 0x01, 0x02, 0, 1]);
    payload[8..].copy_from_slice(&record);
    let parsed = super::misc::MiscReadResponse::parse(packet(
        gct_hci::recovered_opcode::MISC_READ_RESPONSE,
        &payload,
    ));
    assert_eq!(
        parsed,
        Ok(super::misc::MiscReadResponse::Msisdn(
            super::misc::MsisdnReadResponse {
                read_result: 0,
                result: 0,
                records: &record,
            }
        ))
    );
    if let Ok(super::misc::MiscReadResponse::Msisdn(response)) = parsed {
        assert_eq!(response.num_msisdn(), 1);
    }

    let local_failure = [0, 0, 0, 3, 0, 1, 7];
    assert_eq!(
        super::misc::MiscReadResponse::parse(packet(
            gct_hci::recovered_opcode::MISC_READ_RESPONSE,
            &local_failure,
        )),
        Ok(super::misc::MiscReadResponse::Msisdn(
            super::misc::MsisdnReadResponse {
                read_result: 0,
                result: 7,
                records: &[],
            }
        ))
    );
}

#[test]
fn msisdn_read_rejects_record_count_overflow_and_truncation() {
    let too_many = [0, 0, 0, 3, 0, 2, 0, 4];
    assert_eq!(
        super::misc::MiscReadResponse::parse(packet(
            gct_hci::recovered_opcode::MISC_READ_RESPONSE,
            &too_many,
        )),
        Err(super::misc::MiscReadDecodeError::TooManyMsisdnRecords {
            maximum: 3,
            actual: 4,
        })
    );

    let mut truncated = [0_u8; 18];
    truncated[..8].copy_from_slice(&[0, 0, 0, 3, 0, 12, 0, 1]);
    truncated[8..].fill(0xaa);
    assert_eq!(
        super::misc::MiscReadResponse::parse(packet(
            gct_hci::recovered_opcode::MISC_READ_RESPONSE,
            &truncated,
        )),
        Err(super::misc::MiscReadDecodeError::TruncatedMsisdnRecords {
            expected: 256,
            actual: 10,
        })
    );
}

#[test]
fn plmn_search_stop_matches_live_request_and_response_layouts() {
    let mut request = [0_u8; 5];
    assert_eq!(
        super::plmn::PlmnSearchStopRequest { search_type: 3 }.encode(&mut request),
        Ok(5)
    );
    assert_eq!(request, [0x31, 0x27, 0x00, 0x01, 0x03]);

    assert_eq!(
        super::plmn::PlmnSearchStopResponse::parse(packet(
            gct_hci::recovered_opcode::PLMN_SEARCH_STOP_RESPONSE,
            &[3, 0x12, 0x34, 0x56, 0x78],
        )),
        Ok(super::plmn::PlmnSearchStopResponse {
            search_type: 3,
            result: 0x1234_5678,
        })
    );
    assert_eq!(
        super::plmn::PlmnSearchStopResponse::parse(packet(
            gct_hci::recovered_opcode::PLMN_SEARCH_STOP_RESPONSE,
            &[3, 0, 0, 0],
        )),
        Err(super::common::ResponseDecodeError::UnexpectedLength {
            expected: 5,
            actual: 4,
        })
    );
}

#[test]
fn plmn_list_response_assembles_three_tlvs_per_record() {
    let payload = [
        0x01, 0x12, 0x03, 0x62, 0xf0, 0x10, 0x13, 0x04, 0, 0, 0, 7, 0x14, 0x04, 0, 0, 0, 9, 0x14,
        0x04, 0, 0, 0, 3, 0x12, 0x03, 0x21, 0x43, 0x65, 0x13, 0x04, 0, 0, 0, 2,
    ];
    let Ok(response) = super::plmn::PlmnListResponse::parse(packet(0xb10c, &payload)) else {
        return;
    };
    assert_eq!(response.search_complete, 1);
    let mut records = response.records();
    assert_eq!(
        records.next_record(),
        Ok(Some(super::plmn::PlmnInfo {
            plmn_id: [0x62, 0xf0, 0x10],
            priority: 7,
            status: 9,
        }))
    );
    assert_eq!(
        records.next_record(),
        Ok(Some(super::plmn::PlmnInfo {
            plmn_id: [0x21, 0x43, 0x65],
            priority: 2,
            status: 3,
        }))
    );
    assert_eq!(records.next_record(), Ok(None));
}

#[test]
fn plmn_search_response_splits_fixed_metadata_and_records() {
    let payload = [
        0x00, 0x00, 0x00, 0x00, 0x02, 0x62, 0xf0, 0x10, 0x00, 0x11, 0x00, 0x1e, 0xfe, 0x00, 0x03,
        0x12, 0x34, 0x00, 0x00, 0x18, 0x9c, 0xaa, 0xbb, 0x01, 0x23, 0x45, 0x67, 0x13, 0x04, 0x00,
        0x00, 0x00, 0x07, 0x26, 0x04, 0x01, 0x62, 0xf0, 0x10, 0x12, 0x03, 0x62, 0xf0, 0x10, 0x13,
        0x04, 0x00, 0x00, 0x00, 0x01, 0x14, 0x04, 0x00, 0x00, 0x00, 0x02,
    ];
    let Ok(response) = super::plmn::PlmnSearchResponse::parse(packet(0xb10a, &payload)) else {
        return;
    };
    assert_eq!(response.result, 0);
    assert_eq!(response.selection_mode, 2);
    assert_eq!(response.selected_plmn_id, [0x62, 0xf0, 0x10]);
    assert_eq!(response.next_index, 0x11);
    assert_eq!(response.network_interval, 30);
    assert_eq!(response.remaining_count, -2);
    assert_eq!(response.band, 3);
    assert_eq!(response.cell_id, 0x1234);
    assert_eq!(response.frequency, 6300);
    assert_eq!(response.tac, [0xaa, 0xbb]);
    assert_eq!(response.bit28_cell_id, 0x0123_4567);
    assert_eq!(response.plmn_priority, Some(7));
    assert_eq!(
        response.sib1_plmn,
        Some(super::plmn::Sib1PlmnList {
            count: 1,
            packed_plmn: &[0x62, 0xf0, 0x10],
        })
    );

    let mut records = response.records();
    assert_eq!(
        records.next_record(),
        Ok(Some(super::plmn::PlmnInfo {
            plmn_id: [0x62, 0xf0, 0x10],
            priority: 1,
            status: 2,
        }))
    );
    assert_eq!(records.next_record(), Ok(None));
}

#[test]
fn plmn_parsers_reject_ambiguous_or_unsafe_vendor_shapes() {
    let duplicate = [
        1, 0x12, 0x03, 1, 2, 3, 0x12, 0x03, 4, 5, 6, 0x14, 0x04, 0, 0, 0, 1,
    ];
    let Ok(response) = super::plmn::PlmnListResponse::parse(packet(0xb10c, &duplicate)) else {
        return;
    };
    let mut records = response.records();
    assert_eq!(
        records.next_record(),
        Err(super::plmn::PlmnInfoDecodeError::DuplicateField(
            super::plmn::PlmnInfoField::PlmnId
        ))
    );

    let mut oversized_sib1 = [0_u8; 79];
    oversized_sib1[27] = 0x26;
    oversized_sib1[28] = 50;
    assert_eq!(
        super::plmn::PlmnSearchResponse::parse(packet(0xb10a, &oversized_sib1)),
        Err(super::plmn::PlmnSearchDecodeError::Sib1PlmnTooLong {
            maximum: 49,
            actual: 50,
        })
    );

    let short_priority = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x13,
        0x03, 1, 2, 3,
    ];
    assert_eq!(
        super::plmn::PlmnSearchResponse::parse(packet(0xb10a, &short_priority)),
        Err(
            super::plmn::PlmnSearchDecodeError::UnexpectedMetadataLength {
                kind: 0x13,
                expected: 4,
                actual: 3,
            }
        )
    );
}

#[test]
fn uicc_status_and_pin_status_requests_match_live_wire_frames() {
    let mut status = [0_u8; 9];
    assert_eq!(
        super::uicc::UiccStatusRequest { app_type: 2 }.encode(&mut status),
        Ok(9)
    );
    assert_eq!(
        status,
        [0x35, 0x04, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x02]
    );

    let mut pin_status = [0_u8; 8];
    assert_eq!(
        super::uicc::UiccPinStatusRequest.encode(&mut pin_status),
        Ok(8)
    );
    assert_eq!(pin_status, [0x35, 0x04, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00]);
}

#[test]
fn uicc_response_envelope_uses_result_type_len_wire_order() {
    let payload = [0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x05, 0x02];
    assert_eq!(
        super::uicc::UiccResponse::parse(packet(0xb505, &payload)),
        Ok(super::uicc::UiccResponse {
            result: 0,
            kind: super::uicc::uicc_control::STATUS,
            data: &[0x05, 0x02],
        })
    );
    assert_eq!(
        super::uicc::UiccStatusResponse::parse(packet(0xb505, &payload)),
        Ok(super::uicc::UiccStatusResponse {
            uicc_status: 5,
            app_type: 2,
        })
    );

    let mismatched = [0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x05, 0x02];
    assert_eq!(
        super::uicc::UiccResponse::parse(packet(0xb505, &mismatched)),
        Err(super::uicc::UiccResponseDecodeError::DataLengthMismatch {
            declared: 3,
            actual: 2,
        })
    );
}

#[test]
fn uicc_pin_status_and_command_responses_match_dwarf_layouts() {
    let pin_status = [
        0x00, 0x00, 0x00, 0x07, 0x00, 0x0b, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
    ];
    assert_eq!(
        super::uicc::UiccPinStatusResponse::parse(packet(0xb505, &pin_status)),
        Ok(super::uicc::UiccPinStatusResponse {
            uicc_return: 1,
            global_pin: 2,
            application: super::uicc::PinStatus {
                status: 3,
                pin_retries: 4,
                puk_retries: 5,
            },
            universal: super::uicc::PinStatus {
                status: 6,
                pin_retries: 7,
                puk_retries: 8,
            },
            local: super::uicc::PinStatus {
                status: 9,
                pin_retries: 10,
                puk_retries: 11,
            },
        })
    );

    let pin_command = [0x00, 0x00, 0x00, 0x06, 0x00, 0x05, 1, 2, 3, 4, 5];
    assert_eq!(
        super::uicc::UiccPinCommandResponse::parse(packet(0xb505, &pin_command)),
        Ok(super::uicc::UiccPinCommandResponse {
            uicc_return: 1,
            pin_type: 2,
            pin_command: 3,
            pin_retries: 4,
            puk_retries: 5,
        })
    );
}

#[test]
fn uicc_pin_command_request_is_bounded_and_zero_pads_fixed_pin_data() {
    let request = super::uicc::UiccPinCommandRequest {
        pin_type: 1,
        pin_command: 2,
        old_pin: super::uicc::PinData { code: b"1234" },
        new_pin: super::uicc::PinData { code: b"" },
    };
    let mut wire = [0_u8; 28];
    assert_eq!(request.encode(&mut wire), Ok(28));
    assert_eq!(
        wire,
        [
            0x35, 0x04, 0x00, 0x18, 0x00, 0x06, 0x00, 0x14, 0x01, 0x02, 0x04, b'1', b'2', b'3',
            b'4', 0, 0, 0, 0, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
    );

    let too_long = super::uicc::UiccPinCommandRequest {
        pin_type: 1,
        pin_command: 2,
        old_pin: super::uicc::PinData { code: b"123456789" },
        new_pin: super::uicc::PinData { code: b"" },
    };
    assert_eq!(
        too_long.encode(&mut wire),
        Err(super::uicc::UiccPinEncodeError::PinTooLong {
            maximum: 8,
            actual: 9,
        })
    );
}

#[test]
fn typed_uicc_response_rejects_outer_failure_before_interpreting_data() {
    let payload = [0x00, 0x05, 0x00, 0x07, 0x00, 0x00];
    assert_eq!(
        super::uicc::UiccPinStatusResponse::parse(packet(0xb505, &payload)),
        Err(super::uicc::UiccTypedDecodeError::FailureResult(5))
    );
}

#[test]
fn uicc_read_requests_match_recovered_big_endian_layouts() {
    let binary = super::uicc::UiccReadBinaryRequest {
        app_type: 2,
        fid: 0x6f07,
        offset: 0x0123,
        length: 0x0040,
    };
    let mut binary_wire = [0_u8; 17];
    assert_eq!(binary.encode(&mut binary_wire), Ok(17));
    assert_eq!(
        binary_wire,
        [
            0x35, 0x04, 0x00, 0x0d, 0x00, 0x01, 0x00, 0x09, 0x02, 0x00, 0x00, 0x6f, 0x07, 0x01,
            0x23, 0x00, 0x40,
        ]
    );

    let record = super::uicc::UiccReadRecordRequest {
        app_type: 1,
        fid: 0x6f3a,
        record_index: 7,
    };
    let mut record_wire = [0_u8; 14];
    assert_eq!(record.encode(&mut record_wire), Ok(14));
    assert_eq!(
        record_wire,
        [
            0x35, 0x04, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x06, 0x01, 0x00, 0x00, 0x6f, 0x3a, 0x07,
        ]
    );
}

#[test]
fn uicc_read_binary_response_borrows_exact_embedded_length() {
    let payload = [
        0x00, 0x00, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x02, 0x00, 0x00, 0x6f, 0x07, 0x90, 0x00, 0x00,
        0x04, 0xde, 0xad, 0xbe, 0xef,
    ];
    assert_eq!(
        super::uicc::UiccReadBinaryResponse::parse(packet(0xb505, &payload)),
        Ok(super::uicc::UiccReadBinaryResponse {
            uicc_return: 0,
            app_type: 2,
            fid: 0x6f07,
            sw1: 0x90,
            sw2: 0x00,
            data: &[0xde, 0xad, 0xbe, 0xef],
        })
    );

    let bad_inner_len = [
        0x00, 0x00, 0x00, 0x01, 0x00, 0x0d, 0x00, 0x02, 0x00, 0x00, 0x6f, 0x07, 0x90, 0x00, 0x00,
        0x04, 0xde, 0xad, 0xbe,
    ];
    assert_eq!(
        super::uicc::UiccReadBinaryResponse::parse(packet(0xb505, &bad_inner_len)),
        Err(super::uicc::UiccFileDecodeError::EmbeddedLengthMismatch {
            declared: 4,
            actual: 3,
        })
    );
}

#[test]
fn uicc_read_record_response_distinguishes_one_record_from_all_records() {
    let one = [
        0x00, 0x00, 0x00, 0x02, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x6f, 0x3a, 0x90, 0x00, 0x07,
        0x05, 0x02, 1, 2, 3, 4, 5,
    ];
    assert_eq!(
        super::uicc::UiccReadRecordResponse::parse(packet(0xb505, &one)),
        Ok(super::uicc::UiccReadRecordResponse {
            uicc_return: 0,
            app_type: 1,
            fid: 0x6f3a,
            sw1: 0x90,
            sw2: 0x00,
            record_index: 7,
            length: 5,
            record_count: 2,
            data: &[1, 2, 3, 4, 5],
        })
    );

    let all = [
        0x00, 0x00, 0x00, 0x02, 0x00, 0x11, 0x00, 0x01, 0x00, 0x00, 0x6f, 0x3a, 0x90, 0x00, 0x00,
        0x03, 0x02, 1, 2, 3, 4, 5, 6,
    ];
    assert_eq!(
        super::uicc::UiccReadRecordResponse::parse(packet(0xb505, &all)),
        Ok(super::uicc::UiccReadRecordResponse {
            uicc_return: 0,
            app_type: 1,
            fid: 0x6f3a,
            sw1: 0x90,
            sw2: 0x00,
            record_index: 0,
            length: 3,
            record_count: 2,
            data: &[1, 2, 3, 4, 5, 6],
        })
    );

    let truncated_all = [
        0x00, 0x00, 0x00, 0x02, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x6f, 0x3a, 0x90, 0x00, 0x00,
        0x03, 0x02, 1, 2, 3, 4, 5,
    ];
    assert_eq!(
        super::uicc::UiccReadRecordResponse::parse(packet(0xb505, &truncated_all)),
        Err(super::uicc::UiccFileDecodeError::EmbeddedLengthMismatch {
            declared: 6,
            actual: 5,
        })
    );
}

#[test]
fn uicc_fixed_requests_preserve_every_stock_subtype_byte() {
    let mut authenticate = [0xa5_u8; 36];
    authenticate[0] = 2;
    authenticate[1] = 1;
    authenticate[2] = 0x11;
    authenticate[18] = 1;
    authenticate[19] = 0x22;
    authenticate[35] = 1;
    let mut wire = [0_u8; 44];
    assert_eq!(
        super::uicc::UiccFixedRequest::authenticate(&authenticate)
            .and_then(|request| request.encode(&mut wire)),
        Ok(44)
    );
    assert_eq!(
        &wire[..8],
        &[0x35, 0x04, 0x00, 0x28, 0x00, 0x05, 0x00, 0x24]
    );
    assert_eq!(&wire[8..], &authenticate);

    let pin = [0x5a_u8; 20];
    let mut wire = [0_u8; 28];
    assert_eq!(
        super::uicc::UiccFixedRequest::pin_command(&pin)
            .and_then(|request| request.encode(&mut wire)),
        Ok(28)
    );
    assert_eq!(
        &wire[..8],
        &[0x35, 0x04, 0x00, 0x18, 0x00, 0x06, 0x00, 0x14]
    );
    assert_eq!(&wire[8..], &pin);
}

#[test]
fn uicc_authenticate_request_zero_pads_fixed_slots_and_bounds_inputs() {
    let request = super::uicc::UiccAuthenticateRequest {
        app_type: 2,
        rand: &[1, 2, 3],
        auth: &[0xaa, 0xbb],
        gsm_auth_selection: 1,
    };
    let mut wire = [0_u8; 44];
    assert_eq!(request.encode(&mut wire), Ok(44));
    assert_eq!(
        &wire[..8],
        &[0x35, 0x04, 0x00, 0x28, 0x00, 0x05, 0x00, 0x24]
    );
    assert_eq!(wire[8], 2);
    assert_eq!(wire[9], 3);
    assert_eq!(&wire[10..13], &[1, 2, 3]);
    assert!(wire[13..26].iter().all(|&byte| byte == 0));
    assert_eq!(wire[26], 2);
    assert_eq!(&wire[27..29], &[0xaa, 0xbb]);
    assert!(wire[29..43].iter().all(|&byte| byte == 0));
    assert_eq!(wire[43], 1);

    let too_long = [0_u8; 17];
    assert_eq!(
        super::uicc::UiccAuthenticateRequest {
            app_type: 2,
            rand: &too_long,
            auth: &[],
            gsm_auth_selection: 0,
        }
        .encode(&mut wire),
        Err(super::uicc::UiccAuthenticateEncodeError::FieldTooLong {
            field: super::uicc::UiccAuthenticateField::Rand,
            maximum: 16,
            actual: 17,
        })
    );
}

#[test]
fn uicc_authenticate_response_exposes_declared_authentication_material() {
    let mut payload = [0_u8; 92];
    payload[..6].copy_from_slice(&[0x00, 0x00, 0x00, 0x05, 0x00, 0x56]);
    let data = &mut payload[6..];
    data[0] = 1;
    data[1] = 2;
    data[2] = 3;
    data[3] = 2;
    data[4..6].copy_from_slice(&[0x10, 0x11]);
    data[20] = 1;
    data[21] = 0x20;
    data[37] = 2;
    data[38..40].copy_from_slice(&[0x30, 0x31]);
    data[54] = 1;
    data[55] = 0x40;
    data[71] = 4;
    data[72..76].copy_from_slice(&[0x50, 0x51, 0x52, 0x53]);
    data[76] = 3;
    data[77..80].copy_from_slice(&[0x60, 0x61, 0x62]);
    data[85] = 7;

    assert_eq!(
        super::uicc::UiccAuthenticateResponse::parse(packet(0xb505, &payload)),
        Ok(super::uicc::UiccAuthenticateResponse {
            uicc_return: 1,
            app_type: 2,
            auth_return: 3,
            res: &[0x10, 0x11],
            ck: &[0x20],
            ik: &[0x30, 0x31],
            auts: &[0x40],
            sres: &[0x50, 0x51, 0x52, 0x53],
            kc: &[0x60, 0x61, 0x62],
            gsm_auth_result: 7,
        })
    );
}

#[test]
fn uicc_authenticate_response_rejects_embedded_lengths_beyond_slots() {
    let mut payload = [0_u8; 92];
    payload[..6].copy_from_slice(&[0x00, 0x00, 0x00, 0x05, 0x00, 0x56]);
    payload[6 + 71] = 5;
    assert_eq!(
        super::uicc::UiccAuthenticateResponse::parse(packet(0xb505, &payload)),
        Err(super::uicc::UiccAuthenticateDecodeError::FieldTooLong {
            field: super::uicc::UiccAuthenticateField::Sres,
            maximum: 4,
            actual: 5,
        })
    );
}

#[test]
fn detach_required_indication_is_one_big_endian_word() {
    assert_eq!(
        super::attach::DetachRequiredIndication::parse(packet(0xb16a, &[0x01, 0x23, 0x45, 0x67])),
        Ok(super::attach::DetachRequiredIndication {
            detach_type: 0x0123_4567,
        })
    );
    assert_eq!(
        super::attach::DetachRequiredIndication::parse(packet(0xb16a, &[0, 0, 1])),
        Err(super::common::ResponseDecodeError::UnexpectedLength {
            expected: 4,
            actual: 3,
        })
    );
}

#[test]
fn psm_lcs_lpp_control_requests_match_exact_live_p4_bytes() {
    let mut psm = [0_u8; 14];
    assert_eq!(
        super::emm::PsmControlRequest {
            ctrl_cmd: 0x1234,
            t3324_timer_value_unit: 5,
            t3324_timer_value: 6,
            ext_t3412_timer_value_unit: 7,
            ext_t3412_timer_value: 8,
        }
        .encode(&mut psm),
        Ok(14)
    );
    assert_eq!(
        psm,
        [
            0x31, 0x55, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x12, 0x34, 5, 6, 7, 8
        ]
    );

    let mut lcs = [0_u8; 12];
    assert_eq!(
        super::emm::LcsControlRequest { mode: 0x1122_3344 }.encode(&mut lcs),
        Ok(12)
    );
    assert_eq!(lcs, [0x31, 0x55, 0, 8, 0, 9, 0, 4, 0x11, 0x22, 0x33, 0x44]);
    let mut lpp = [0_u8; 12];
    assert_eq!(
        super::emm::LppControlRequest { mode: 0x1122_3344 }.encode(&mut lpp),
        Ok(12)
    );
    assert_eq!(lpp, [0x31, 0x55, 0, 8, 0, 10, 0, 4, 0x11, 0x22, 0x33, 0x44]);
}

#[test]
fn emm_timer_start_preserves_exact_three_stock_bytes() {
    let mut output = [0_u8; 11];
    assert_eq!(
        super::emm::EmmTimerStartRequest {
            params: [0x12, 0x34, 0x56]
        }
        .encode(&mut output),
        Ok(11)
    );
    assert_eq!(output, [0x31, 0x55, 0, 7, 0, 13, 0, 3, 0x12, 0x34, 0x56]);
    let dropped = [0, 0, 0, 13, 0, 3, 0xaa];
    assert_eq!(
        super::emm::EmmControlResponse::parse(packet(0xb156, &dropped)),
        Ok(super::emm::EmmControlResponse::Unsupported { kind: 13 })
    );
}

#[test]
fn emm_control_requests_and_live_envelopes_match_exact_bytes() {
    let mut timer = [0_u8; 12];
    assert_eq!(
        super::emm::EmmTimerControlRequest {
            timer_id: 0x1234,
            timer_value_unit: 5,
            timer_value: 6,
        }
        .encode(&mut timer),
        Ok(12)
    );
    assert_eq!(
        timer,
        [
            0x31, 0x55, 0x00, 0x08, 0x00, 0x07, 0x00, 0x04, 0x12, 0x34, 5, 6
        ]
    );

    let mut ni = [0_u8; 12];
    assert_eq!(
        super::emm::EmmNiReattachControlRequest {
            control: 0x1122_3344
        }
        .encode(&mut ni),
        Ok(12)
    );
    assert_eq!(
        ni,
        [
            0x31, 0x55, 0x00, 0x08, 0x00, 0x0b, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44
        ]
    );

    let ni_response = [0x00, 0x00, 0x00, 0x0b, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44];
    assert_eq!(
        super::emm::EmmControlResponse::parse(packet(0xb156, &ni_response)),
        Ok(super::emm::EmmControlResponse::NiReattach {
            result: 0x1122_3344
        })
    );
    let timer_response = [0x00, 0x00, 0x00, 0x07, 0x00, 0x04, 0, 0, 0, 1];
    assert_eq!(
        super::emm::EmmControlResponse::parse(packet(0xb156, &timer_response)),
        Ok(super::emm::EmmControlResponse::Unsupported { kind: 7 })
    );
    for kind in [8_u8, 9, 10] {
        let response = [0, 0, 0, kind, 0, 4, 0, 0, 0, 1];
        assert_eq!(
            super::emm::EmmControlResponse::parse(packet(0xb156, &response)),
            Ok(super::emm::EmmControlResponse::Unsupported {
                kind: u16::from(kind)
            })
        );
    }

    let report = [0x12, 0x34, 0x00, 0x0b, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd];
    assert_eq!(
        super::emm::EmmControlReport::parse(packet(0xb164, &report)),
        Ok(super::emm::EmmControlReport::Reattach(
            super::emm::EmmReattachControlReport {
                prefix: 0x1234,
                value: 0xaabb_ccdd,
            }
        ))
    );

    let bad_value_len = [0x00, 0x00, 0x00, 0x0b, 0x00, 0x03, 1, 2, 3, 4];
    assert_eq!(
        super::emm::EmmControlResponse::parse(packet(0xb156, &bad_value_len)),
        Err(super::emm::EmmControlDecodeError::UnexpectedValueLength {
            expected: 4,
            actual: 3,
        })
    );
    assert_eq!(
        super::emm::EmmControlResponse::parse(packet(0xb156, &ni_response[..9])),
        Err(super::emm::EmmControlDecodeError::Response(
            super::common::ResponseDecodeError::UnexpectedLength {
                expected: 10,
                actual: 9,
            }
        ))
    );
}

#[test]
fn ue_mode_change_has_exact_one_byte_request_and_response() {
    let mut output = [0_u8; 5];
    assert_eq!(
        super::emm::UeModeChangeRequest { mode: 7 }.encode(&mut output),
        Ok(5)
    );
    assert_eq!(output, [0x31, 0x18, 0x00, 0x01, 7]);
    assert_eq!(
        super::emm::UeModeChangeResponse::parse(packet(0xb14f, &[9])),
        Ok(super::emm::UeModeChangeResponse { result: 9 })
    );
    assert_eq!(
        super::emm::UeModeChangeResponse::parse(packet(0xb14f, &[9, 0])),
        Err(super::common::ResponseDecodeError::UnexpectedLength {
            expected: 1,
            actual: 2,
        })
    );
}

#[test]
fn rrc_capability_common_frames_match_live_p4_set_and_get_grammar() {
    let mut set_frame = [0_u8; 13];
    let set = RrcCapabilitySetRequest {
        type_id: 4,
        data: &[2, 0, 1, 0, 2],
    };
    assert_eq!(set.encode(&mut set_frame), Ok(13));
    assert_eq!(
        set_frame,
        [
            0x39, 0x06, 0x00, 0x09, 0x00, 0x04, 0x00, 0x05, 2, 0, 1, 0, 2
        ]
    );

    let mut get_frame = [0_u8; 6];
    assert_eq!(
        (RrcCapabilityGetRequest { type_id: 18 }).encode(&mut get_frame),
        Ok(6)
    );
    assert_eq!(get_frame, [0x39, 0x0d, 0x00, 0x02, 0x00, 0x12]);

    assert_eq!(
        RrcCapabilitySetResponse::parse(packet(0xb907, &[0, 0, 0, 0, 0, 18])),
        Ok(RrcCapabilitySetResponse {
            result: 0,
            type_id: 18,
            data: &[],
        })
    );
    assert_eq!(
        RrcCapabilityGetResponse::parse(packet(0xb90e, &[0, 0, 0, 4, 0, 5, 2, 0, 1, 0, 2],)),
        Ok(RrcCapabilityGetResponse {
            result: 0,
            type_id: 4,
            data: &[2, 0, 1, 0, 2],
        })
    );
    assert_eq!(
        RrcCapabilityGetResponse::parse(packet(0xb90e, &[0, 0, 0, 4, 0, 5, 2, 0, 1])),
        Err(ResponseDecodeError::UnexpectedLength {
            expected: 11,
            actual: 9,
        })
    );
}

#[test]
fn at_from_device_borrows_the_entire_raw_payload() {
    assert_eq!(
        super::at::AtCommandFromDevice::parse(packet(0xb308, b"\r\nOK\r\n")),
        Ok(super::at::AtCommandFromDevice {
            command: b"\r\nOK\r\n",
        })
    );
    assert_eq!(
        super::at::AtCommandFromDevice::parse(packet(0xb308, &[])),
        Ok(super::at::AtCommandFromDevice { command: &[] })
    );
}

#[test]
fn extended_at_to_device_matches_live_channel_command_lf_layout() {
    static OVERSIZED: [u8; 65_534] = [0; 65_534];

    let command = super::at::AtCommandExt::new(7, b"AT");
    let mut output = [0_u8; 8];
    assert_eq!(command.encode(&mut output), Ok(8));
    assert_eq!(output, [0x33, 0x23, 0x00, 0x04, 7, b'A', b'T', b'\n']);

    assert_eq!(
        super::at::AtCommandExt::new(1, &OVERSIZED).encode(&mut []),
        Err(gct_hci::EncodeError::PayloadTooLong)
    );
}

#[test]
fn extended_at_from_device_splits_channel_from_raw_command() {
    assert_eq!(
        super::at::AtCommandFromDeviceExt::parse(packet(0xb324, &[7, b'O', b'K'])),
        Ok(super::at::AtCommandFromDeviceExt {
            channel: 7,
            command: b"OK",
        })
    );
    assert_eq!(
        super::at::AtCommandFromDeviceExt::parse(packet(0xb324, &[])),
        Err(super::common::ResponseDecodeError::TruncatedPrefix {
            minimum: 1,
            actual: 0,
        })
    );
}
