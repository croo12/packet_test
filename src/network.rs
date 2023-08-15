use crate::{transport, util};
use std::net;

#[derive(Debug)]
pub enum PacketType {
    Length(u16),
    XNSIDP,
    IPv4(IPv4Packet),
    X25PLP,
    ARP,
    RARP,
    NetwareIPX,
    NetBIOS,
    IPv6,
    UNDEFINED(u16),
}

#[derive(Debug)]
pub struct IPv4Packet {
    version: u8,
    header_length: u8,
    diff_serv: u8,
    total_length: u16,
    identification: u16,
    flag: u8,
    fragment: u16,
    ttl: u8,
    protocol_type: transport::ProtocolType,
    header_checksum: u16,
    sender_ip: net::Ipv4Addr,
    receiver_ip: net::Ipv4Addr,
    option: Vec<u8>,
    payload: transport::TransportSegment,
}

impl IPv4Packet {
    pub fn new(byte_array: &[u8]) -> Option<Self> {
        let mut iter = byte_array.iter().map(|&s| s);

        let mut byte: u8 = iter.next().unwrap();

        //- 버전(4비트) - header length(4비트)
        let (version, header_length) = util::splice_byte(4, byte);

        // - diff_serv(1바이트)
        let diff_serv = iter.next().unwrap();

        // - total length(2바이트)
        let total_length: u16 = util::assemble_byte(&mut iter.by_ref().take(2));

        // - identification(16비트)
        let identification: u16 = util::assemble_byte(&mut iter.by_ref().take(2));

        // - flag(3비트) - fragment offset(13비트)
        byte = iter.next().unwrap();

        let (flag, other) = util::splice_byte(3, byte);
        let fragment: u16 = util::assemble_byte(&mut [other, iter.next().unwrap()].into_iter());

        // - TTL(1바이트)
        let ttl = iter.next().unwrap();

        // - protocol type(8비트)
        let protocol_type = match iter.next().unwrap() {
            1 => transport::ProtocolType::ICMP,
            6 => transport::ProtocolType::TCP,
            17 => transport::ProtocolType::UDP,
            x => transport::ProtocolType::UNDEFINED(x),
        };

        // - header checksum(16비트)
        let header_checksum: u16 = util::assemble_byte(&mut iter.by_ref().take(2));

        // - 보내는 사람 ip주소(32비트)
        let sender_ip = util::mapping_ip4_addr(&mut iter);
        // - 받는 사람 ip주소(32비트)
        let receiver_ip = util::mapping_ip4_addr(&mut iter);

        //여기까지 20bytes
        let option: Vec<u8> = iter
            .by_ref()
            .take((header_length * 4 - 20) as usize)
            .collect();

        let data: Vec<u8> = iter.collect();
        let payload = match &protocol_type {
            transport::ProtocolType::ICMP => {
                transport::TransportSegment::ICMP(transport::ICMPSegment::new(&data).unwrap())
            }
            transport::ProtocolType::TCP => {
                transport::TransportSegment::TCP(transport::TCPSegment::new(&data).unwrap())
            }
            transport::ProtocolType::UDP => {
                transport::TransportSegment::UDP(transport::UDPSegment::new(&data).unwrap())
            }
            _ => {
                // println!("do nothing");
                transport::TransportSegment::UNDEFINED
            },
        };
        // - data(세그먼트) 나머지 전부

        Some(IPv4Packet {
            version,
            header_length,
            diff_serv,
            total_length,
            identification,
            flag,
            fragment,
            ttl,
            protocol_type,
            header_checksum,
            sender_ip,
            receiver_ip,
            option,
            payload,
        })
    }
}
