extern crate pnet;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::{self, ethernet, PrimitiveValues};
use pnet::util::MacAddr;

use std::env;
use std::net::Ipv4Addr;

#[derive(Debug)]
struct EthernetIIFrame {
    destination: MacAddr,
    sender: MacAddr,
    ether_type: ethernet::EtherType,
    payload: PacketType,
    // frame_check_sequence: u32,
}

impl EthernetIIFrame {
    fn new(byte_array: &[u8]) -> Option<Self> {
        let mut iter = byte_array.iter().cloned();

        let destination = mapping_mac_addr(iter.by_ref().take(6).collect());
        let sender = mapping_mac_addr(iter.by_ref().take(6).collect());
        let ether_type = ethernet::EtherType(assemble_byte(&mut iter.by_ref().take(2)));
        // let frame_check_sequence: u32 = assemble_byte(
        //     &mut iter
        //         .by_ref()
        //         .rev()
        //         .take(4)
        //         .collect::<Vec<u8>>()
        //         .into_iter()
        //         .rev(),
        // );

        let bytes: Vec<u8> = iter.collect();

        //=========packet============///
        let packet = match ether_type.to_primitive_values().0 {
            x if x < 0x0600 => PacketType::Length(x),
            0x0600 => PacketType::XNSIDP,
            0x0800 => PacketType::IPv4(IPv4Packet::new(&bytes).unwrap()),
            0x0805 => PacketType::X25PLP,
            0x0806 => PacketType::ARP,
            0x8035 => PacketType::RARP,
            0x8137 => PacketType::NetwareIPX,
            0x8191 => PacketType::NetBIOS,
            0x86DD => PacketType::IPv6,
            other => PacketType::UNDEFINED(other),
        };

        Some(EthernetIIFrame {
            destination,
            sender,
            ether_type,
            payload: packet,
            // frame_check_sequence,
        })
    }
}

#[derive(Debug)]
struct IPv4Packet {
    version: u8,
    header_length: u8,
    diff_serv: u8,
    total_length: u16,
    identification: u16,
    flag: u8,
    fragment: u16,
    ttl: u8,
    protocol_type: ProtocolType,
    header_checksum: u16,
    sender_ip: Ipv4Addr,
    receiver_ip: Ipv4Addr,
    option: Vec<u8>,
    payload: TransportSegment,
}

impl IPv4Packet {
    fn new(byte_array: &[u8]) -> Option<Self> {
        let mut iter = byte_array.iter().map(|&s| s);

        let mut byte: u8 = iter.next().unwrap();

        //- 버전(4비트) - header length(4비트)
        let (version, header_length) = splice_byte(4, byte);

        // - diff_serv(1바이트)
        let diff_serv = iter.next().unwrap();

        // - total length(2바이트)
        let total_length: u16 = assemble_byte(&mut iter.by_ref().take(2));

        // - identification(16비트)
        let identification: u16 = assemble_byte(&mut iter.by_ref().take(2));

        // - flag(3비트) - fragment offset(13비트)
        byte = iter.next().unwrap();

        let (flag, other) = splice_byte(3, byte);
        let fragment: u16 = assemble_byte(&mut [other, iter.next().unwrap()].into_iter());

        // - TTL(1바이트)
        let ttl = iter.next().unwrap();

        // - protocol type(8비트)
        let protocol_type = match iter.next().unwrap() {
            1 => ProtocolType::ICMP,
            6 => ProtocolType::TCP,
            17 => ProtocolType::UDP,
            x => ProtocolType::UNDEFINED(x),
        };

        // - header checksum(16비트)
        let header_checksum: u16 = assemble_byte(&mut iter.by_ref().take(2));

        // - 보내는 사람 ip주소(32비트)
        let sender_ip = mapping_ip4_addr(&mut iter);
        // - 받는 사람 ip주소(32비트)
        let receiver_ip = mapping_ip4_addr(&mut iter);

        //여기까지 20bytes
        let option: Vec<u8> = iter
            .by_ref()
            .take((header_length * 4 - 20) as usize)
            .collect();

        let data: Vec<u8> = iter.collect();
        let payload = match &protocol_type {
            ProtocolType::TCP => {
                TransportSegment::TCP(TCPSegment::new(&data).unwrap())
            },
            ProtocolType::UDP => {
                TransportSegment::UDP(UDPSegment::new(&data).unwrap())
            },
            _ => {
                println!("do nothing");
                TransportSegment::UNDEFINED
            }
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

#[derive(Debug)]
enum TransportSegment {
    TCP(TCPSegment),
    UDP(UDPSegment),
    UNDEFINED,
}

#[derive(Debug)]
struct TCPSegment {
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgement_number: u32,
    data_offset: u8,
    reserved: u8,
    cwr: u8,
    ece: u8,
    urg: u8,
    ack: u8,
    psh: u8,
    rst: u8,
    syn: u8,
    fin: u8,
    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,
    option: Vec<u8>,
    data: Vec<u8>,
}

impl TCPSegment {
    fn new(byte_array: &[u8]) -> Option<Self> {
        let mut iter = byte_array.iter().map(|&s| s);

        let source_port: u16 = assemble_byte(&mut iter.by_ref().take(2));
        let destination_port: u16 = assemble_byte(&mut iter.by_ref().take(2));
        let sequence_number: u32 = assemble_byte(&mut iter.by_ref().take(4));
        let acknowledgement_number: u32 = assemble_byte(&mut iter.by_ref().take(4));
        let (data_offset, reserved) = splice_byte(4, iter.next().unwrap());
        let (fin, other) = splice_byte(1, iter.next().unwrap());
        let (syn, other) = splice_byte(2, other);
        let (rst, other) = splice_byte(3, other);
        let (psh, other) = splice_byte(4, other);
        let (ack, other) = splice_byte(5, other);
        let (urg, other) = splice_byte(6, other);
        let (cwr, ece) = splice_byte(7, other);
        let window_size = assemble_byte(&mut iter.by_ref().take(2));
        let checksum = assemble_byte(&mut iter.by_ref().take(2));
        let urgent_pointer = assemble_byte(&mut iter.by_ref().take(2));
        let option = iter.by_ref().take(data_offset as usize * 4 - 20).collect();
        let data = iter.collect();

        Some(TCPSegment {
            source_port,
            destination_port,
            sequence_number,
            acknowledgement_number,
            data_offset,
            reserved,
            cwr,
            ece,
            urg,
            ack,
            psh,
            rst,
            syn,
            fin,
            window_size,
            checksum,
            urgent_pointer,
            option,
            data,
        })
    }
}

#[derive(Debug)]
struct UDPSegment {
    source_port: u16,
    destination_port: u16,
    length: u16,
    checksum: u16,
    data: Vec<u8>,
}

impl UDPSegment {
    fn new(byte_array: &[u8]) -> Option<Self> {
        let mut iter = byte_array.iter().map(|&s| s);
        
        let source_port = assemble_byte(&mut iter.by_ref().take(2));
        let destination_port = assemble_byte(&mut iter.by_ref().take(2));
        let length = assemble_byte(&mut iter.by_ref().take(2));
        let checksum = assemble_byte(&mut iter.by_ref().take(2));
        let data = iter.collect();

        Some(UDPSegment {
            source_port,
            destination_port,
            length,
            checksum,
            data,
        })
    }
}

#[derive(Debug)]
enum ProtocolType {
    ICMP,
    TCP,
    UDP,
    UNDEFINED(u8),
}

#[derive(Debug)]
enum PacketType {
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

// Invoke as echo <interface name>
fn main() {
    let interface_name = env::args().nth(1).unwrap();
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    for i in &interfaces {
        println!("이름: {}\n설명: {}\n", i.name, i.description);
    }

    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    // Create a new channel, dealing with layer 2 packets
    let (mut _tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_exception) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                EthernetPacket::new(packet);
                // let packet = EthernetPacket::new(packet).unwrap();
                let custom_packet = EthernetIIFrame::new(packet);
                match custom_packet {
                    Some(pc) => {
                        println!("\n{:?}", pc);
                    }
                    None => {
                        println!("Problem is happened");
                    }
                };

                //header 길이가 5가 아닌것
                //identification 이 같은 패킷 flag랑 fragment_offset에 맞춰서 조립하기

                //data 분석하는 방법 비교하기
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}

fn mapping_mac_addr(datas: Vec<u8>) -> MacAddr {
    if datas.len() != 6 {
        println!("wtf is going on");
        return MacAddr::default();
    }

    MacAddr::new(datas[0], datas[1], datas[2], datas[3], datas[4], datas[5])
}

fn mapping_ip4_addr<T>(iter: &mut T) -> Ipv4Addr
where
    T: Iterator<Item = u8>,
{
    Ipv4Addr::new(
        iter.next().unwrap(),
        iter.next().unwrap(),
        iter.next().unwrap(),
        iter.next().unwrap(),
    )
}

fn splice_byte(number: u8, byte: u8) -> (u8, u8) {
    assert!(number < 8);

    let key = 1 << (8 - number);

    (byte / key, byte % key)
}

fn assemble_byte<T>(pieces: &mut dyn Iterator<Item = u8>) -> T
where
    T: From<u8> + std::ops::Shl<u8, Output = T> + Default + std::ops::BitOr<Output = T>,
{
    pieces.fold(T::default(), |sum, n| (sum << 8) | T::from(n))
}

// Constructs a single packet, the same length as the the one received,
// using the provided closure. This allows the packet to be constructed
// directly in the write buffer, without copying. If copying is not a
// problem, you could also use send_to.
//
// The packet is sent once the closure has finished executing.
// tx.build_and_send(1, packet.packet().len(),
//     &mut |mut new_packet| {
//         let mut new_packet = MutableEthernetPacket::new(new_packet).unwrap();

//         // Create a clone of the original packet
//         new_packet.clone_from(&packet);

//         // Switch the source and destination
//         new_packet.set_source(packet.get_destination());
//         new_packet.set_destination(packet.get_source());
// });
