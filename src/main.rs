extern crate pnet;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;

use std::env;
use std::net::Ipv4Addr;

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
    IP{
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
        data: Vec<u8>,
    },
    X25PLP,
    ARP,
    RARP,
    NetwareIPX,
    NetBIOS,
    IPv6,
    UNDEFINED(u16),
}

#[derive(Debug)]
struct CustomPacket {
    destination: MacAddr,
    sender: MacAddr,
    packet_type: PacketType,
}

// Invoke as echo <interface name>
fn main() {
    let interface_name = env::args().nth(1).unwrap();
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    for i in &interfaces {
        println!("name: {}\ndescription: {}\n", i.name, i.description);
    }

    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    // Create a new channel, dealing with layer 2 packets
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    // std::collections::Hash

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap();

                let packet = make_custom_packet(packet.packet());
                match packet {
                    Some(packet) => {
                        println!("\n{:?}", packet);
                    }
                    None => {
                        println!("Problem is happened");
                    }
                };

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
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}

fn make_custom_packet(raw_packet: &[u8]) -> Option<CustomPacket> {
    let mut iter = raw_packet.iter().cloned();

    let destination = mapping_mac_addr(iter.by_ref().take(6).collect());
    let sender = mapping_mac_addr(iter.by_ref().take(6).collect());
    let packet_type = match (iter.next().unwrap()) as u16 * 256 + (iter.next().unwrap()) as u16 {
        x if x < 0x0600 => PacketType::Length(x),
        0x0600 => PacketType::XNSIDP,
        0x0800 => {
            //- 버전(4비트) - header length(4비트)
            let mut byte = iter.next().unwrap();

            let version = byte / 16;
            let header_length = byte % 16;

            // - type service(1바이트)
            let diff_serv = iter.next().unwrap();

            // - total length(2바이트)
            let total_length: u16 =
                iter.next().unwrap() as u16 * 256 + iter.next().unwrap() as u16;

            // - identification(16비트)
            let identification: u16 =
                iter.next().unwrap() as u16 * 256 + iter.next().unwrap() as u16;

            // - flag(3비트) - fragment offset(13비트)
            byte = iter.next().unwrap();

            let flag = byte / 32;
            let fragment: u16 = byte as u16 % 32 + iter.next().unwrap() as u16;

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
            let header_checksum: u16 = iter.next().unwrap() as u16 * 256 + iter.next().unwrap() as u16;

            // - 보내는 사람 ip주소(32비트)
            let sender_ip = mapping_ip4_addr(&mut iter);
            // - 받는 사람 ip주소(32비트)
            let receiver_ip = mapping_ip4_addr(&mut iter);

            //여기까지 20bytes
            let option: Vec<u8> = iter.by_ref().take((header_length*4 - 20) as usize).collect();

            // - data(세그먼트) 나머지 전부
            let data: Vec<u8> = iter.collect();
            
            PacketType::IP{
                version, header_length, 
                diff_serv, 
                total_length, 
                identification,
                flag, fragment, 
                ttl, 
                protocol_type, 
                header_checksum,
                sender_ip, 
                receiver_ip,
                option,
                data
            }
        }
        0x0805 => PacketType::X25PLP,
        0x0806 => PacketType::ARP,
        0x8035 => PacketType::RARP,
        0x8137 => PacketType::NetwareIPX,
        0x8191 => PacketType::NetBIOS,
        0x86DD => PacketType::IPv6,
        other => PacketType::UNDEFINED(other),
    };

    Some(CustomPacket {
        destination,
        sender,
        packet_type,
    })
}

fn mapping_mac_addr(datas: Vec<u8>) -> MacAddr {
    if datas.len() != 6 {
        println!("wtf is going on");
        return MacAddr::default();
    }

    MacAddr::new(
        datas[0], datas[1], datas[2], datas[3], datas[4], datas[5],
    )
}

fn mapping_ip4_addr<T>(iter: &mut T) -> Ipv4Addr
    where T: Iterator<Item = u8>
{
    Ipv4Addr::new(iter.next().unwrap(), iter.next().unwrap(), iter.next().unwrap(), iter.next().unwrap())
}