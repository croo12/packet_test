use pnet::packet::{ethernet, PrimitiveValues};

use crate::{network, util};

#[derive(Debug)]
pub struct EthernetIIFrame {
    destination: pnet::util::MacAddr,
    sender: pnet::util::MacAddr,
    ether_type: ethernet::EtherType,
    payload: network::PacketType,
}

impl EthernetIIFrame {
    pub fn new(byte_array: &[u8]) -> Option<Self> {
        let mut iter = byte_array.iter().cloned();

        let destination = util::mapping_mac_addr(iter.by_ref().take(6).collect());
        let sender = util::mapping_mac_addr(iter.by_ref().take(6).collect());
        let ether_type = ethernet::EtherType(util::assemble_byte(&mut iter.by_ref().take(2)));

        let bytes: Vec<u8> = iter.collect();

        //=========packet============///
        let packet = match ether_type.to_primitive_values().0 {
            x if x < 0x0600 => network::PacketType::Length(x),
            0x0600 => network::PacketType::XNSIDP,
            0x0800 => network::PacketType::IPv4(network::IPv4Packet::new(&bytes).unwrap()),
            0x0805 => network::PacketType::X25PLP,
            0x0806 => network::PacketType::ARP,
            0x8035 => network::PacketType::RARP,
            0x8137 => network::PacketType::NetwareIPX,
            0x8191 => network::PacketType::NetBIOS,
            0x86DD => network::PacketType::IPv6,
            other => network::PacketType::UNDEFINED(other),
        };

        Some(EthernetIIFrame {
            destination,
            sender,
            ether_type,
            payload: packet,
            // frame_check_sequence,
        })
    }

    pub fn get_source(&self) -> pnet::util::MacAddr {
        self.sender
    }

    pub fn get_network_packet(&self) -> &network::PacketType {
        &self.payload
    }
}