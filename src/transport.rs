use crate::util;

#[derive(Debug)]
pub enum ProtocolType {
    ICMP,
    TCP,
    UDP,
    UNDEFINED(u8),
}

#[derive(Debug)]
pub enum TransportSegment {
    TCP(TCPSegment),
    UDP(UDPSegment),
    UNDEFINED,
}

#[derive(Debug)]
pub struct TCPSegment {
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
    pub fn new(byte_array: &[u8]) -> Option<Self> {
        let mut iter = byte_array.iter().map(|&s| s);

        let source_port: u16 = util::assemble_byte(&mut iter.by_ref().take(2));
        let destination_port: u16 = util::assemble_byte(&mut iter.by_ref().take(2));
        let sequence_number: u32 = util::assemble_byte(&mut iter.by_ref().take(4));
        let acknowledgement_number: u32 = util::assemble_byte(&mut iter.by_ref().take(4));
        let (data_offset, reserved) = util::splice_byte(4, iter.next().unwrap());
        let (cwr, other) = util::splice_byte(1, iter.next().unwrap());
        let (ece, other) = util::splice_byte(2, other);
        let (urg, other) = util::splice_byte(3, other);
        let (ack, other) = util::splice_byte(4, other);
        let (psh, other) = util::splice_byte(5, other);
        let (rst, other) = util::splice_byte(6, other);
        let (syn, fin) = util::splice_byte(7, other);
        let window_size = util::assemble_byte(&mut iter.by_ref().take(2));
        let checksum = util::assemble_byte(&mut iter.by_ref().take(2));
        let urgent_pointer = util::assemble_byte(&mut iter.by_ref().take(2));
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
pub struct UDPSegment {
    source_port: u16,
    destination_port: u16,
    length: u16,
    checksum: u16,
    data: Vec<u8>,
}

impl UDPSegment {
    pub fn new(byte_array: &[u8]) -> Option<Self> {
        let mut iter = byte_array.iter().map(|&s| s);
        
        let source_port = util::assemble_byte(&mut iter.by_ref().take(2));
        let destination_port = util::assemble_byte(&mut iter.by_ref().take(2));
        let length = util::assemble_byte(&mut iter.by_ref().take(2));
        let checksum = util::assemble_byte(&mut iter.by_ref().take(2));
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

