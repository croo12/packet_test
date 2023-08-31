use pnet::util::MacAddr;
use std::net;

pub fn mapping_mac_addr(datas: Vec<u8>) -> MacAddr {
    if datas.len() != 6 {
        println!("wtf is going on");
        return MacAddr::default();
    }

    MacAddr::new(datas[0], datas[1], datas[2], datas[3], datas[4], datas[5])
}

pub fn mapping_ip4_addr<T>(iter: &mut T) -> net::Ipv4Addr
where
    T: Iterator<Item = u8>,
{
    net::Ipv4Addr::new(
        iter.next().unwrap(),
        iter.next().unwrap(),
        iter.next().unwrap(),
        iter.next().unwrap(),
    )
}

pub fn splice_byte(number: u8, byte: u8) -> (u8, u8) {
    assert!(number < 8);

    let key = 1 << (8 - number);

    (byte / key, byte % key)
}

pub fn assemble_byte<T>(pieces: &mut dyn Iterator<Item = u8>) -> T
where
    T: From<u8> + std::ops::Shl<u8, Output = T> + Default + std::ops::BitOr<Output = T>,
{
    pieces.fold(T::default(), |sum, n| (sum << 8) | T::from(n))
}
