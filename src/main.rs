mod datalink;
mod network;
mod transport;
mod util;

extern crate pnet;

use datalink::EthernetIIFrame;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::NetworkInterface;

use std::collections::HashMap;
use std::thread;
use std::sync::{Arc, RwLock};
use std::time::Duration;

// Invoke as echo <interface name>
fn main() {
    // let interface_name = env::args().nth(1).unwrap();
    // let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

    // Find the network interface with the provided name
    let interfaces = pnet::datalink::interfaces();
    for i in &interfaces {
        println!("이름: {}\n설명: {}\n", i.name, i.description);
    }

    let packet_box = Arc::new(RwLock::new(HashMap::new()));
    let mut handles = vec![];

    interfaces.into_iter().for_each(|interface| {
        let map = Arc::clone(&packet_box);
        let handle = thread::spawn(move || capture_packet(interface, map));
        handles.push(handle);
    });

    loop {
        // let mut buf = String::new();
        // stdin().read_line(&mut buf).unwrap();

        // println!("{}", buf);

        std::thread::sleep(Duration::from_millis(1000));

        for (key, packet) in packet_box.read().unwrap().iter() {
            println!("no.{} packet\n{:?}\n\n", key, packet);
        }

        println!("good choice");
    }
}

fn capture_packet(
    interface: NetworkInterface,
    map: Arc<RwLock<HashMap<usize, EthernetIIFrame>>>,
) {
    // Create a new channel, dealing with layer 2 packets
    let (mut _tx, mut rx) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_exception) => panic!("Unhandled channel type"),
        Err(e) => {
            println!("An error occurred when creating the datalink channel: {}\ninterface: {}", e, interface.description);
            return;
        },
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                // EthernetPacket::new(packet);
                // let packet = EthernetPacket::new(packet).unwrap();
                let custom_packet = datalink::EthernetIIFrame::new(packet);
                match custom_packet {
                    Some(pc) => {
                        // println!("\n{:?}", pc);
                        let key = map.read().unwrap().len();
                        map.write().unwrap().insert(key, pc);
                    }
                    None => {
                        println!("Problem is happened");
                    }
                };
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
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
