mod datalink;
mod network;
mod transport;
mod util;

extern crate pnet;

use datalink::EthernetIIFrame;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::NetworkInterface;
use pnet::util::MacAddr;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use std::fs;
use std::io::Write;

// static mut THREAD_HANDLER: Vec<JoinHandle<()>> = vec![];
// static mut PACKET_BOX: RwLock<HashMap<NetworkInterface, Vec<EthernetIIFrame>>> = RwLock::new(HashMap::new());

pub fn get_interface_names() -> String {
    let mut context = String::new();

    for interface in pnet::datalink::interfaces() {
        context.push_str(&format!(
            "[ Name : {} ]\ndescript : {}\nmacAddr : {:?}\nips : {:?}\nflags : {}\n",
            interface.name,
            interface.description,
            if let Some(mac_addr) = interface.mac {
                mac_addr
            } else {
                MacAddr::default()
            },
            interface.ips,
            interface.flags
        ));
    }

    return context;
}

pub fn read_packet(interfaces: &[String], is_save: bool) {
    let packet_box: Arc<RwLock<HashMap<NetworkInterface, Vec<EthernetIIFrame>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let mut thread_handler: Vec<JoinHandle<()>> = vec![];

    let interface_list = pnet::datalink::interfaces();
    let interfaces = interface_list
        .into_iter()
        .filter(|x| interfaces.contains(&x.name));

    interfaces.for_each(|interface| {
        let map = Arc::clone(&packet_box);

        println!("action thread for {:?}", &interface.name);

        let handle = thread::spawn(move || capture_packet(&interface, map, is_save));

        thread_handler.push(handle);
    });

    if thread_handler.len() == 0 {
        panic!("No interface be matched");
    }

    loop {
        thread::sleep(Duration::from_millis(1000));
    }
}

fn capture_packet(
    interface: &NetworkInterface,
    map: Arc<RwLock<HashMap<NetworkInterface, Vec<EthernetIIFrame>>>>,
    is_save: bool,
) {
    // Create a new channel, dealing with layer 2 packets
    let (mut _tx, mut rx) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_exception) => panic!("Unhandled channel type"),
        Err(e) => {
            println!(
                "An error occurred when creating the datalink channel: {}\ninterface: {}",
                e, interface.description
            );
            return;
        }
    };

    let file_name = format!(
        "{}__{}.txt",
        interface.name.as_str().replace("\\", "_"),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );

    println!("log file >> {}", file_name);

    let mut log_file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(&file_name);

    let mut log_file = match log_file {
        Err(e) => panic!("{:?}", e),
        Ok(f) => f,
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                // EthernetPacket::new(packet);
                // let packet = EthernetPacket::new(packet).unwrap();
                let custom_packet = datalink::EthernetIIFrame::new(packet);
                match custom_packet {
                    Some(pc) => {
                        //print man
                        let pac = format!("\n{:?}", pc);
                        println!("{}", pac);

                        //save to map
                        // map.write().unwrap().get(interface).unwrap().push(pc);

                        if is_save {
                            if let Err(e) = writeln!(log_file, "{}", pac) {
                                eprintln!("cannot write packet data to this file");
                            }
                        }
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
