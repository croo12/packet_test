#![allow(unused)]

use clap::Parser;
use network_test::read_packet;

mod network_test;

#[derive(Parser)]
#[command(name = "NetworkTest")]
#[command(author = "croo12 <its19447@gmail.com")]
#[command(version = "0.1")]
#[command(about = "NetworkTest And Rust Tutorial")]
struct CommandLine {
    #[clap(subcommand)]
    command: Option<Command>
}

#[derive(Parser)]
enum Command {
    Ls,
    Read(ReadArgs)
}

#[derive(Parser)]
struct ReadArgs {
    #[arg(short, long)]
    name: Vec<String>
}

fn main() {
    let cmd = CommandLine::parse();

    if let Some(command) = cmd.command {
        match command {
            Command::Ls => {
                print!("{}", network_test::get_interface_names());
            },
            Command::Read(args) => {
                println!("args = {:?}", args.name);
                // read_packet(&[String::from("\\Device\\NPF_{795C5FEC-E759-4FF5-AE9A-F6782C4FC796}")]);
                read_packet(&args.name);
            }
            _ => {
                println!("this is not defined command");
            }
        }
        
    } else {
        println!(
            "This is Network Test. Made by croo12 <its19447@gmail.com>"
        );
    }


}

// Invoke as echo <interface name>
// fn main() {
//     // let interface_name = env::args().nth(1).unwrap();
//     // let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

//     // Find the network interface with the provided name
//     let interfaces = pnet::datalink::interfaces();
//     for i in &interfaces {
//         println!("이름: {}\n설명: {}\n", i.name, i.description);
//     }

//     let packet_box = Arc::new(RwLock::new(HashMap::new()));
//     let mut handles = vec![];

//     interfaces.into_iter().for_each(|interface| {
//         let map = Arc::clone(&packet_box);
//         let handle = thread::spawn(move || capture_packet(interface, map));
//         handles.push(handle);
//     });

//     loop {
//         // let mut buf = String::new();
//         // stdin().read_line(&mut buf).unwrap();

//         // println!("{}", buf);

//         std::thread::sleep(Duration::from_millis(1000));

//         for (key, packet) in packet_box.read().unwrap().iter() {
//             println!("no.{} packet\n{:?}\n\n", key, packet);
//         }

//         println!("good choice");
//     }
// }

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
