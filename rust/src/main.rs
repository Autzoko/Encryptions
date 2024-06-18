mod encryptions;

use std::env;
use std::process;

use encryptions::sha_256;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} <message>", args[0]);
        process::exit(1);
    }

    let function = &args[1];
    let message = &args[2];

    if function.eq("sha-256") {
        let hash = sha_256::sha256(message.as_bytes());
        sha_256::print_hash(&hash);
    }
}
