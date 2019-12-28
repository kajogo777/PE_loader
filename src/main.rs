mod parse;
mod structs;

use parse::PE;
use std::env;
use std::fs::File;

fn main() {
    let mut args = env::args();

    if args.len() < 1 {
        println!("Please specify executable name");
        return;
    }

    let path: String = args.nth(1).unwrap();
    println!("{}", path);

    let file = File::open(path.clone()).expect("Unable to open file");
    let pe = PE::new(&file);

    println!("{}", pe);
}
