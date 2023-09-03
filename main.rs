use quick_xml::Reader;
use quick_xml::events::Event;
use std::fs::File;
use std::io::{BufReader};
use std::str;
use std::env;
use std::io::Write;
use std::fs;

fn main() {
  let args: Vec<String> = env::args().collect();
  if args.len() < 2 {
    println!("\x1b[38;5;208mToo few arguments.\x1b[0m");
    return;
  }
  if args.len() > 3 {
    println!("\x1b[38;5;208mToo many arguments.\x1b[0m");
    return;
  }
  let cve_path = args[1].trim(); // Path to local .xml db
  let find_this = args[2].trim(); // String to search for in the db

  if cve_path.len() < 1 {
    println!("\x1b[38;5;208mInvalid path to CVE database.\x1b[0m");
    return;
  }

  if find_this.len() < 3 {
    println!("\x1b[38;5;208mSearch string is too small.\x1b[0m");
    return;
  }

  println!("\x1b[38;5;208mSearching database...\x1b[0m");
  let file = match File::open(cve_path) {
    Ok(f) => f,
    Err(e) => { println!("\x1b[38;5;208mError opening db file: {}\x1b[0m", e); return; }
  };

  let prereader = BufReader::new(file);
  let mut reader = Reader::from_reader(Box::new(prereader));
  reader.trim_text(true).expand_empty_elements(true);
  let mut buf = Vec::new(); 
  let mut txt: Vec<String> = Vec::new();
  let mut entry = String::new();

  // Loop through xml starts here
  loop {
		match reader.read_event(&mut buf) {
      Ok(Event::Start(ref e)) if e.name() == b"Title" => {
				entry = match reader.read_text(b"Title", &mut Vec::new()) {
					Ok(r) => r,
					Err(e) => { println!("\x1b[38;5;208mError reading xml: {}\x1b[0m", e); return; }
				};
			}
			Ok(Event::Start(ref e)) if e.name() == b"Note" => {
				let attr = &e.attributes().map(|a| a.unwrap()).collect::<Vec<_>>()[1];
				let desc = &attr.value;
				unsafe {
					let desc_str = str::from_utf8_unchecked(&desc);
					if desc_str.eq("Description") {
						let desc_val = match reader.read_text(b"Note", &mut Vec::new()) {
							Ok(x) => x,
							Err(_) => continue,
						};
            txt.push(desc_val);
						if entry.contains(find_this) {
							println!("\x1b[38;5;89mEntry found: \x1b[0m\x1b[38;5;86m{}\x1b[0m", txt[0]);
              println!("\x1b[38;5;208mProcessing complete.\x1b[0m");
						  return;
            }
						txt = Vec::new();
					}
				}
			},
			Ok(Event::Eof) => break, // exits the loop when reaching end of file
			Err(e) => println!("\x1b[38;5;208mError in buffered reader: {}\x1b[0m",  e),
			_ => (), // There are several other `Event`s we do not consider here
		}
		buf.clear();
  }
}
