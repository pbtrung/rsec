extern crate libc;
extern crate sodiumoxide;
extern crate getopts;
extern crate url;
extern crate reqwest;

use std::io::{stdin, stdout, Write};
use url::Url;
use std::env;
use std::io::prelude::*;
use std::fs::File;
use std::io::SeekFrom;

mod ctr;
mod skein3fish;

use getopts::Options;

fn print_usage(cmd: &str, opts: &Options) {
    let brief = format!("Usage: {} [options] [args]", cmd);
    print!("{}", opts.usage(&brief));
}

fn print_usage_msg(msg: &str, cmd: &str, opts: &Options) {
    println!("{}", msg);
	print_usage(&cmd, &opts);
}

fn main() {
	let mut main_opts = Options::new();
    let main_args: Vec<String> = env::args().collect();
    let program = main_args[0].clone();
    main_opts.optopt("p", "pwd", "path to password file (REQUIRED)", "PATH");
    main_opts.optopt("u", "url", "remote path (URL) to database", "URL");
    main_opts.optopt("l", "local", "local path to database", "PATH");
    main_opts.optflag("h", "help", "show help information");

    let main_matches = match main_opts.parse(&main_args[1..]) {
        Ok(m) => { m },
        Err(_f) => { 
            print_usage_msg("Unknown option(s) or missing arg(s).", &program, &main_opts);
            std::process::exit(-1);
        },
    };
    if main_matches.opt_present("h") && main_args.len() == 2 {
        print_usage(&program, &main_opts);
        return;
    }
    if main_matches.opt_present("h") && main_args.len() != 2 {
    	print_usage_msg("Error: -h/--help cannot be used with other option(s)", &program, &main_opts);
        std::process::exit(-1);
    }

    let mut enc_buf: Vec<u8> = vec![];
    if !main_matches.opt_present("p") {
        print_usage_msg("Password file is required.", &program, &main_opts);
        std::process::exit(-1);
    } else if (main_matches.opt_present("u") && main_matches.opt_present("l")) || (!main_matches.opt_present("u") && !main_matches.opt_present("l")) {
        print_usage_msg("Either URL or local path is needed.", &program, &main_opts);
        std::process::exit(-1);
    } else {
        if main_matches.opt_present("u") {
            let url = match Url::parse(&main_matches.opt_str("u").unwrap()) {
                Err(e) => panic!(e.to_string()),
                Ok(url) => { url },
            };
            if url.scheme() != "https" {
                println!("Only https is allowed for remote URL.");
                std::process::exit(-1);
            }
            let username = rpassword::read_password_from_tty(Some("Username: ")).unwrap();
            let password = rpassword::read_password_from_tty(Some("Password: ")).unwrap();

            let client = reqwest::Client::new();
            let mut resp = client.get(url.as_str())
                .basic_auth(username, Some(password))
                .send().unwrap();
            if !resp.status().is_success() {
                println!("Error(s) happened. Status: {:?}", resp.status());
                println!("Recheck URL, username, and password");
                std::process::exit(-1);
            }
            resp.copy_to(&mut enc_buf).unwrap();
        }

        if main_matches.opt_present("l") {
            let local_path = main_matches.opt_str("l").unwrap();
            let mut enc_file = File::open(local_path).unwrap();
            let mut header = [0; 4];
            enc_file.read(&mut header).unwrap();
            if header != [0x00, 0x00, 0x00, 0x01] {
                println!("Header does not match.\nRecheck local path for correct file.");
                std::process::exit(-1);
            }
            enc_file.seek(SeekFrom::Current(-(header.len() as i64))).unwrap();
            enc_file.read_to_end(&mut enc_buf).unwrap();
        }
    }

    println!("\nPress ? to get help.");
    loop {
		print!("rsec >> ");
        stdout().flush().unwrap();

     	let mut input = String::new();
        match stdin().read_line(&mut input) {
        	Ok(n) => if n <= 1 {
        		continue;
        	},
        	Err(_e) => break,
        }

        let mut sub_opts = Options::new();
        let args: Vec<&str> = input.trim().split_whitespace().collect();
        let cmd = args[0].clone();

        match cmd {
        	"exit" | "e" | "quit" | "q" => return,
        	"show" | "sw" => {
        		sub_opts.optflag("h", "help", "show help information");
        		sub_opts.optopt("t", "tag", "show entries with the same tag", "TAG");

        		let matches = match sub_opts.parse(&args[1..]) {
			        Ok(m) => { m },
			        Err(_f) => { 
	        			print_usage_msg("Unknown option(s) or missing arg(s).", &cmd, &sub_opts);
	        			continue;
			        },
			    };
			    if args.len() == 1 {
	        		print_usage_msg("Unknown option(s) or missing arg(s).", &cmd, &sub_opts);
	        	} else if matches.opt_present("h") && args.len() == 2 {
			        print_usage(&cmd, &sub_opts);
			    } else if matches.opt_present("h") && args.len() != 2 {
			    	print_usage_msg("Error: -h/--help cannot be used with other option(s)", &cmd, &sub_opts);
			    } else {

			    }
        	},
        	"search" | "sh" => println!("search"),
        	"?" | "h" => {
        		println!("show");
        		println!("search");
        		println!("add");
        	},
        	_ => println!("Unknown command. Press ? to get help."),
        }
    }
}
