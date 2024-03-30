use argon2::{password_hash::PasswordHash, password_hash::PasswordVerifier, Argon2};
use csv::StringRecord;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{self, Write};

fn read_csv_file(filename: &str, username: &str, password: &str) -> Result<(), Box<dyn Error>> {
    // Open the CSV file
    let file = File::open(filename)?;
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(file);

    // Search for the username and load the password hash
    let mut password_hash: Option<String> = None;
    for result in rdr.records() {
        let record = result?;
        if let Some(csv_username) = record.get(0) {
            if csv_username == username {
                if let Some(hash) = record.get(1) {
                    password_hash = Some(hash.to_string());
                    break;
                }
            }
        }
    }

    // Display error if username not found
    if password_hash.is_none() {
        eprintln!("Error: Username not found.");
        return Ok(());
    }

    // Verify password hash with the input password
    let argon2 = Argon2::default();
    let parsed_hash = match PasswordHash::new(&password_hash.unwrap()) {
        Ok(parsed_hash) => parsed_hash,
        Err(err) => return Err(err.to_string().into()),
    };
    if argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
    {
        println!("Success! Password verified.");
    } else {
        eprintln!("Error: Incorrect password.");
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: cargo run <filename>");
        std::process::exit(1);
    }
    let filename = &args[1];

    // Prompt the user for username
    print!("Enter username: ");
    io::stdout().flush()?;
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;

    // Prompt the user for password
    print!("Enter password: ");
    io::stdout().flush()?;
    let mut password = String::new();
    io::stdin().read_line(&mut password)?;

    // Read the CSV file and verify password hash
    read_csv_file(filename, username.trim(), password.trim())
}
