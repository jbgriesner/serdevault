use serde::{Deserialize, Serialize};
use serdevault::VaultFile;

#[derive(Serialize, Deserialize, Debug)]
struct AppConfig {
    api_key: String,
    server_url: String,
    max_connections: u32,
    features: Vec<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig {
        api_key: "secret_key_12345".to_string(),
        server_url: "https://api.example.com".to_string(),
        max_connections: 100,
        features: vec![
            "auth".to_string(),
            "messaging".to_string(),
            "storage".to_string(),
        ],
    };

    let vault = VaultFile::open("~/toto.vault", "correct-horse-battery");

    vault.save(&config)?;
    println!("Saved successfully.");

    let loaded: AppConfig = vault.load()?;
    println!("Loaded: {loaded:?}");

    let wrong = VaultFile::open("~/toto.vault", "wrong_password");
    match wrong.load::<AppConfig>() {
        Err(e) => println!("Expected error: {e}"),
        Ok(_) => println!("This should never print"),
    }

    Ok(())
}
