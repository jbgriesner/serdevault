// examples/config.rs
use serde::{Deserialize, Serialize};
use serdevault::serialize::impls::json::JsonSerialized;
use serdevault::traits::SafeSerde;

#[derive(Serialize, Deserialize, Debug)]
struct AppConfig {
    api_key: String,
    server_url: String,
    max_connections: u32,
    features: Vec<String>,
}

impl SafeSerde for AppConfig {
    type S = JsonSerialized<AppConfig>;
    const VAULT_PATH: &'static str = "~/.fp.crypted";
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a config
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

    // Save it encrypted - will prompt for password
    config.save("toto")?;
    println!("Config saved successfully!");

    // Later, load it back - will prompt for password
    let loaded_config: AppConfig = AppConfig::load("toto")?;
    println!("Loaded config: {:?}", loaded_config);

    // Should failed
    let loaded_config: AppConfig = AppConfig::load("ttytyty")?;
    println!("Loaded config: {:?}", loaded_config);

    Ok(())
}
