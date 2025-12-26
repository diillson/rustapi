use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    pub jwt_secret: String,
    pub enable_swagger: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub security: SecurityConfig,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let run_mode = std::env::var("RUN_MODE").unwrap_or_else(|_| "development".into());

        Config::builder()
            // Carrega defaults de config.root.yaml (se existir)
            .add_source(File::with_name("config").required(false))
            // Carrega overrides do ambiente (ex: config.production.yaml)
            .add_source(File::with_name(&run_mode).required(false))
            // Carrega variaveis de ambiente (ex: APP_SERVER_PORT=8080)
            .add_source(Environment::with_prefix("APP").separator("_"))
            .build()?
            .try_deserialize()
    }
}
