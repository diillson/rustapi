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
pub struct RateLimitConfig {
    #[serde(default = "rate_limit_per_second_default")]
    pub per_second: u64,
    #[serde(default = "rate_limit_burst_size_default")]
    pub burst_size: u32,
}

fn rate_limit_per_second_default() -> u64 { 10 }
fn rate_limit_burst_size_default() -> u32 { 20 }

#[derive(Debug, Deserialize, Clone)]
pub struct CorsConfig {
    #[serde(default = "cors_origin_default")]
    pub allowed_origin: String,
}

fn cors_origin_default() -> String { "http://localhost:3000".to_string() }

#[derive(Debug, Deserialize, Clone)]
pub struct ObservabilityConfig {
    #[serde(default = "log_level_default")]
    pub log_level: String,
    #[serde(default = "log_format_default")]
    pub log_format: String,
    #[serde(default = "enable_metrics_default")]
    pub enable_metrics: bool,
}

fn log_level_default() -> String { "info".to_string() }
fn log_format_default() -> String { "json".to_string() }
fn enable_metrics_default() -> bool { true }

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub security: SecurityConfig,
    pub rate_limit: RateLimitConfig,
    pub cors: CorsConfig,
    pub observability: ObservabilityConfig,
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
            .add_source(Environment::with_prefix("APP").separator("__").try_parsing(true))
            .build()?
            .try_deserialize()
    }
}
