use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing_subscriber::filter;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// Path to lianad configuration file.
    pub daemon_config_path: Option<PathBuf>,
    /// Path to lianad_rpc socket file.
    pub daemon_rpc_path: Option<PathBuf>,
    /// log level, can be "info", "debug", "trace".
    pub log_level: Option<String>,
    /// Use iced debug feature if true.
    pub debug: Option<bool>,
    /// Start internal bitcoind executable.
    #[serde(default)]
    pub start_internal_bitcoind: bool,
}

pub const DEFAULT_FILE_NAME: &str = "gui.toml";

impl Config {
    pub fn new(daemon_config_path: PathBuf, start_internal_bitcoind: bool) -> Self {
        Self {
            daemon_config_path: Some(daemon_config_path),
            daemon_rpc_path: None,
            log_level: None,
            debug: None,
            start_internal_bitcoind,
        }
    }

    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let config = std::fs::read(path)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => ConfigError::NotFound,
                _ => ConfigError::ReadingFile(format!("Reading configuration file: {}", e)),
            })
            .and_then(|file_content| {
                toml::from_slice::<Config>(&file_content).map_err(|e| {
                    ConfigError::ReadingFile(format!("Parsing configuration file: {}", e))
                })
            })?;

        // check if log_level field is valid
        config.log_level()?;
        Ok(config)
    }

    /// TODO: Deserialize directly in the struct.
    pub fn log_level(&self) -> Result<filter::LevelFilter, ConfigError> {
        if let Some(level) = &self.log_level {
            match level.as_ref() {
                "info" => Ok(filter::LevelFilter::INFO),
                "debug" => Ok(filter::LevelFilter::DEBUG),
                "trace" => Ok(filter::LevelFilter::TRACE),
                _ => Err(ConfigError::InvalidField(
                    "log_level",
                    format!("Unknown value '{}'", level),
                )),
            }
        } else if let Some(true) = self.debug {
            Ok(filter::LevelFilter::DEBUG)
        } else {
            Ok(filter::LevelFilter::INFO)
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum ConfigError {
    InvalidField(&'static str, String),
    NotFound,
    ReadingFile(String),
    Unexpected(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Config file not found"),
            Self::InvalidField(field, message) => {
                write!(f, "Config field {} is invalid: {}", field, message)
            }
            Self::ReadingFile(e) => write!(f, "Error while reading file: {}", e),
            Self::Unexpected(e) => write!(f, "Unexpected error: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {}

// Get the absolute path to the liana configuration folder.
///
/// This a "liana" directory in the XDG standard configuration directory for all OSes but
/// Linux-based ones, for which it's `~/.liana`.
/// Rationale: we want to have the database, RPC socket, etc.. in the same folder as the
/// configuration file but for Linux the XDG specify a data directory (`~/.local/share/`) different
/// from the configuration one (`~/.config/`).
pub fn default_datadir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    let configs_dir = dirs::home_dir();

    #[cfg(not(target_os = "linux"))]
    let configs_dir = dirs::config_dir();

    if let Some(mut path) = configs_dir {
        #[cfg(target_os = "linux")]
        path.push(".liana_demo");

        #[cfg(not(target_os = "linux"))]
        path.push("LianaDemo");

        return Ok(path);
    }

    Err("Failed to get default data directory".into())
}
