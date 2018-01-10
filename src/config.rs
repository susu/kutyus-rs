
use std::io;
use std::path::Path;

use config_crate::Config;

use ::errors::Result;

pub fn init(path: &Path, force: bool) -> Result<()>
{
    println!("Initializing kutyus-rs instance...");
    if path.exists() {
        if force {
            bail!("Not implemented");
        } else {
            bail!("Already initialized! Use --force to destroy previous instance");
        }
    } else {
        create_initial_config(path)?;
    }

    Ok(())
}

pub fn load_config(path: &str) -> Result<Config>
{
    let mut settings = Config::default();

    settings
        .set_default("storage", expand_path("~/.kutyus-rs/storage".into()))?;

    settings
        .merge(::config_crate::File::with_name(path))?;

    Ok(settings)
}

pub fn get_storage_path(settings: &Config) -> String
{
    expand_path(settings.get_str("storage").expect("unreachable"))
}

fn expand_path(path: String) -> String
{
    use std::env;
    if path.starts_with('~') {
        let home_dir = env::home_dir().expect("Please set HOME env vars");
        return path.replacen('~', home_dir.to_str().expect("unreachable"), 1);
    }
    path
}


fn create_initial_config(path: &Path) -> io::Result<()>
{
    use std::fs;

    let directory = path.parent().expect("Should have a parent directory");
    fs::create_dir_all(directory)?;
    use std::io::Write;
    let mut file = fs::File::create(path)?;
    file.write_all(DEFAULT_CONFIG_FILE.as_bytes())?;
    println!(">> Created default config at {:?}", path);

    Ok(())
}

static DEFAULT_CONFIG_FILE: &'static str =
r#"
# This is the default example kutyus-rs config file.

# Path of your feed-storage
# storage = "~/.kutyus-rs/storage/"
"#;
