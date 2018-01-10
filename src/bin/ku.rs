extern crate clap;
extern crate config;
extern crate kutyus;
extern crate kutyus_core;
extern crate kutyus_persistence;

use clap::{Arg, App, SubCommand, ArgMatches};

use std::env;
use std::path::{PathBuf, Path};

use kutyus::errors::Result;
use kutyus::config::{init, load_config, get_storage_path};


fn main()
{
    let default_config_path = default_config_path();
    let matches = arg_matches(default_config_path.as_str());
    let config_file_path_str = matches.value_of("config").expect("unreachable");
    let config_file_path = Path::new(config_file_path_str);

    if let Some(ref init_matches) = matches.subcommand_matches("init") {
        with_nice_error_handling(|| init(config_file_path, init_matches.is_present("force")))
    } else {
        with_nice_error_handling(|| do_work(config_file_path_str, &matches))
    }
}

fn with_nice_error_handling<F>(func: F)
    where F: Fn() -> Result<()>
{
    if let Err(e) = func() {
        println!("Error: {:?}", e);
    }
}

fn do_work(config_file_path: &str, matches: &ArgMatches) -> Result<()>
{
    let settings = load_config(config_file_path)?;

    if let Some(m) = matches.subcommand_matches("newfeed") {
        let storage_path_string = get_storage_path(&settings);
        prepare_storage_area_if_needed(&storage_path_string)?;
    }

    if let Some(m) = matches.subcommand_matches("append") {
        let storage_path_string = get_storage_path(&settings);
        prepare_storage_area_if_needed(&storage_path_string)?;
        println!("append: storage: {:?}", storage_path_string);
        // get current/latest frame
        // create new frame
    }
    Ok(())
}

fn prepare_storage_area_if_needed(path: &String) -> Result<()>
{
    let storage_path = Path::new(path.as_str());
    create_storage_dir(storage_path)?;
    generate_key(&storage_path.join("keys"))?;
    Ok(())
}

fn create_storage_dir(path: &Path) -> Result<()>
{
    if !path.exists() {
        std::fs::create_dir_all(path.join("feeds"))?;
    }
    Ok(())
}

fn generate_key(path: &Path) -> Result<()>
{
    use std::io::Write;
    if !path.exists() { std::fs::create_dir_all(path)?; }

    let keyfile_path = path.join("my.key");
    if !keyfile_path.exists() {
        let privkey = kutyus_core::generate_private_key()?;
        println!(">> No key found, generating to {:?}", keyfile_path);
        let mut file = std::fs::File::create(keyfile_path)?;
        file.write_all(&privkey)?;
    }
    Ok(())
}

fn arg_matches<'a>(default_config_path: &'a str) -> ArgMatches<'a>
{
    App::new("ku - kutyus-rs CLI")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Marton Suranyi <marton.suranyi@gmail.com>")
        .arg(
            Arg::with_name("config")
            .short("c")
            .long("config")
            .value_name("FILE")
            .help("Override default config path")
            .default_value(default_config_path)
         )
        .subcommand(
            SubCommand::with_name("keygen")
            .about("Generates an Ed25519 keypair from system random (not pseudo)")
        )
        .subcommand(
            SubCommand::with_name("init")
            .about("Initializes your config")
            .arg(Arg::with_name("force")
                 .short("f")
                 .long("force")
                 .help("Forces re-generating config"))
        )
        .subcommand(
            SubCommand::with_name("append")
            .about("Adds new message to your storage - WIP: uses blob content_type, reads content from stdin")
        )
        .subcommand(
            SubCommand::with_name("newfeed")
            .about("Creates a new feed")
            .arg(
                Arg::with_name("name")
                .short("n")
                .long("name")
                .value_name("NAME")
                .help("name of the new feed")
                .required(true)
            )
        )
        .get_matches()
}

fn default_config_path() -> String
{
    let mut config_dir_path: PathBuf = env::var_os("XDG_CONFIG_HOME")
        .map(|x| PathBuf::from(x))
        .unwrap_or_else(|| {
            let home_dir = env::home_dir().expect("Please set HOME or XDG_CONFIG_HOME env vars");
            Path::join(&home_dir, ".config")
        });
    config_dir_path.push("kutyus-rs");
    config_dir_path.push("config.toml");
    config_dir_path.to_string_lossy().into()
}
