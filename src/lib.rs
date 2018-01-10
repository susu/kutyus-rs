
extern crate kutyus_core;

#[macro_use]
extern crate error_chain;
extern crate config as config_crate;

pub mod errors {
    error_chain!{
        foreign_links {
            Io(::std::io::Error);
            Config(::config_crate::ConfigError);
        }

        links {
            Core(::kutyus_core::errors::Error, ::kutyus_core::errors::ErrorKind);
        }
    }
}

pub mod config;
