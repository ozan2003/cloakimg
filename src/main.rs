//! Command line entry point for the `cloakimg` tool.

use cloakimg::cli;

fn main()
{
    if let Err(err) = cli::run()
    {
        eprintln!("Error: {err}");
        std::process::exit(1);
    }
}
