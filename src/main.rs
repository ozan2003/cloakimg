use std::process;

use cloakimg::cli;

fn main()
{
    if let Err(err) = cli::run()
    {
        eprintln!("Error: {err}");
        process::exit(1);
    }
}
