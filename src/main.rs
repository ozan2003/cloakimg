use std::process;

use png_steganography::cli;

fn main()
{
    if let Err(err) = cli::run()
    {
        eprintln!("Error: {err}");
        process::exit(1);
    }
}
