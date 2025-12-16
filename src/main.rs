use cloakimg::cli::{self, AppError};

fn main() -> Result<(), AppError>
{
    if let Err(err) = cli::run()
    {
        eprintln!("Error: {err}");
        return Err(err);
    }
    Ok(())
}
