fn main() {
    match saw::cli::run(std::env::args().skip(1)) {
        Ok(output) => {
            print!("{}", output);
        }
        Err(err) => {
            eprintln!("error: {}", err);
            std::process::exit(2);
        }
    }
}
