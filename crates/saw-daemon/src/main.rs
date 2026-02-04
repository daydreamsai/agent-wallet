use std::sync::{atomic::AtomicBool, Arc};

use signal_hook::consts::signal::{SIGINT, SIGTERM};
use signal_hook::flag;

fn main() {
    let stop = Arc::new(AtomicBool::new(false));
    let _ = flag::register(SIGINT, stop.clone());
    let _ = flag::register(SIGTERM, stop.clone());

    if let Err(err) = saw_daemon::cli::run_with_shutdown(std::env::args().skip(1), stop) {
        eprintln!("error: {}", err);
        std::process::exit(2);
    }
}
