fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("saw_cosigner=info".parse().unwrap()),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();

    match run(args) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let mut iter = args.iter();
    let mut root = std::path::PathBuf::from(
        std::env::var("HOME").unwrap_or_else(|_| ".".into()),
    )
    .join(".saw-cosigner");

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                eprintln!(
                    "saw-cosigner - Human cosigner for SAW threshold signing\n\n\
                     Usage: saw-cosigner [options]\n\n\
                     Options:\n  \
                       --join <url>    Join a keygen or signing ceremony\n  \
                       --root <path>   Data directory (default: ~/.saw-cosigner)\n  \
                       --help          Show this help\n\n\
                     The cosigner holds Share 3 — used for:\n  \
                       - Recovery when another party is compromised\n  \
                       - Approving transactions that exceed policy limits\n  \
                       - Key refresh ceremonies\n"
                );
                return Ok(());
            }
            "--root" => {
                root = std::path::PathBuf::from(
                    iter.next().ok_or("missing --root value")?,
                );
            }
            "--join" => {
                let _url = iter.next().ok_or("missing --join value")?;
                // TODO: Join keygen ceremony as party 2 (human cosigner)
                // TODO: Or join escalated signing session
                eprintln!("join not yet implemented");
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    tracing::info!(root = %root.display(), "saw-cosigner starting");

    // TODO: Listen for incoming signing requests (escalated from saw-policy)
    // TODO: Display transaction details for human review
    // TODO: On approval, participate in MPC signing round

    eprintln!("saw-cosigner: scaffolding only — not yet functional");
    Ok(())
}
