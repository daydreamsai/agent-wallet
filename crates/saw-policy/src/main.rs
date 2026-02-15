use std::path::PathBuf;

mod policy;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("saw_policy=info".parse().unwrap()),
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
    let mut config_path = PathBuf::from("policy.yaml");
    let mut listen = String::from("0.0.0.0:9443");
    let mut root = PathBuf::from(
        std::env::var("HOME")
            .unwrap_or_else(|_| "/opt/saw-policy".into()),
    )
    .join(".saw-policy");

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                eprintln!(
                    "saw-policy - Threshold signing policy agent\n\n\
                     Usage: saw-policy [options]\n\n\
                     Options:\n  \
                       --config <path>  Policy YAML file (default: policy.yaml)\n  \
                       --listen <addr>  Listen address (default: 0.0.0.0:9443)\n  \
                       --root <path>    Data directory (default: ~/.saw-policy)\n  \
                       --join <url>     Join a keygen ceremony\n  \
                       --help           Show this help\n"
                );
                return Ok(());
            }
            "--config" => {
                config_path = PathBuf::from(
                    iter.next().ok_or("missing --config value")?,
                );
            }
            "--listen" => {
                listen = iter.next().ok_or("missing --listen value")?.clone();
            }
            "--root" => {
                root = PathBuf::from(
                    iter.next().ok_or("missing --root value")?,
                );
            }
            "--join" => {
                let _url = iter.next().ok_or("missing --join value")?;
                // TODO: Join keygen ceremony as party 1 (policy agent)
                eprintln!("keygen join not yet implemented");
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    tracing::info!(
        config = %config_path.display(),
        listen = %listen,
        root = %root.display(),
        "saw-policy starting"
    );

    // TODO: Load share from root/keys/
    // TODO: Load policy from config_path
    // TODO: Start WebSocket server on listen addr
    // TODO: Accept connections from saw-daemon
    // TODO: Handle sign requests: evaluate policy → approve/deny/escalate → MPC rounds

    eprintln!("saw-policy: scaffolding only — not yet functional");
    Ok(())
}
