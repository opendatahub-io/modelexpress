use modelexpress_operator::{controller, telemetry};

#[derive(Debug, thiserror::Error)]
enum MainError {
    #[error("kubernetes client: {0}")]
    Client(#[from] kube::Error),
    #[error(transparent)]
    Telemetry(#[from] telemetry::TelemetryError),
    #[error("bad metrics addr {addr}: {source}")]
    Addr {
        addr: String,
        source: std::net::AddrParseError,
    },
}

#[tokio::main]
async fn main() -> Result<(), MainError> {
    telemetry::init_tracing(telemetry::LogFormat::from_env())?;

    let handle = telemetry::install_recorder()?;
    let addr = telemetry::DEFAULT_ADDR
        .parse()
        .map_err(|source| MainError::Addr {
            addr: telemetry::DEFAULT_ADDR.to_string(),
            source,
        })?;

    let client = kube::Client::try_default().await?;
    tracing::info!(%addr, "modelexpress-operator starting");

    // either side exiting is fatal: a dead metrics listener means dead
    // probes, which should restart the pod rather than linger half-alive
    tokio::select! {
        res = telemetry::serve(addr, handle) => res?,
        res = controller::run(client) => res?,
    }
    Ok(())
}
