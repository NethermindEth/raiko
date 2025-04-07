#![allow(incomplete_features)]
use raiko_host::{interfaces::HostResult, server::serve, ProverState};
use std::path::PathBuf;
use tracing::{debug, info};
use tracing_appender::{
    non_blocking::WorkerGuard,
    rolling::{Builder, Rotation},
};
use tracing_subscriber::{fmt, layer::SubscriberExt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() -> HostResult<()> {
    // Get console layer
    let console_layer = console_subscriber::ConsoleLayer::builder()
        .with_default_env()
        .spawn();

    dotenv::dotenv().ok();
    // Remove env_logger initialization - we'll handle everything with tracing
    // env_logger::Builder::from_default_env()
    //    .target(env_logger::Target::Stdout)
    //    .init();

    let state = ProverState::init()?;
    let _guard = subscribe_log(
        &state.opts.log_path,
        &state.opts.log_level,
        state.opts.max_log,
        console_layer,
    );
    debug!("Start config:\n{:#?}", state.opts.proof_request_opt);
    debug!("Args:\n{:#?}", state.opts);

    info!("Supported chains: {:?}", state.chain_specs);
    info!("Start config:\n{:#?}", state.opts.proof_request_opt);
    info!("Args:\n{:#?}", state.opts);

    serve(state).await?;
    Ok(())
}

fn subscribe_log<L>(
    log_path: &Option<PathBuf>,
    log_level: &String,
    max_log: usize,
    console_layer: L,
) -> Option<WorkerGuard>
where
    L: tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync + 'static,
{
    // Create a stdout layer with its own filter
    let stdout_layer = fmt::layer().with_filter(EnvFilter::new("debug"));

    match log_path {
        Some(ref log_path) => {
            let file_appender = Builder::new()
                .rotation(Rotation::DAILY)
                .filename_prefix("raiko.log")
                .max_log_files(max_log)
                .build(log_path)
                .expect("initializing rolling file appender failed");
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

            // Create a JSON layer for file output with its own filter
            let file_layer = fmt::layer()
                .json()
                .with_writer(non_blocking)
                .with_filter(EnvFilter::new(log_level));

            // Set up a registry with all three layers
            tracing_subscriber::registry()
                .with(console_layer)
                .with(stdout_layer)
                .with(file_layer)
                .init();

            Some(guard)
        }
        None => {
            // Without a log path, just set up stdout and console
            tracing_subscriber::registry()
                .with(console_layer)
                .with(stdout_layer)
                .init();

            None
        }
    }
}
