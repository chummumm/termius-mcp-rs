#[tokio::main]
async fn main() -> std::process::ExitCode {
    termius_mcp::cli::run().await
}
