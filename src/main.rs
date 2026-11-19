use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;
use std::{
    io::{self, IsTerminal, Write},
    path::PathBuf,
};
use termius_mcp::{protocol, storage::Store, tools::Runtime};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version,
    about = "Native Rust Termius Cloud MCP server. With no command, serve MCP on stdin/stdout."
)]
struct Cli {
    /// Separate Rust state directory; never automatically modifies Python ~/.termius.
    #[arg(long, env = "TERMIUS_DATA_DIR", global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Sign in interactively. Passwords are read without echo, or from TERMIUS_VAULT_PASSWORD.
    Login {
        #[arg(value_enum)]
        method: Option<LoginMethod>,
        #[arg(short, long)]
        username: Option<String>,
        #[arg(long)]
        otp: Option<String>,
        /// Keep the session, but do not retain the vault password.
        #[arg(long)]
        no_remember: bool,
    },
    /// Show safe session/cache metadata without connecting to the cloud.
    Status,
    /// Erase the saved session, password, SSO state, and local inventory.
    Logout,
    /// Pull and decrypt the cloud inventory now.
    Sync {
        /// Prompt for the vault password instead of using the saved password.
        #[arg(long)]
        password: bool,
        #[arg(long)]
        no_remember: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum LoginMethod {
    Email,
    Google,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    let directory = match cli.data_dir {
        Some(path) => path,
        None => dirs::home_dir()
            .context("Cannot determine the home directory; pass --data-dir")?
            .join(".termius-rs"),
    };
    let runtime = Runtime::new(Store::open(directory)?);
    let Some(command) = cli.command else {
        return protocol::serve(
            runtime,
            tokio::io::BufReader::new(tokio::io::stdin()),
            tokio::io::stdout(),
        )
        .await;
    };
    let result = match command {
        Command::Status => {
            runtime
                .call("status", json!({}), CancellationToken::new())
                .await?
        }
        Command::Logout => {
            runtime
                .call("logout", json!({}), CancellationToken::new())
                .await?
        }
        Command::Sync {
            password,
            no_remember,
        } => {
            let mut args = json!({"remember":!no_remember});
            if password {
                args["password"] = json!(&*vault_password()?);
            }
            runtime.call("sync", args, CancellationToken::new()).await?
        }
        Command::Login {
            method,
            username,
            otp,
            no_remember,
        } => {
            let method = match method {
                Some(m) => m,
                None if username.is_some() => LoginMethod::Email,
                None => match prompt("Sign-in method (google/email) [google]: ")?.as_str() {
                    "" | "google" => LoginMethod::Google,
                    "email" => LoginMethod::Email,
                    _ => bail!("method must be google or email"),
                },
            };
            let (tool, mut args) = match method {
                LoginMethod::Email => {
                    let username = match username {
                        Some(v) => v,
                        None => prompt("Termius email: ")?,
                    };
                    let password = vault_password()?;
                    (
                        "login",
                        json!({"method":"email","username":username,"password":&*password,"remember":!no_remember}),
                    )
                }
                LoginMethod::Google => {
                    let started = runtime
                        .call(
                            "login",
                            json!({"method":"google"}),
                            CancellationToken::new(),
                        )
                        .await?;
                    eprintln!(
                        "Open this URL and complete Google sign-in:\n{}",
                        started["url"].as_str().unwrap_or("")
                    );
                    eprintln!(
                        "Copy the termius://app/continue-sso?... callback from the redirect page. See README for instructions."
                    );
                    let callback = secret_prompt("Paste callback URL (hidden): ")?;
                    let password = vault_password()?;
                    (
                        "login_complete",
                        json!({"callback_url":&*callback,"password":&*password,"remember":!no_remember}),
                    )
                }
            };
            if let Some(otp) = otp {
                args["otp"] = json!(otp);
            }
            let first = runtime
                .call(tool, args.clone(), CancellationToken::new())
                .await;
            match first {
                Ok(data) => data,
                Err(e)
                    if args.get("otp").is_none()
                        && io::stdin().is_terminal()
                        && needs_otp(&e.message) =>
                {
                    args["otp"] = json!(&*secret_prompt("Authenticator code: ")?);
                    runtime.call(tool, args, CancellationToken::new()).await?
                }
                Err(e) => return Err(e.into()),
            }
        }
    };
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn prompt(label: &str) -> Result<String> {
    if !io::stdin().is_terminal() {
        bail!("Interactive input requires a terminal. Specify the login method and --username.");
    }
    eprint!("{label}");
    io::stderr().flush()?;
    let mut text = String::new();
    io::stdin().read_line(&mut text)?;
    Ok(text.trim().to_string())
}
fn secret_prompt(label: &str) -> Result<Zeroizing<String>> {
    if !io::stdin().is_terminal() {
        bail!(
            "Secret input requires a terminal; use TERMIUS_VAULT_PASSWORD for non-interactive email login."
        );
    }
    let text = Zeroizing::new(rpassword::prompt_password(label)?);
    if text.is_empty() {
        bail!("A non-empty value is required");
    }
    Ok(text)
}
fn vault_password() -> Result<Zeroizing<String>> {
    match std::env::var("TERMIUS_VAULT_PASSWORD") {
        Ok(password) if !password.is_empty() => Ok(Zeroizing::new(password)),
        _ => secret_prompt("Vault encryption password: "),
    }
}
fn needs_otp(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("otp")
        || lower.contains("two-factor")
        || lower.contains("2fa")
        || lower.contains("authy")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cli_preserves_default_stdio_and_login_flags() {
        assert!(
            Cli::try_parse_from(["termius-mcp-rs"])
                .unwrap()
                .command
                .is_none()
        );
        assert!(matches!(
            Cli::try_parse_from([
                "termius-mcp-rs",
                "login",
                "email",
                "-u",
                "you@example.com",
                "--no-remember"
            ])
            .unwrap()
            .command,
            Some(Command::Login {
                no_remember: true,
                ..
            })
        ));
        assert!(
            Cli::try_parse_from([
                "termius-mcp-rs",
                "login",
                "--password",
                "do-not-accept-passwords-on-command-line"
            ])
            .is_err()
        );
    }
}
