//! The Python command-line contract, shared by both original executable names.
//!
//! Terminal behavior belongs here; authentication, encrypted state and MCP tool
//! semantics remain in Runtime. The private I/O and service boundaries let the
//! complete login conversation be checked without real credentials or a network.

use crate::{
    protocol,
    storage::Store,
    tools::{Runtime, ToolError, ToolResult},
};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use rustyline::{ColorMode, Config, DefaultEditor, error::ReadlineError};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    io::{self, IsTerminal, Write},
    path::PathBuf,
    process::ExitCode,
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const METHOD_PROMPT: &str = "Sign-in method (google/email) [google]: ";
const EMAIL_PROMPT: &str = "Email: ";
const PASSWORD_PROMPT: &str = "Vault encryption password: ";
const CALLBACK_PROMPT: &str = "Paste callback URL: ";
const OTP_PROMPT: &str = "OTP: ";
const STDIO_BANNER: &str = "Termius MCP server. Point your MCP client at this binary (no args). To sign in from a terminal, run: termius login\nWaiting on stdin.\n";

#[derive(Parser)]
#[command(
    name = "termius",
    bin_name = "termius",
    disable_help_subcommand = true,
    infer_long_args = true,
    args_override_self = true,
    subcommand_value_name = "command",
    about = "Termius Cloud MCP server. With no arguments, speak MCP on stdin/stdout. Use login to sign in from a terminal."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    #[command(
        about = "Sign in with Google, email and password, or OTP",
        infer_long_args = true,
        args_override_self = true,
        long_about = "Sign in to Termius Cloud from a terminal. google prints an SSO URL. email prompts for the vault password. If 2FA is on, the command prompts for OTP."
    )]
    Login(LoginArgs),
    #[command(about = "Sign out and clear local inventory")]
    Logout,
    #[command(about = "Show login state without syncing")]
    Status,
}

#[derive(Args)]
struct LoginArgs {
    /// google SSO or email/password. Prompt if omitted on a TTY.
    #[arg(value_enum)]
    method: Option<LoginMethod>,
    /// Termius email (email method)
    #[arg(short = 'u', long)]
    username: Option<String>,
    /// Authenticator / Authy code if 2FA is on
    #[arg(long)]
    otp: Option<String>,
    /// Do not store the vault password in the secret store
    #[arg(long)]
    no_remember: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum LoginMethod {
    Google,
    Email,
}

/// Starts stdio for an empty argument list, otherwise runs the original CLI.
pub async fn run() -> ExitCode {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let command = if arguments.is_empty() {
        None
    } else {
        match Cli::try_parse_from(std::iter::once(OsString::from("termius")).chain(arguments)) {
            Ok(Cli {
                command: Some(command),
            }) => Some(command),
            Ok(_) => {
                let _ = Cli::command().write_help(&mut io::stderr());
                let _ = writeln!(io::stderr());
                return ExitCode::from(2);
            }
            Err(error) => {
                let code = error.exit_code() as u8;
                let _ = error.print();
                return ExitCode::from(code);
            }
        }
    };
    let mut console = Console::default();
    if command.is_none() && console.is_terminal() {
        let _ = console.write(Stream::Stderr, STDIO_BANNER);
    }
    let store = match data_directory().and_then(Store::open) {
        Ok(store) => store,
        Err(error) => {
            let _ = console.write(Stream::Stderr, &format!("termius: {error}\n"));
            return ExitCode::FAILURE;
        }
    };
    let runtime = Runtime::new(store);
    match command {
        Some(command) => ExitCode::from(execute(command, runtime.as_ref(), &mut console).await),
        None => match protocol::serve(
            runtime,
            tokio::io::BufReader::new(tokio::io::stdin()),
            tokio::io::stdout(),
        )
        .await
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                let _ = console.write(Stream::Stderr, &format!("termius: {error}\n"));
                ExitCode::FAILURE
            }
        },
    }
}

fn data_directory() -> anyhow::Result<PathBuf> {
    if let Some(path) = std::env::var_os("TERMIUS_DATA_DIR").filter(|path| !path.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    dirs::home_dir()
        .map(|home| home.join(".termius-rs"))
        .ok_or_else(|| anyhow::anyhow!("Cannot determine the home directory; set TERMIUS_DATA_DIR"))
}

trait Service {
    async fn call(&self, name: &str, arguments: Value) -> ToolResult;
}

impl Service for Runtime {
    async fn call(&self, name: &str, arguments: Value) -> ToolResult {
        Runtime::call(self, name, arguments, CancellationToken::new()).await
    }
}

#[derive(Clone, Copy)]
enum Stream {
    Stdout,
    Stderr,
}

trait Terminal {
    fn is_terminal(&self) -> bool;
    fn environment_password(&self) -> Option<Zeroizing<String>>;
    fn prompt(&mut self, label: &str) -> io::Result<String>;
    fn secret(&mut self, label: &str) -> io::Result<Zeroizing<String>>;
    fn write(&mut self, stream: Stream, text: &str) -> io::Result<()>;
}

#[derive(Default)]
struct Console {
    editor: Option<DefaultEditor>,
}

impl Terminal for Console {
    fn is_terminal(&self) -> bool {
        io::stdin().is_terminal()
    }

    fn environment_password(&self) -> Option<Zeroizing<String>> {
        std::env::var("TERMIUS_VAULT_PASSWORD")
            .ok()
            .filter(|value| !value.is_empty())
            .map(Zeroizing::new)
    }

    fn prompt(&mut self, label: &str) -> io::Result<String> {
        if self.is_terminal() && io::stdout().is_terminal() {
            if self.editor.is_none() {
                // Raw line editing avoids the terminal's canonical input limit
                // when pasting a long SSO callback. Never load or save history.
                let config = Config::builder()
                    .auto_add_history(false)
                    .color_mode(ColorMode::Disabled)
                    .build();
                self.editor = Some(DefaultEditor::with_config(config).map_err(terminal_error)?);
            }
            self.editor
                .as_mut()
                .expect("editor initialized above")
                .readline(label)
                .map_err(terminal_error)
        } else {
            self.write(Stream::Stdout, label)?;
            stdin_line()
        }
    }

    fn secret(&mut self, label: &str) -> io::Result<Zeroizing<String>> {
        match rpassword::prompt_password(label) {
            Ok(value) => Ok(Zeroizing::new(value)),
            Err(error)
                if !self.is_terminal()
                    && !matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::InvalidData
                    ) =>
            {
                // Python getpass falls back to stdin when /dev/tty cannot be
                // used. Keep piped input usable without echoing it ourselves.
                self.write(Stream::Stderr, "Warning: Password input may be echoed.\n")?;
                self.write(Stream::Stderr, label)?;
                let value = stdin_line()?;
                self.write(Stream::Stderr, "\n")?;
                Ok(Zeroizing::new(value))
            }
            Err(error) => Err(error),
        }
    }

    fn write(&mut self, stream: Stream, text: &str) -> io::Result<()> {
        match stream {
            Stream::Stdout => {
                let mut output = io::stdout().lock();
                output.write_all(text.as_bytes())?;
                output.flush()
            }
            Stream::Stderr => {
                let mut output = io::stderr().lock();
                output.write_all(text.as_bytes())?;
                output.flush()
            }
        }
    }
}

fn terminal_error(error: ReadlineError) -> io::Error {
    match error {
        ReadlineError::Interrupted => {
            io::Error::new(io::ErrorKind::Interrupted, "Input interrupted")
        }
        ReadlineError::Eof => {
            io::Error::new(io::ErrorKind::UnexpectedEof, "EOF when reading a line")
        }
        _ => io::Error::other("Cannot read terminal input"),
    }
}

fn stdin_line() -> io::Result<String> {
    let mut value = String::new();
    if io::stdin().read_line(&mut value)? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "EOF when reading a line",
        ));
    }
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    Ok(value)
}

enum Failure {
    Input(&'static str),
    Service(ToolError),
}

impl From<ToolError> for Failure {
    fn from(error: ToolError) -> Self {
        Self::Service(error)
    }
}

impl From<io::Error> for Failure {
    fn from(error: io::Error) -> Self {
        Self::Input(match error.kind() {
            io::ErrorKind::UnexpectedEof => "EOF when reading a line",
            io::ErrorKind::Interrupted => "Input interrupted",
            _ => "Cannot read or write terminal input",
        })
    }
}

impl Failure {
    fn message(&self) -> String {
        match self {
            Self::Input(message) => (*message).into(),
            Self::Service(error) => format!("Login failed: {}", error.message),
        }
    }
}

async fn execute(command: Command, service: &impl Service, terminal: &mut impl Terminal) -> u8 {
    match dispatch(command, service, terminal).await {
        Ok(()) => 0,
        Err(error) => {
            let _ = terminal.write(Stream::Stderr, &format!("{}\n", error.message()));
            1
        }
    }
}

async fn dispatch(
    command: Command,
    service: &impl Service,
    terminal: &mut impl Terminal,
) -> Result<(), Failure> {
    match command {
        Command::Login(arguments) => login(arguments, service, terminal).await,
        Command::Logout => {
            service.call("logout", json!({})).await?;
            terminal.write(Stream::Stdout, "Signed out.\n")?;
            Ok(())
        }
        Command::Status => {
            let data = service.call("status", json!({})).await?;
            let message = if data["logged_in"].as_bool() == Some(true) {
                let username = data["username"]
                    .as_str()
                    .filter(|name| !name.is_empty())
                    .unwrap_or("unknown");
                let hosts = data["hosts"].as_u64().unwrap_or(0);
                let freshness = if data["stale"].as_bool().unwrap_or(true) {
                    "stale"
                } else {
                    "fresh"
                };
                format!("Signed in as {username}, {hosts} hosts, cache {freshness}.\n")
            } else {
                "Not signed in.\n".into()
            };
            terminal.write(Stream::Stdout, &message)?;
            Ok(())
        }
    }
}

async fn login(
    arguments: LoginArgs,
    service: &impl Service,
    terminal: &mut impl Terminal,
) -> Result<(), Failure> {
    let method = login_method(&arguments, terminal)?;
    let (tool, mut payload) = match method {
        LoginMethod::Email => {
            let username = email_username(&arguments, terminal)?;
            let password = vault_password(terminal)?;
            (
                "login",
                json!({"method":"email","username":username,"password":&*password,"remember":!arguments.no_remember}),
            )
        }
        LoginMethod::Google => {
            let started = service.call("login", json!({"method":"google"})).await?;
            google_instructions(terminal, started["url"].as_str().unwrap_or_default())?;
            let callback = Zeroizing::new(terminal.prompt(CALLBACK_PROMPT)?.trim().to_string());
            if callback.is_empty() {
                return Err(Failure::Input("callback URL is required"));
            }
            let password = vault_password(terminal)?;
            (
                "login_complete",
                json!({"callback_url":&*callback,"password":&*password,"remember":!arguments.no_remember}),
            )
        }
    };
    let supplied_otp = arguments.otp.as_deref().is_some_and(|otp| !otp.is_empty());
    if let Some(otp) = arguments.otp {
        payload["otp"] = json!(otp);
    }
    let response = service.call(tool, payload.clone()).await;
    let data = match response {
        Err(error) if error.code == "otp_required" && !supplied_otp => {
            let otp = Zeroizing::new(terminal.prompt(OTP_PROMPT)?.trim().to_string());
            if otp.is_empty() {
                return Err(Failure::Input("otp is required"));
            }
            payload["otp"] = json!(&*otp);
            service
                .call(tool, payload.clone())
                .await
                .map_err(|error| protect_login_error(error, &payload))?
        }
        Err(error) => return Err(protect_login_error(error, &payload).into()),
        Ok(data) => data,
    };
    let username = data["username"].as_str().unwrap_or("unknown");
    terminal.write(Stream::Stdout, &format!("Signed in as {username}.\n"))?;
    Ok(())
}

fn login_method(
    arguments: &LoginArgs,
    terminal: &mut impl Terminal,
) -> Result<LoginMethod, Failure> {
    if let Some(method) = arguments.method {
        return Ok(method);
    }
    if arguments
        .username
        .as_ref()
        .is_some_and(|username| !username.is_empty())
    {
        return Ok(LoginMethod::Email);
    }
    if !terminal.is_terminal() {
        return Err(Failure::Input("specify google or email"));
    }
    match terminal
        .prompt(METHOD_PROMPT)?
        .trim()
        .to_lowercase()
        .as_str()
    {
        "" | "google" => Ok(LoginMethod::Google),
        "email" => Ok(LoginMethod::Email),
        _ => Err(Failure::Input("method must be google or email")),
    }
}

fn email_username(arguments: &LoginArgs, terminal: &mut impl Terminal) -> Result<String, Failure> {
    if let Some(username) = arguments
        .username
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Ok(username.into());
    }
    if !terminal.is_terminal() {
        return Err(Failure::Input(
            "username is required for email login (use -u)",
        ));
    }
    let username = terminal.prompt(EMAIL_PROMPT)?.trim().to_string();
    if username.is_empty() {
        return Err(Failure::Input("username is required for email login"));
    }
    Ok(username)
}

fn vault_password(terminal: &mut impl Terminal) -> Result<Zeroizing<String>, Failure> {
    if let Some(password) = terminal
        .environment_password()
        .filter(|password| !password.is_empty())
    {
        return Ok(password);
    }
    let password = terminal.secret(PASSWORD_PROMPT)?;
    if password.is_empty() {
        return Err(Failure::Input("vault encryption password is required"));
    }
    Ok(password)
}

fn google_instructions(terminal: &mut impl Terminal, url: &str) -> io::Result<()> {
    terminal.write(Stream::Stderr, &format!("Open this URL in a browser:\n\n  {url}\n\nSign in with Google.\nWhen the page tries to open Termius, copy the termius://app/continue-sso?... URL.\nPaste that URL below.\n"))
}

fn protect_login_error(mut error: ToolError, arguments: &Value) -> ToolError {
    // Cloud errors are already sanitized. This boundary also prevents a future
    // backend change from echoing credentials through the terminal's error path.
    for field in ["password", "otp", "callback_url"] {
        if let Some(secret) = arguments[field]
            .as_str()
            .filter(|secret| !secret.is_empty())
        {
            error.message = error.message.replace(secret, "[redacted]");
        }
    }
    if let Some(callback) = arguments["callback_url"]
        .as_str()
        .and_then(|value| url::Url::parse(value).ok())
    {
        for (name, secret) in callback.query_pairs() {
            if name == "firebaseToken" && !secret.is_empty() {
                error.message = error.message.replace(secret.as_ref(), "[redacted]");
            }
        }
    }
    error
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::VecDeque};

    struct ScriptedService {
        replies: RefCell<VecDeque<ToolResult>>,
        calls: RefCell<Vec<(String, Value)>>,
    }
    impl ScriptedService {
        fn new(replies: Vec<ToolResult>) -> Self {
            Self {
                replies: RefCell::new(replies.into()),
                calls: RefCell::new(Vec::new()),
            }
        }
    }
    impl Service for ScriptedService {
        async fn call(&self, name: &str, arguments: Value) -> ToolResult {
            self.calls.borrow_mut().push((name.into(), arguments));
            self.replies
                .borrow_mut()
                .pop_front()
                .expect("unexpected backend call")
        }
    }

    struct ScriptedTerminal {
        tty: bool,
        environment_password: Option<String>,
        answers: VecDeque<String>,
        passwords: VecDeque<String>,
        prompts: Vec<String>,
        secret_prompts: Vec<String>,
        stdout: String,
        stderr: String,
    }
    impl ScriptedTerminal {
        fn new(tty: bool, answers: &[&str], passwords: &[&str]) -> Self {
            Self {
                tty,
                environment_password: None,
                answers: answers.iter().map(|v| (*v).into()).collect(),
                passwords: passwords.iter().map(|v| (*v).into()).collect(),
                prompts: Vec::new(),
                secret_prompts: Vec::new(),
                stdout: String::new(),
                stderr: String::new(),
            }
        }
    }
    impl Terminal for ScriptedTerminal {
        fn is_terminal(&self) -> bool {
            self.tty
        }
        fn environment_password(&self) -> Option<Zeroizing<String>> {
            self.environment_password.clone().map(Zeroizing::new)
        }
        fn prompt(&mut self, label: &str) -> io::Result<String> {
            self.prompts.push(label.into());
            self.stdout.push_str(label);
            Ok(self.answers.pop_front().expect("unexpected visible prompt"))
        }
        fn secret(&mut self, label: &str) -> io::Result<Zeroizing<String>> {
            self.secret_prompts.push(label.into());
            Ok(Zeroizing::new(
                self.passwords
                    .pop_front()
                    .expect("unexpected password prompt"),
            ))
        }
        fn write(&mut self, stream: Stream, text: &str) -> io::Result<()> {
            match stream {
                Stream::Stdout => self.stdout.push_str(text),
                Stream::Stderr => self.stderr.push_str(text),
            }
            Ok(())
        }
    }
    fn parsed(arguments: &[&str]) -> Command {
        Cli::try_parse_from(std::iter::once("termius").chain(arguments.iter().copied()))
            .unwrap()
            .command
            .expect("command")
    }
    fn signed_in() -> ToolResult {
        Ok(json!({"ok":true,"username":"you@example.com"}))
    }
    fn started() -> ToolResult {
        Ok(json!({"url":"https://account.termius.com/sso/desktop?provider=google&request=fixture"}))
    }
    fn challenge() -> ToolResult {
        Err(ToolError::new("otp_required", "This account requires otp."))
    }
    const CALLBACK: &str = "termius://app/continue-sso?email=you%40example.com&firebaseToken=fixture-firebase-token&requestId=fixture";

    #[test]
    fn parser_preserves_source_commands_and_login_options() {
        assert!(Cli::try_parse_from(["termius"]).unwrap().command.is_none());
        assert!(matches!(
            parsed(&[
                "login",
                "email",
                "-u",
                "you@example.com",
                "--otp",
                "123456",
                "--no-remember"
            ]),
            Command::Login(LoginArgs {
                no_remember: true,
                ..
            })
        ));
        for arguments in [
            vec!["sync"],
            vec!["--version"],
            vec!["--data-dir", "/tmp/example", "status"],
            vec!["login", "--password", "fixture"],
            vec!["login", "EMAIL"],
        ] {
            assert_eq!(
                Cli::try_parse_from(std::iter::once("termius").chain(arguments))
                    .err()
                    .unwrap()
                    .exit_code(),
                2
            );
        }
        let mut help = Vec::new();
        Cli::command().write_long_help(&mut help).unwrap();
        let help = String::from_utf8(help).unwrap();
        assert!(help.contains("login") && help.contains("logout") && help.contains("status"));
        assert!(!help.contains("termius-mcp-rs"));
    }

    #[test]
    fn parser_preserves_argparse_abbreviations_and_last_option_value() {
        let Command::Login(arguments) = parsed(&[
            "login",
            "--user",
            "first@example.com",
            "--username",
            "second@example.com",
            "--otp",
            "111111",
            "--otp",
            "222222",
            "--no-rem",
            "--no-remember",
        ]) else {
            panic!("expected login");
        };
        assert_eq!(arguments.username.as_deref(), Some("second@example.com"));
        assert_eq!(arguments.otp.as_deref(), Some("222222"));
        assert!(arguments.no_remember);
    }

    #[tokio::test]
    async fn email_login_preserves_username_password_and_remember_contract() {
        let service = ScriptedService::new(vec![signed_in()]);
        let mut terminal = ScriptedTerminal::new(true, &[], &["  vault password  "]);
        assert_eq!(
            execute(
                parsed(&[
                    "login",
                    "email",
                    "-u",
                    "  you@example.com  ",
                    "--no-remember"
                ]),
                &service,
                &mut terminal
            )
            .await,
            0
        );
        assert_eq!(terminal.stdout, "Signed in as you@example.com.\n");
        assert!(terminal.stderr.is_empty());
        assert_eq!(terminal.secret_prompts, [PASSWORD_PROMPT]);
        let calls = service.calls.borrow();
        assert_eq!(calls[0].0, "login");
        assert_eq!(
            calls[0].1,
            json!({"method":"email","username":"you@example.com","password":"  vault password  ","remember":false})
        );
    }

    #[tokio::test]
    async fn username_selects_email_without_a_terminal() {
        let service = ScriptedService::new(vec![signed_in()]);
        let mut terminal = ScriptedTerminal::new(false, &[], &[]);
        terminal.environment_password = Some("env-password".into());
        assert_eq!(
            execute(
                parsed(&["login", "-u", "you@example.com"]),
                &service,
                &mut terminal
            )
            .await,
            0
        );
        assert!(terminal.prompts.is_empty() && terminal.secret_prompts.is_empty());
        assert_eq!(service.calls.borrow()[0].1["password"], "env-password");
    }

    #[tokio::test]
    async fn missing_method_and_username_have_original_non_tty_errors() {
        for (args, message) in [
            (vec!["login"], "specify google or email\n"),
            (
                vec!["login", "email"],
                "username is required for email login (use -u)\n",
            ),
            (
                vec!["login", "email", "-u", "  "],
                "username is required for email login (use -u)\n",
            ),
        ] {
            let service = ScriptedService::new(vec![]);
            let mut terminal = ScriptedTerminal::new(false, &[], &[]);
            assert_eq!(execute(parsed(&args), &service, &mut terminal).await, 1);
            assert_eq!(terminal.stderr, message);
            assert!(terminal.stdout.is_empty());
        }
    }

    #[tokio::test]
    async fn interactive_method_is_trimmed_and_case_insensitive() {
        let service = ScriptedService::new(vec![signed_in()]);
        let mut terminal =
            ScriptedTerminal::new(true, &[" EmAiL ", " you@example.com "], &["vault-pass"]);
        assert_eq!(
            execute(parsed(&["login"]), &service, &mut terminal).await,
            0
        );
        assert_eq!(terminal.prompts, [METHOD_PROMPT, EMAIL_PROMPT]);
        assert_eq!(service.calls.borrow()[0].1["username"], "you@example.com");
    }

    #[tokio::test]
    async fn empty_interactive_method_defaults_to_google() {
        let service = ScriptedService::new(vec![started(), signed_in()]);
        let mut terminal = ScriptedTerminal::new(true, &["", CALLBACK], &["vault-pass"]);
        assert_eq!(
            execute(parsed(&["login"]), &service, &mut terminal).await,
            0
        );
        assert_eq!(terminal.prompts, [METHOD_PROMPT, CALLBACK_PROMPT]);
        assert_eq!(service.calls.borrow()[1].0, "login_complete");
    }

    #[tokio::test]
    async fn blank_username_argument_prompts_as_in_python() {
        for args in [vec!["login", "email", "-u", ""], vec!["login", "-u", "  "]] {
            let service = ScriptedService::new(vec![signed_in()]);
            let mut terminal = ScriptedTerminal::new(true, &["you@example.com"], &["vault-pass"]);
            assert_eq!(execute(parsed(&args), &service, &mut terminal).await, 0);
            assert_eq!(terminal.prompts, [EMAIL_PROMPT]);
        }
    }

    #[tokio::test]
    async fn empty_username_does_not_suppress_the_method_prompt() {
        let service = ScriptedService::new(vec![signed_in()]);
        let mut terminal =
            ScriptedTerminal::new(true, &["email", "you@example.com"], &["vault-pass"]);
        assert_eq!(
            execute(parsed(&["login", "-u", ""]), &service, &mut terminal).await,
            0
        );
        assert_eq!(terminal.prompts, [METHOD_PROMPT, EMAIL_PROMPT]);
    }

    #[tokio::test]
    async fn invalid_or_empty_interactive_input_stops_before_authentication() {
        for (args, answers, passwords, message) in [
            (
                vec!["login"],
                vec!["invalid"],
                vec![],
                "method must be google or email\n",
            ),
            (
                vec!["login", "email"],
                vec!["  "],
                vec![],
                "username is required for email login\n",
            ),
            (
                vec!["login", "email", "-u", "you@example.com"],
                vec![],
                vec![""],
                "vault encryption password is required\n",
            ),
        ] {
            let service = ScriptedService::new(vec![]);
            let mut terminal = ScriptedTerminal::new(true, &answers, &passwords);
            assert_eq!(execute(parsed(&args), &service, &mut terminal).await, 1);
            assert_eq!(terminal.stderr, message);
            assert!(service.calls.borrow().is_empty());
        }
    }

    #[tokio::test]
    async fn environment_password_takes_priority_without_trimming() {
        let service = ScriptedService::new(vec![signed_in()]);
        let mut terminal = ScriptedTerminal::new(true, &[], &[]);
        terminal.environment_password = Some(" env password ".into());
        assert_eq!(
            execute(
                parsed(&["login", "email", "-u", "you@example.com"]),
                &service,
                &mut terminal
            )
            .await,
            0
        );
        assert!(terminal.secret_prompts.is_empty());
        assert_eq!(service.calls.borrow()[0].1["password"], " env password ");
    }

    #[tokio::test]
    async fn empty_environment_password_uses_the_password_prompt_even_without_tty() {
        let service = ScriptedService::new(vec![signed_in()]);
        let mut terminal = ScriptedTerminal::new(false, &[], &["piped-password"]);
        terminal.environment_password = Some(String::new());
        assert_eq!(
            execute(
                parsed(&["login", "email", "-u", "you@example.com"]),
                &service,
                &mut terminal
            )
            .await,
            0
        );
        assert_eq!(terminal.secret_prompts, [PASSWORD_PROMPT]);
    }

    #[tokio::test]
    async fn google_instructions_stream_and_visible_callback_match_source() {
        let service = ScriptedService::new(vec![started(), signed_in()]);
        let callback = format!("  {CALLBACK}  ");
        let mut terminal = ScriptedTerminal::new(false, &[&callback], &["vault-pass"]);
        assert_eq!(
            execute(
                parsed(&["login", "google", "--no-remember"]),
                &service,
                &mut terminal
            )
            .await,
            0
        );
        assert_eq!(
            terminal.stderr,
            "Open this URL in a browser:\n\n  https://account.termius.com/sso/desktop?provider=google&request=fixture\n\nSign in with Google.\nWhen the page tries to open Termius, copy the termius://app/continue-sso?... URL.\nPaste that URL below.\n"
        );
        assert_eq!(
            terminal.stdout,
            "Paste callback URL: Signed in as you@example.com.\n"
        );
        assert_eq!(terminal.prompts, [CALLBACK_PROMPT]);
        assert_eq!(terminal.secret_prompts, [PASSWORD_PROMPT]);
        assert_eq!(
            service.calls.borrow()[1].1,
            json!({"callback_url":CALLBACK,"password":"vault-pass","remember":false})
        );
    }

    #[tokio::test]
    async fn empty_google_callback_does_not_prompt_for_a_password() {
        let service = ScriptedService::new(vec![started()]);
        let mut terminal = ScriptedTerminal::new(false, &[" "], &[]);
        assert_eq!(
            execute(parsed(&["login", "google"]), &service, &mut terminal).await,
            1
        );
        assert!(terminal.stderr.ends_with("callback URL is required\n"));
        assert_eq!(service.calls.borrow().len(), 1);
    }

    #[tokio::test]
    async fn long_google_callback_reaches_authentication_unchanged() {
        let callback = format!(
            "termius://app/continue-sso?firebaseToken={}&requestId=fixture",
            "x".repeat(12_000)
        );
        let service = ScriptedService::new(vec![started(), signed_in()]);
        let mut terminal = ScriptedTerminal::new(true, &[&callback], &["vault-pass"]);
        assert_eq!(
            execute(parsed(&["login", "google"]), &service, &mut terminal).await,
            0
        );
        assert_eq!(service.calls.borrow()[1].1["callback_url"], callback);
    }

    #[tokio::test]
    async fn email_otp_challenge_retries_once_with_trimmed_visible_input_without_tty() {
        let service = ScriptedService::new(vec![challenge(), signed_in()]);
        let mut terminal = ScriptedTerminal::new(false, &["  123456  "], &["vault-pass"]);
        assert_eq!(
            execute(
                parsed(&["login", "email", "-u", "you@example.com"]),
                &service,
                &mut terminal
            )
            .await,
            0
        );
        assert_eq!(terminal.prompts, [OTP_PROMPT]);
        assert_eq!(terminal.secret_prompts, [PASSWORD_PROMPT]);
        assert_eq!(service.calls.borrow()[1].1["otp"], "123456");
    }

    #[tokio::test]
    async fn google_otp_challenge_reuses_the_callback_and_password() {
        let service = ScriptedService::new(vec![started(), challenge(), signed_in()]);
        let mut terminal = ScriptedTerminal::new(false, &[CALLBACK, "654321"], &["vault-pass"]);
        assert_eq!(
            execute(parsed(&["login", "google"]), &service, &mut terminal).await,
            0
        );
        assert_eq!(terminal.prompts, [CALLBACK_PROMPT, OTP_PROMPT]);
        let calls = service.calls.borrow();
        assert_eq!(calls[2].0, "login_complete");
        assert_eq!(calls[2].1["callback_url"], CALLBACK);
        assert_eq!(calls[2].1["password"], "vault-pass");
        assert_eq!(calls[2].1["otp"], "654321");
    }

    #[tokio::test]
    async fn supplied_otp_is_not_reprompted_or_trimmed() {
        let service = ScriptedService::new(vec![challenge()]);
        let mut terminal = ScriptedTerminal::new(true, &[], &["vault-pass"]);
        assert_eq!(
            execute(
                parsed(&[
                    "login",
                    "email",
                    "-u",
                    "you@example.com",
                    "--otp",
                    " 123456 "
                ]),
                &service,
                &mut terminal
            )
            .await,
            1
        );
        assert!(terminal.prompts.is_empty());
        assert_eq!(service.calls.borrow().len(), 1);
        assert_eq!(service.calls.borrow()[0].1["otp"], " 123456 ");
        assert_eq!(
            terminal.stderr,
            "Login failed: This account requires otp.\n"
        );
    }

    #[tokio::test]
    async fn empty_supplied_otp_can_be_prompted_once() {
        let service = ScriptedService::new(vec![challenge(), signed_in()]);
        let mut terminal = ScriptedTerminal::new(true, &["123456"], &["vault-pass"]);
        assert_eq!(
            execute(
                parsed(&["login", "email", "-u", "you@example.com", "--otp", ""]),
                &service,
                &mut terminal
            )
            .await,
            0
        );
        assert_eq!(terminal.prompts, [OTP_PROMPT]);
    }

    #[tokio::test]
    async fn empty_otp_stops_without_repeating_authentication() {
        let service = ScriptedService::new(vec![challenge()]);
        let mut terminal = ScriptedTerminal::new(true, &[" "], &["vault-pass"]);
        assert_eq!(
            execute(
                parsed(&["login", "email", "-u", "you@example.com"]),
                &service,
                &mut terminal
            )
            .await,
            1
        );
        assert_eq!(terminal.stderr, "otp is required\n");
        assert_eq!(service.calls.borrow().len(), 1);
    }

    #[tokio::test]
    async fn a_second_otp_challenge_is_returned_without_a_third_attempt() {
        let service = ScriptedService::new(vec![challenge(), challenge()]);
        let mut terminal = ScriptedTerminal::new(true, &["123456"], &["vault-pass"]);
        assert_eq!(
            execute(
                parsed(&["login", "email", "-u", "you@example.com"]),
                &service,
                &mut terminal
            )
            .await,
            1
        );
        assert_eq!(service.calls.borrow().len(), 2);
        assert_eq!(terminal.prompts, [OTP_PROMPT]);
    }

    #[tokio::test]
    async fn mentioning_otp_in_an_unrelated_error_never_prompts() {
        let service = ScriptedService::new(vec![Err(ToolError::new(
            "login_failed",
            "Server rejected an unrelated OTP setting",
        ))]);
        let mut terminal = ScriptedTerminal::new(true, &[], &["vault-pass"]);
        assert_eq!(
            execute(
                parsed(&["login", "email", "-u", "you@example.com"]),
                &service,
                &mut terminal
            )
            .await,
            1
        );
        assert!(terminal.prompts.is_empty());
        assert_eq!(
            terminal.stderr,
            "Login failed: Server rejected an unrelated OTP setting\n"
        );
    }

    #[tokio::test]
    async fn authentication_errors_have_original_prefix_and_cannot_echo_secrets() {
        let service = ScriptedService::new(vec![
            started(),
            Err(ToolError::new(
                "login_failed",
                format!("denied: vault-pass 123456 fixture-firebase-token {CALLBACK}"),
            )),
        ]);
        let mut terminal = ScriptedTerminal::new(false, &[CALLBACK], &["vault-pass"]);
        assert_eq!(
            execute(
                parsed(&["login", "google", "--otp", "123456"]),
                &service,
                &mut terminal
            )
            .await,
            1
        );
        assert!(terminal.stderr.contains("Login failed: denied:"));
        for secret in ["vault-pass", "123456", "fixture-firebase-token", CALLBACK] {
            assert!(!terminal.stderr.contains(secret));
            assert!(!terminal.stdout.contains(secret));
        }
    }

    #[tokio::test]
    async fn bad_credentials_preserve_the_original_error_message() {
        let service =
            ScriptedService::new(vec![Err(ToolError::new("login_failed", "bad credentials"))]);
        let mut terminal = ScriptedTerminal::new(true, &[], &["vault-pass"]);
        assert_eq!(
            execute(
                parsed(&["login", "email", "-u", "you@example.com"]),
                &service,
                &mut terminal
            )
            .await,
            1
        );
        assert_eq!(terminal.stderr, "Login failed: bad credentials\n");
    }

    #[tokio::test]
    async fn status_has_original_plain_text_and_never_syncs() {
        for (data, expected) in [
            (json!({"logged_in":false}), "Not signed in.\n"),
            (
                json!({"logged_in":true,"username":"you@example.com","hosts":3,"stale":true}),
                "Signed in as you@example.com, 3 hosts, cache stale.\n",
            ),
            (
                json!({"logged_in":true,"username":"","hosts":0,"stale":false}),
                "Signed in as unknown, 0 hosts, cache fresh.\n",
            ),
        ] {
            let service = ScriptedService::new(vec![Ok(data)]);
            let mut terminal = ScriptedTerminal::new(false, &[], &[]);
            assert_eq!(execute(Command::Status, &service, &mut terminal).await, 0);
            assert_eq!(terminal.stdout, expected);
            assert!(terminal.stderr.is_empty());
            assert_eq!(service.calls.borrow()[0].0, "status");
        }
    }

    #[tokio::test]
    async fn logout_has_original_plain_text() {
        let service = ScriptedService::new(vec![Ok(json!({"ok":true,"logged_in":false}))]);
        let mut terminal = ScriptedTerminal::new(false, &[], &[]);
        assert_eq!(execute(Command::Logout, &service, &mut terminal).await, 0);
        assert_eq!(terminal.stdout, "Signed out.\n");
        assert!(terminal.stderr.is_empty());
        assert_eq!(service.calls.borrow()[0].0, "logout");
    }
}
