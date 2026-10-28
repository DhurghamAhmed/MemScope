use std::process::ExitCode;

use memscope::{VERSION, diag};

fn main() -> ExitCode {
    diag::init_from_environment();

    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version" | "-V") => {
            println!("memscope {VERSION}");
            ExitCode::SUCCESS
        }
        Some("--help" | "-h") | None => {
            print_help();
            ExitCode::SUCCESS
        }
        Some("serve") => serve(),
        Some(other) => {
            diag::error(&format!("unknown argument {other:?}; try --help"));
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        r"memscope {VERSION} - local MCP server for Windows process memory analysis

USAGE:
    memscope serve         Serve the MCP tool surface over stdio
    memscope --version     Print the version
    memscope --help        Print this help

ENVIRONMENT:
    MEMSCOPE_ALLOW_WRITE=1      Required, together with confirm=true on the call,
                                before any memory mutation is possible.
    MEMSCOPE_LOG=<level>        error | warn | info | debug (default: info)

While serving, stdout carries protocol messages only; all diagnostics go to stderr.

Target selection is unrestricted. Windows determines process access."
    );
}

fn serve() -> ExitCode {
    let policy = memscope::policy::Policy::default();
    diag::info("target selection: unrestricted; process access is determined by Windows");
    if memscope::writes_enabled_in_environment() {
        diag::warn(
            "MEMSCOPE_ALLOW_WRITE=1: memory mutation is permitted for calls that also pass \
             confirm=true",
        );
    } else {
        diag::info("memory mutation is disabled; set MEMSCOPE_ALLOW_WRITE=1 to permit it");
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            diag::error(&format!("cannot start the async runtime: {e}"));
            return ExitCode::FAILURE;
        }
    };

    runtime.block_on(async {
        use rmcp::ServiceExt;

        let server = memscope::mcp::MemScope::new(policy);
        diag::info(&format!(
            "serving {} tools over stdio, protocol {}",
            memscope::mcp::TOOL_NAMES.len(),
            memscope::mcp::NEGOTIATED_PROTOCOL_VERSION
        ));

        let service = match server.serve(rmcp::transport::stdio()).await {
            Ok(service) => service,
            Err(e) => {
                diag::error(&format!("the stdio transport failed to start: {e}"));
                return ExitCode::FAILURE;
            }
        };

        match service.waiting().await {
            Ok(reason) => {
                diag::info(&format!("the client closed the session: {reason:?}"));
                ExitCode::SUCCESS
            }
            Err(e) => {
                diag::error(&format!("the session ended with an error: {e}"));
                ExitCode::FAILURE
            }
        }
    })
}
