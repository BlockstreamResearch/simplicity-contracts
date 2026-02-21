#![allow(clippy::missing_errors_doc)]

use std::io::{self, BufRead, Write};

use anyhow::Context;
use serde_json::Value;

mod handler;
mod nodes;
mod protocol;
mod wallet;

use handler::HarnessState;
use protocol::{HarnessRequest, HarnessResponse};

fn write_response(stdout: &mut impl Write, response: &HarnessResponse) -> anyhow::Result<()> {
    serde_json::to_writer(&mut *stdout, response).context("failed to write harness response")?;
    stdout
        .write_all(b"\n")
        .context("failed to terminate harness response line")?;
    stdout.flush().context("failed to flush harness response")?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let run_result: anyhow::Result<()> = async {
        let stdin = io::stdin();
        let mut stdout = io::stdout();
        let mut state = HarnessState::new();

        for line_result in stdin.lock().lines() {
            let line = line_result.context("failed to read stdin line")?;
            if line.trim().is_empty() {
                continue;
            }

            let parsed_value: Value = match serde_json::from_str(&line) {
                Ok(value) => value,
                Err(error) => {
                    let response = HarnessResponse {
                        id: 0,
                        ok: false,
                        result: None,
                        error: Some(format!("invalid JSON request: {error}")),
                    };
                    write_response(&mut stdout, &response)?;
                    continue;
                }
            };

            let id = parsed_value
                .get("id")
                .and_then(Value::as_u64)
                .unwrap_or_default();

            let request: HarnessRequest = match serde_json::from_value(parsed_value) {
                Ok(request) => request,
                Err(error) => {
                    let response = HarnessResponse {
                        id,
                        ok: false,
                        result: None,
                        error: Some(format!("invalid request envelope: {error}")),
                    };
                    write_response(&mut stdout, &response)?;
                    continue;
                }
            };

            let response = match handler::handle_command(&mut state, request.command).await {
                Ok(outcome) => {
                    let response = HarnessResponse {
                        id: request.id,
                        ok: true,
                        result: Some(outcome.result),
                        error: None,
                    };
                    write_response(&mut stdout, &response)?;
                    if outcome.shutdown {
                        break;
                    }
                    continue;
                }
                Err(error) => HarnessResponse {
                    id: request.id,
                    ok: false,
                    result: None,
                    error: Some(error.to_string()),
                },
            };

            write_response(&mut stdout, &response)?;
        }

        Ok(())
    }
    .await;

    let shutdown_result = nodes::shutdown_node_context()
        .context("failed to shutdown node context during harness exit");

    match (run_result, shutdown_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(run_error), Ok(())) => Err(run_error),
        (Ok(()), Err(shutdown_error)) => Err(shutdown_error),
        (Err(run_error), Err(shutdown_error)) => Err(run_error.context(format!(
            "also failed to shutdown node context during harness exit: {shutdown_error}"
        ))),
    }
}
