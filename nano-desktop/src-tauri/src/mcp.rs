//! Asking the MCP server what it can actually do.
//!
//! The "MCP tools" screen could have been a hardcoded list. It isn't, because a
//! hardcoded list is a promise the app can't keep: the tool inventory lives in
//! `@nano-rs/investigator-mcp-server`, it changes when that package changes, and
//! a screen that confidently shows nine tools while the server exposes twelve is
//! worse than no screen. So we ask the server itself, over the same stdio
//! transport and the same generated config that Claude Code and Codex use — what
//! the analyst sees IS what the agent gets.

use std::time::Duration;

use serde::Serialize;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use crate::error::{Error, Result};

/// npx may have to fetch the package the first time. After that it is cached, but
/// the first call on a cold machine is genuinely slow.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(90);

/// One tool the agent can reach — straight from the server's own `tools/list`.
#[derive(Debug, Clone, Serialize)]
pub struct McpTool {
    /// `search`, `search_sql`, … (the wire name is `mcp__nano__<name>`).
    pub name: String,
    pub description: String,
    /// The JSON Schema for its arguments, as the server declares it.
    pub input_schema: Value,
    /// Which of nano's permissions this tool needs, and therefore whether the
    /// desktop's read-only key can actually call it. Derived, not guessed —
    /// see `required_permission`.
    pub permission: Option<String>,
}

/// The inventory is stable for the life of a connection and costs an npx spawn to
/// fetch, so it is fetched once.
#[derive(Default)]
pub struct McpInventory {
    cached: Mutex<Option<Vec<McpTool>>>,
}

impl McpInventory {
    pub async fn tools(&self, app: &tauri::AppHandle) -> Result<Vec<McpTool>> {
        let mut cached = self.cached.lock().await;
        if let Some(tools) = cached.as_ref() {
            return Ok(tools.clone());
        }
        let tools = list_tools(app).await?;
        *cached = Some(tools.clone());
        Ok(tools)
    }

    /// Re-provisioning (or revoking) changes what the server is pointed at.
    pub async fn invalidate(&self) {
        *self.cached.lock().await = None;
    }
}

/// Speak just enough MCP to ask "what have you got?": initialize, then
/// `tools/list`. One line of JSON-RPC per message over the child's stdio.
async fn list_tools(app: &tauri::AppHandle) -> Result<Vec<McpTool>> {
    let workspace = crate::agent::workspace_dir(app)?;
    let config = workspace.join(".mcp.json");
    if !config.exists() {
        return Err(Error::Internal(
            "Connect the agent tools first — the MCP config has not been written.".into(),
        ));
    }

    // Read the command out of the generated config rather than re-deriving it, so
    // this can never drift from what the agents are actually launched with.
    let raw = std::fs::read_to_string(&config)
        .map_err(|e| Error::Internal(format!("read .mcp.json: {e}")))?;
    let parsed: Value = serde_json::from_str(&raw)
        .map_err(|e| Error::Internal(format!("parse .mcp.json: {e}")))?;
    let server = parsed
        .get("mcpServers")
        .and_then(|servers| servers.get("nano"))
        .ok_or_else(|| Error::Internal("no nano server in .mcp.json".into()))?;

    let command = server
        .get("command")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Internal("no command in .mcp.json".into()))?;

    let mut child = tokio::process::Command::new(command);
    child.current_dir(&workspace);
    if let Some(args) = server.get("args").and_then(Value::as_array) {
        for arg in args.iter().filter_map(Value::as_str) {
            child.arg(arg);
        }
    }
    if let Some(env) = server.get("env").and_then(Value::as_object) {
        for (key, value) in env {
            if let Some(value) = value.as_str() {
                child.env(key, value);
            }
        }
    }

    let mut child = child
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        // Unread stderr on a full pipe would deadlock the child (npx is chatty).
        .stderr(std::process::Stdio::null())
        // The handshake is all we want; the server must not outlive it.
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| Error::Internal(format!("launch MCP server: {e}")))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Error::Internal("MCP server has no stdin".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::Internal("MCP server has no stdout".into()))?;
    let mut lines = BufReader::new(stdout).lines();

    let handshake = async {
        let initialize = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "nano-desktop", "version": env!("CARGO_PKG_VERSION") }
            }
        });
        send(&mut stdin, &initialize).await?;
        // Drain until the initialize response — the server may log first.
        read_response(&mut lines, 1).await?;

        send(
            &mut stdin,
            &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        )
        .await?;
        send(
            &mut stdin,
            &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }),
        )
        .await?;

        let response = read_response(&mut lines, 2).await?;
        Ok::<Value, Error>(response)
    };

    let response = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
        .await
        .map_err(|_| {
            Error::Internal(
                "The MCP server did not answer in time. If this is the first run, npx may \
                 still be downloading it."
                    .into(),
            )
        })??;

    let tools = response
        .get("result")
        .and_then(|result| result.get("tools"))
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Internal("MCP server returned no tool list".into()))?
        .iter()
        .map(|tool| {
            let name = tool
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            McpTool {
                permission: required_permission(&name),
                description: tool
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                input_schema: tool.get("inputSchema").cloned().unwrap_or(Value::Null),
                name,
            }
        })
        .collect();

    Ok(tools)
}

async fn send(stdin: &mut tokio::process::ChildStdin, message: &Value) -> Result<()> {
    let line = format!("{message}\n");
    stdin
        .write_all(line.as_bytes())
        .await
        .map_err(|e| Error::Internal(format!("write to MCP server: {e}")))?;
    stdin
        .flush()
        .await
        .map_err(|e| Error::Internal(format!("flush to MCP server: {e}")))
}

/// Read lines until the JSON-RPC response with this id shows up. Anything else on
/// stdout (a stray log line, a notification) is skipped rather than treated as
/// the answer.
async fn read_response<R>(lines: &mut tokio::io::Lines<BufReader<R>>, id: i64) -> Result<Value>
where
    R: tokio::io::AsyncRead + Unpin,
{
    while let Some(line) = lines
        .next_line()
        .await
        .map_err(|e| Error::Internal(format!("read from MCP server: {e}")))?
    {
        let Ok(message) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if message.get("id").and_then(Value::as_i64) == Some(id) {
            if let Some(error) = message.get("error") {
                return Err(Error::Server(format!("MCP server: {error}")));
            }
            return Ok(message);
        }
    }
    Err(Error::Internal(
        "The MCP server closed before answering.".into(),
    ))
}

/// Which nano permission a tool needs — where we actually KNOW.
///
/// This is what makes the screen honest rather than decorative: the desktop mints
/// a read-only key, so a tool needing anything else cannot be called by pivt, and
/// the analyst should be able to see that rather than discover it when the agent
/// comes back Forbidden. `search_sql` is the live example — the server advertises
/// it as its PRIMARY search tool, and this app cannot call it at all.
///
/// Deliberately NOT a heuristic. An earlier version guessed from the tool's name
/// prefix (`list_*` → `search:view`), which is precisely how a screen ends up
/// stating a permission the server never asked for. Anything not named here
/// returns `None`, and the UI says it doesn't know instead of inventing an answer.
/// nano exposes no per-tool permission metadata today; when it does, this map
/// should be deleted in favour of it.
fn required_permission(tool: &str) -> Option<String> {
    let permission = match tool {
        // Verified against a live run: the call comes back
        // "Forbidden: Raw SQL queries require the search:sql permission".
        "search_sql" => "search:sql",
        "search" | "explain_query" | "get_field_values" => "search:execute",
        "get_schema" => "search:view",
        _ => return None,
    };
    Some(permission.to_string())
}

#[cfg(test)]
mod tests;
