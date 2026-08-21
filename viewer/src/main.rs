//! A local viewer for a simulated [`blackwood`] network.
//!
//! The simulated network is entirely in memory: nodes hand each other messages
//! as Rust values, exactly as they do in the core's tests. The only real socket
//! is the one this server listens on so a browser can draw the result.
//!
//! ```text
//! cargo run -p blackwood-viewer -- [port] [ui-directory]
//! ```

mod http;
mod sim;

use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Mutex;

use sim::{Id, Sim};

fn main() {
    let mut args = std::env::args().skip(1);
    let port: u16 = args
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8080);
    let ui_root = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/ui/dist")));

    if !ui_root.join("index.html").exists() {
        eprintln!("warning: no UI at {}", ui_root.display());
        eprintln!("         build it first: cd viewer/ui && npm install && npm run build");
    }

    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("cannot listen on 127.0.0.1:{port}: {error}");
            std::process::exit(1);
        }
    };
    println!("blackwood viewer on http://127.0.0.1:{port}");

    let sim = Mutex::new(Sim::new());
    for stream in listener.incoming().flatten() {
        serve(stream, &sim, &ui_root);
    }
}

fn serve(stream: TcpStream, sim: &Mutex<Sim>, ui_root: &std::path::Path) {
    let Some(request) = http::read(&stream) else {
        return;
    };

    if let Some(command) = request.path.strip_prefix("/api/") {
        // A poisoned lock would mean a previous request panicked mid-command.
        let mut sim = match sim.lock() {
            Ok(sim) => sim,
            Err(poisoned) => poisoned.into_inner(),
        };
        match run(command, &request, &mut sim) {
            Ok(extra) => {
                let state = sim.snapshot();
                let body = match extra {
                    Some(extra) => format!(r#"{{"ok":true,{extra},"state":{state}}}"#),
                    None => format!(r#"{{"ok":true,"state":{state}}}"#),
                };
                http::respond_json(stream, "200 OK", &body);
            }
            Err(message) => {
                let state = sim.snapshot();
                let body = format!(
                    r#"{{"ok":false,"error":{},"state":{state}}}"#,
                    json_string(&message)
                );
                http::respond_json(stream, "200 OK", &body);
            }
        }
        return;
    }

    match http::read_asset(ui_root, &request.path) {
        Some((body, content_type)) => http::respond(stream, "200 OK", content_type, &body),
        None => http::respond(stream, "404 Not Found", "text/plain", b"not found"),
    }
}

/// Runs one command, returning any extra JSON fields it produced.
fn run(command: &str, request: &http::Request, sim: &mut Sim) -> Result<Option<String>, String> {
    // Reading the network is a GET; changing it is a POST.
    if command != "state" && request.method != "POST" {
        return Err(format!("{command} must be a POST"));
    }
    match command {
        "state" => Ok(None),
        "node/add" => {
            sim.add_node()?;
            Ok(None)
        }
        "node/remove" => {
            sim.remove_node(request.number::<Id>("id")?)?;
            Ok(None)
        }
        "link/add" => {
            sim.add_link(request.number::<Id>("a")?, request.number::<Id>("b")?)?;
            Ok(None)
        }
        "link/remove" => {
            sim.remove_link(request.number::<Id>("a")?, request.number::<Id>("b")?)?;
            Ok(None)
        }
        "send" => {
            let delivery = sim.send(request.number::<Id>("from")?, request.number::<Id>("to")?)?;
            let route = delivery
                .route
                .iter()
                .map(Id::to_string)
                .collect::<Vec<_>>()
                .join(",");
            Ok(Some(format!(
                r#""route":[{route}],"delivered":{}"#,
                delivery.delivered
            )))
        }
        "reset" => {
            *sim = Sim::new();
            Ok(None)
        }
        _ => Err(format!("unknown command {command}")),
    }
}

fn json_string(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}
