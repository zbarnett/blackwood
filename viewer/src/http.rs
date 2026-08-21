//! Just enough HTTP to talk to a browser on the loopback interface.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

/// A parsed request line. Bodies are never read: every command this server
/// takes says what it needs in the query string.
pub struct Request {
    /// `GET`, `POST`, and so on.
    pub method: String,
    /// The path, with the query string stripped off.
    pub path: String,
    /// Query parameters, undecoded. Every value this server reads is a number.
    pub query: BTreeMap<String, String>,
}

impl Request {
    /// Reads a query parameter as a number.
    pub fn number<T: std::str::FromStr>(&self, name: &str) -> Result<T, String> {
        self.query
            .get(name)
            .ok_or_else(|| format!("missing parameter {name}"))?
            .parse()
            .map_err(|_| format!("parameter {name} is not a number"))
    }
}

/// Reads one request, stopping at the end of the headers.
pub fn read(stream: &TcpStream) -> Option<Request> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;

    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();

    // Drain the headers so the browser is not left mid-write.
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).ok()? == 0 || header.trim().is_empty() {
            break;
        }
    }

    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path.to_string(), parse_query(query)),
        None => (target, BTreeMap::new()),
    };
    Some(Request {
        method,
        path,
        query,
    })
}

fn parse_query(query: &str) -> BTreeMap<String, String> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

/// Writes a response and closes the connection.
pub fn respond(mut stream: TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

/// Responds with JSON.
pub fn respond_json(stream: TcpStream, status: &str, body: &str) {
    respond(stream, status, "application/json", body.as_bytes());
}

/// Reads a file to serve, refusing anything that tries to climb out of `root`.
pub fn read_asset(root: &std::path::Path, path: &str) -> Option<(Vec<u8>, &'static str)> {
    let relative = path.trim_start_matches('/');
    let relative = if relative.is_empty() {
        "index.html"
    } else {
        relative
    };
    if relative.split('/').any(|part| part == "..") {
        return None;
    }
    let full = root.join(relative);
    let mut file = std::fs::File::open(&full).ok()?;
    let mut body = Vec::new();
    file.read_to_end(&mut body).ok()?;
    Some((body, content_type_for(relative)))
}

fn content_type_for(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, extension)| extension) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("wasm") => "application/wasm",
        Some("json") => "application/json",
        Some("ico") => "image/x-icon",
        _ => "application/octet-stream",
    }
}
