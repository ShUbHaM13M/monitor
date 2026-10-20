//! Runs the real binary against a tiny fake Monitor that records requests.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Debug, Clone)]
struct Hit {
    path: String,
    body: String,
}

/// Answers every request with `status`, recording path and body.
fn fake_monitor(status: u16) -> (String, Arc<Mutex<Vec<Hit>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let hits = Arc::new(Mutex::new(Vec::new()));
    let seen = hits.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let path = request_line
                .split(' ')
                .nth(1)
                .unwrap_or_default()
                .to_owned();
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            seen.lock().unwrap().push(Hit {
                path,
                body: String::from_utf8_lossy(&body).into_owned(),
            });
            let _ = write!(
                stream,
                "HTTP/1.1 {status} X\r\ncontent-length: 3\r\nconnection: close\r\n\r\nOK\n"
            );
        }
    });
    (url, hits)
}

fn monitor_run(url: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_monitor-run"))
        .arg("--url")
        .arg(url)
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn reports_start_and_success_with_output() {
    let (base, hits) = fake_monitor(200);
    let url = format!("{base}/p/tok");
    let out = monitor_run(&url, &["--", "sh", "-c", "echo hello; echo oops >&2"]);
    assert_eq!(out.status.code(), Some(0));
    // Output still reaches the terminal (or cron's mail) as usual.
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hello\n");
    assert_eq!(String::from_utf8_lossy(&out.stderr), "oops\n");

    let hits = hits.lock().unwrap().clone();
    let paths: Vec<_> = hits.iter().map(|h| h.path.as_str()).collect();
    assert_eq!(paths, ["/p/tok/start", "/p/tok/0"]);
    assert!(hits[1].body.contains("hello\n") && hits[1].body.contains("oops\n"));
}

#[test]
fn passes_through_failure_codes() {
    let (base, hits) = fake_monitor(200);
    let out = monitor_run(
        &format!("{base}/p/tok"),
        &["--no-start", "--", "sh", "-c", "echo bad >&2; exit 3"],
    );
    assert_eq!(out.status.code(), Some(3));
    let hits = hits.lock().unwrap().clone();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].path, "/p/tok/3");
    assert_eq!(hits[0].body, "bad\n");
}

#[test]
fn sends_only_the_end_of_long_output() {
    let (base, hits) = fake_monitor(200);
    let out = monitor_run(
        &format!("{base}/p/tok"),
        &[
            "--tail",
            "6",
            "--",
            "sh",
            "-c",
            "printf 'first-line\\nlast\\n'",
        ],
    );
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(hits.lock().unwrap()[1].body, "\nlast\n");
}

#[test]
fn kills_jobs_that_overrun_the_timeout() {
    let (base, hits) = fake_monitor(200);
    // A shell with a child: the whole group goes, or `sleep` would keep the
    // output pipe open and monitor-run waiting.
    let started = std::time::Instant::now();
    let out = monitor_run(
        &format!("{base}/p/tok"),
        &["--timeout", "1", "--", "sh", "-c", "sleep 30; echo never"],
    );
    assert_eq!(out.status.code(), Some(124));
    assert!(started.elapsed().as_secs() < 10);
    let hits = hits.lock().unwrap().clone();
    assert_eq!(hits.last().unwrap().path, "/p/tok/124");
    assert!(hits.last().unwrap().body.contains("killed after 1s"));
}

#[test]
fn sigterm_is_passed_on_and_the_end_reported() {
    let (base, hits) = fake_monitor(200);
    let mut child = Command::new(env!("CARGO_BIN_EXE_monitor-run"))
        .args([
            "--url",
            &format!("{base}/p/tok"),
            "--",
            "sh",
            "-c",
            "trap 'echo stopping; exit 143' TERM; while :; do sleep 0.1; done",
        ])
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    thread::sleep(std::time::Duration::from_millis(500));
    send_signal(child.id(), 15);
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(143));
    let hits = hits.lock().unwrap().clone();
    assert_eq!(hits.last().unwrap().path, "/p/tok/143");
    assert!(hits.last().unwrap().body.contains("stopping"));
}

fn send_signal(pid: u32, signal: i32) {
    Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(pid.to_string())
        .status()
        .unwrap();
}

#[test]
fn missing_commands_report_127() {
    let (base, hits) = fake_monitor(200);
    let out = monitor_run(&format!("{base}/p/tok"), &["--", "/nonexistent/job"]);
    assert_eq!(out.status.code(), Some(127));
    let hits = hits.lock().unwrap().clone();
    assert_eq!(hits.last().unwrap().path, "/p/tok/127");
    assert!(hits.last().unwrap().body.contains("couldn't run"));
}

#[test]
fn an_unreachable_monitor_never_stops_the_job() {
    // Nothing listens here.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/p/tok", listener.local_addr().unwrap());
    drop(listener);
    let out = monitor_run(&url, &["--", "sh", "-c", "echo ran; exit 5"]);
    assert_eq!(out.status.code(), Some(5));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "ran\n");
    assert!(String::from_utf8_lossy(&out.stderr).contains("couldn't report to Monitor"));

    let quiet = monitor_run(&url, &["--quiet", "--", "true"]);
    assert_eq!(quiet.status.code(), Some(0));
    assert!(quiet.stderr.is_empty());
}

#[test]
fn a_wrong_url_is_not_retried() {
    let (base, hits) = fake_monitor(404);
    let out = monitor_run(&format!("{base}/p/wrong"), &["--no-start", "--", "true"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(hits.lock().unwrap().len(), 1);
    assert!(String::from_utf8_lossy(&out.stderr).contains("HTTP 404"));
}
