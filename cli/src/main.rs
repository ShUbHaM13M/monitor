//! `monitor-run`: runs a job and reports it to a Monitor check.
//!
//! ```text
//! monitor-run --url https://monitor.example.com/p/<token> -- /usr/local/bin/backup.sh --full
//! ```
//!
//! Pings `/start`, runs the command with its output passed through as usual,
//! then reports the exit code with the last 10 KB of output. Monitoring never
//! gets in the job's way: if Monitor can't be reached the job still runs, and
//! `monitor-run` always exits with the job's own exit code.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::process::{Command, ExitCode, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;

const ATTEMPTS: u32 = 3;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// What `timeout(1)` exits with when it kills a command.
const TIMED_OUT: u8 = 124;
/// What shells exit with when a command can't be run.
const NOT_FOUND: u8 = 127;

#[derive(Parser)]
#[command(version, about, trailing_var_arg = true)]
struct Args {
    /// The check's ping URL, e.g. https://monitor.example.com/p/<token>.
    #[arg(long, env = "MONITOR_URL")]
    url: String,

    /// Don't ping /start (the run time won't be measured).
    #[arg(long)]
    no_start: bool,

    /// Kill the command if it runs longer than this many seconds, and report a failure.
    #[arg(long, value_name = "SECONDS")]
    timeout: Option<u64>,

    /// Bytes of output (the end of it) to send with the result.
    #[arg(long, default_value_t = 10_000, value_name = "BYTES")]
    tail: usize,

    /// Don't warn on stderr when Monitor can't be reached.
    #[arg(long, short)]
    quiet: bool,

    /// The command to run, after `--`.
    #[arg(required = true, num_args = 1.., allow_hyphen_values = true)]
    command: Vec<String>,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let url = args.url.trim_end_matches('/').to_owned();
    if !url.contains("/p/") {
        eprintln!("monitor-run: --url should be a check's ping URL (…/p/<token>)");
    }
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(REQUEST_TIMEOUT))
        .user_agent(concat!("monitor-run/", env!("CARGO_PKG_VERSION")))
        .http_status_as_error(false)
        .build()
        .new_agent();
    let report = |path: &str, body: &[u8]| {
        if let Err(err) = post(&agent, &format!("{url}{path}"), body)
            && !args.quiet
        {
            eprintln!("monitor-run: couldn't report to Monitor: {err}");
        }
    };

    if !args.no_start {
        report("/start", b"");
    }
    let output = Arc::new(Mutex::new(Tail::new(args.tail)));
    let code = match run(&args, &output) {
        Ok(code) => code,
        Err(err) => {
            let message = format!("monitor-run: couldn't run {:?}: {err}\n", args.command[0]);
            eprint!("{message}");
            output.lock().unwrap().push(message.as_bytes());
            NOT_FOUND
        }
    };
    let body = output.lock().unwrap().bytes();
    report(&format!("/{code}"), &body);
    ExitCode::from(code)
}

/// Runs the command, teeing its output into `output`. Returns its exit code.
fn run(args: &Args, output: &Arc<Mutex<Tail>>) -> io::Result<u8> {
    let mut command = Command::new(&args.command[0]);
    command
        .args(&args.command[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Its own process group, so a timeout or signal reaches everything the job
    // started (`sh -c "a | b"`), not just the first process.
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    let mut child = command.spawn()?;
    signals::install();
    let readers = [
        tee(child.stdout.take().unwrap(), io::stdout(), output.clone()),
        tee(child.stderr.take().unwrap(), io::stderr(), output.clone()),
    ];

    let deadline = args
        .timeout
        .map(|s| Instant::now() + Duration::from_secs(s));
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        signals::forward(child.id());
        if deadline.is_some_and(|d| Instant::now() >= d) {
            signals::kill_group(child.id());
            child.kill()?;
            child.wait()?;
            break None;
        }
        thread::sleep(Duration::from_millis(50));
    };
    for reader in readers {
        let _ = reader.join();
    }
    Ok(match status {
        Some(status) => exit_code(status),
        None => {
            let message = format!(
                "monitor-run: killed after {}s (--timeout)\n",
                args.timeout.unwrap_or_default()
            );
            eprint!("{message}");
            output.lock().unwrap().push(message.as_bytes());
            TIMED_OUT
        }
    })
}

/// Copies `from` to `to` as it arrives, keeping the end of it in `tail`.
fn tee(
    mut from: impl Read + Send + 'static,
    mut to: impl Write + Send + 'static,
    tail: Arc<Mutex<Tail>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buf = [0u8; 8192];
        while let Ok(n) = from.read(&mut buf) {
            if n == 0 {
                break;
            }
            let _ = to.write_all(&buf[..n]);
            let _ = to.flush();
            tail.lock().unwrap().push(&buf[..n]);
        }
    })
}

/// The exit code a shell would report: the code, or 128 + the signal.
fn exit_code(status: ExitStatus) -> u8 {
    if let Some(code) = status.code() {
        return code.clamp(0, 255) as u8;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return (128 + signal).clamp(0, 255) as u8;
        }
    }
    1
}

/// POSTs with a few retries; a down monitor shouldn't take long to give up on.
fn post(agent: &ureq::Agent, url: &str, body: &[u8]) -> Result<(), String> {
    let mut last = String::new();
    for attempt in 0..ATTEMPTS {
        if attempt > 0 {
            thread::sleep(Duration::from_secs(1 << (attempt - 1)));
        }
        match agent.post(url).send(body) {
            Ok(res) if res.status().is_success() => return Ok(()),
            // 4xx: wrong URL or rate limited; retrying the first won't help.
            Ok(res) if res.status().is_client_error() && res.status() != 429 => {
                return Err(format!("{url}: HTTP {}", res.status()));
            }
            Ok(res) => last = format!("{url}: HTTP {}", res.status()),
            Err(err) => last = format!("{url}: {err}"),
        }
    }
    Err(last)
}

/// The last `max` bytes written.
struct Tail {
    max: usize,
    buf: VecDeque<u8>,
}

impl Tail {
    fn new(max: usize) -> Self {
        Self {
            max,
            buf: VecDeque::new(),
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        self.buf.extend(bytes);
        let excess = self.buf.len().saturating_sub(self.max);
        self.buf.drain(..excess);
    }

    fn bytes(&self) -> Vec<u8> {
        self.buf.iter().copied().collect()
    }
}

/// Passes SIGTERM, SIGHUP and SIGINT on to the job's process group, so stopping
/// `monitor-run` (Ctrl-C, systemd, a container runtime) stops the job and still
/// reports how it ended.
#[cfg(unix)]
mod signals {
    use std::sync::atomic::{AtomicI32, Ordering};

    static PENDING: AtomicI32 = AtomicI32::new(0);

    extern "C" fn record(signal: libc::c_int) {
        PENDING.store(signal, Ordering::SeqCst);
    }

    pub fn install() {
        for signal in [libc::SIGTERM, libc::SIGHUP, libc::SIGINT] {
            // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
            unsafe {
                libc::signal(signal, record as *const () as libc::sighandler_t);
            }
        }
    }

    pub fn forward(pid: u32) {
        let signal = PENDING.swap(0, Ordering::SeqCst);
        if signal != 0 {
            // SAFETY: plain syscall; a negative pid addresses our child's process group.
            unsafe {
                libc::kill(-(pid as libc::pid_t), signal);
            }
        }
    }

    pub fn kill_group(pid: u32) {
        // SAFETY: as above.
        unsafe {
            libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
        }
    }
}

#[cfg(not(unix))]
mod signals {
    pub fn install() {}
    pub fn forward(_pid: u32) {}
    pub fn kill_group(_pid: u32) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_keeps_the_end() {
        let mut tail = Tail::new(5);
        tail.push(b"hello ");
        tail.push(b"world");
        assert_eq!(tail.bytes(), b"world");
        tail.push(b"!");
        assert_eq!(tail.bytes(), b"orld!");
    }
}
