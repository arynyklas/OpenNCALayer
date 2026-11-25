//! A response stream the server aborts after it started (a first-fatal resource failure:
//! the client sees only a lost response) must still leave the typed cause in the server's
//! own log. Real `oncl-server` binary, real socket, real stderr.
use crate::server_support as support;

use std::{
    io::{Read, Write},
    sync::LazyLock,
    time::Duration,
};

const ITEM: &str = "CANARY-ITEM-ID";
const PART: &str = "CANARY-PART-NAME";
const FILE: &str = "CANARY-file-name.pdf";
const CONTENT: &str = "CANARY citizen IIN 900101300123 signs contract";

fn batch_body() -> String {
    let metadata = format!(
        r#"{{"items":[{{"id":"{ITEM}","operation":{{"kind":"hash","algorithm":"sha256","input":"{PART}"}}}}],"parts":[{{"name":"{PART}","item_id":"{ITEM}","role":"document"}}]}}"#
    );
    format!(
        "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{metadata}\r\n--b\r\nContent-Disposition: form-data; name=\"{PART}\"; filename=\"{FILE}\"\r\nContent-Type: application/pdf\r\n\r\n{CONTENT}\r\n--b--\r\n"
    )
}

/// One streamed `/v1/batch` request against a server whose `metadata_bytes` is
/// `metadata_bytes`: the raw response bytes and the server's stderr after a graceful stop.
fn run(metadata_bytes: u64) -> (Vec<u8>, String) {
    let mut process = support::Process::configured("127.0.0.1:0", |root| {
        format!(
            "scratch_directory = {}\nmetadata_bytes = {metadata_bytes}",
            support::toml_path(&root.join("scratch")),
        )
    });
    let body = batch_body();
    let mut stream = std::net::TcpStream::connect(process.address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream
        .write_all(
            format!(
                "POST /v1/batch HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: multipart/form-data; boundary=b\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                process.address,
                process.token.as_str(),
                body.len()
            )
            .as_bytes(),
        )
        .unwrap();
    stream.write_all(body.as_bytes()).unwrap();
    let mut response = Vec::new();
    // A cut-short chunked body ends in an error: the bytes read so far are the evidence.
    let _ = stream.read_to_end(&mut response);
    process
        .child
        .stdin
        .take()
        .unwrap()
        .write_all(b"\n")
        .unwrap();
    process.child.wait().unwrap();
    let mut stderr = String::new();
    process
        .child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    (response, stderr)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Seen {
    /// A typed HTTP refusal before any stream.
    Refused,
    /// The stream ended without a terminal record.
    Aborted,
    /// The stream ended with its terminal record, in which the item failed.
    ItemFailed,
    /// The stream ended with its terminal record, in which the item completed.
    Completed,
}
fn seen(response: &[u8]) -> Seen {
    let text = String::from_utf8_lossy(response);
    if response.starts_with(b"HTTP/1.1 413") {
        Seen::Refused
    } else if !text.contains("name=\"final\"") {
        Seen::Aborted
    } else if text.contains(r#""status":"completed""#) {
        Seen::Completed
    } else {
        Seen::ItemFailed
    }
}

/// The smallest `metadata_bytes` at which the hash batch is admitted: below it a
/// reservation made before the 200 head (the captured plan, mostly) fails and the request
/// is refused. Its place moves with every fixed reservation of the service and with the
/// size of the plan's types on the target, so it is found, not hard-coded.
///
/// It does not move between runs: up to the head, one thread does the request's work in
/// one order, and the response stream does not exist yet. The smallest budget that
/// completes, which these tests used to aim below, moves by up to a whole progress part
/// with how the stream and the native work interleave (see below).
static ADMITTED: LazyLock<u64> = LazyLock::new(|| {
    let (mut refused, mut admitted) = (1_000_000u64, 4_000_000u64);
    assert_eq!(
        seen(&run(refused).0),
        Seen::Refused,
        "admitted at {refused}"
    );
    assert_ne!(
        seen(&run(admitted).0),
        Seen::Refused,
        "refused at {admitted}"
    );
    while admitted - refused > 1 {
        let middle = refused + (admitted - refused) / 2;
        if seen(&run(middle).0) == Seen::Refused {
            refused = middle;
        } else {
            admitted = middle;
        }
    }
    admitted
});

// At the head the request holds `ADMITTED` (the plan's last reservations are its peak),
// and the native work keeps all of it until the item's record is made. From the head on,
// two threads draw on the rest of the budget at once:
// - the native work runs the hash item, holding its source reader and digest state (416
//   bytes on 64-bit targets) while it reads: when they do not fit, the item fails, a typed
//   failure in the terminal record. It then keeps the item's record and its terminal copy
//   (512 + 1024 bytes): when they do not fit, the stream is aborted at item 0 with
//   `MetadataLimit` (the D10 cause);
// - the response stream sends its first progress part as soon as the head is out, and
//   again at most every 500 ms: a JSON buffer of at least 1024 bytes, its part header and
//   CRLF (1180 bytes in all), held until the socket has taken them. When it does not fit,
//   the stream is aborted at whatever item the work has begun, if any.
//
// Which thread reserves first is a race. From `ADMITTED + 1536` on, the record fits
// unless a progress part is held at that moment, so one run completes and the next one
// aborts: the old search for the smallest budget that completes, which counted a probe
// as aborting when its few runs all aborted, could stop that far too high, and the
// budget it aimed below then completed in every run. Below `ADMITTED + 1536` no run
// completes cleanly; the offsets below choose what the race can still decide.

/// Every run aborts. The progress part's 1024-byte JSON buffer never fits next to what
/// the work holds, so the stream sends nothing while the work runs; the work alone runs
/// the item (416 bytes) and never keeps its record (1536 bytes). The stream is aborted
/// either by the progress part, or by the work's error once the work has let go and the
/// progress part has been sent. Which of the two, and so whether the line names the item
/// (`item=none` when the progress part failed before the item began), is still the race.
const ALWAYS_ABORTS: u64 = 720;

/// Every abort is at item 0: the first progress part always fits next to what the work
/// holds before the item (1180 bytes), and the record never does (1536 bytes). Only one
/// race is left, and it cannot be closed by a budget: a progress part held at the moment
/// the item takes its digest state (1180 + 416 > 1536) makes the item fail, a typed
/// failure in a completed stream. That run is not an answer to the question of the test
/// and is made again, a few times; any other outcome is the answer, and a stream that
/// completes the item is a failure.
const ABORTS_AT_ITEM: u64 = 1358;
fn aborted_at_item() -> (Vec<u8>, String) {
    let mut last = run(*ADMITTED + ABORTS_AT_ITEM);
    for _ in 1..ATTEMPTS {
        if seen(&last.0) != Seen::ItemFailed {
            break;
        }
        last = run(*ADMITTED + ABORTS_AT_ITEM);
    }
    last
}
const ATTEMPTS: usize = 5;

fn fields(line: &str) -> std::collections::BTreeMap<&str, &str> {
    line.split(' ')
        .skip(3)
        .map(|pair| pair.split_once('=').expect("key=value"))
        .collect()
}

/// RED before the change: the server wrote nothing, so the operator saw a lost response
/// and no cause.
#[test]
fn an_aborted_stream_is_logged_with_its_typed_cause() {
    let (response, stderr) = aborted_at_item();
    assert_eq!(seen(&response), Seen::Aborted, "{response:?}");
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "exactly one line per aborted stream: {stderr:?}"
    );
    let line = lines[0];
    assert!(line.starts_with("oncl-server: stream aborted: "), "{line}");
    let fields = fields(line);
    assert_eq!(fields["route"], "batch", "{line}");
    assert_eq!(fields["item"], "0", "{line}");
    assert_eq!(fields["kind"], "hash", "{line}");
    assert_eq!(fields["code"], "metadata_limit", "{line}");
    assert_eq!(fields["cause"], "MetadataLimit", "{line}");
    assert_eq!(fields["applied"], "not_applied", "{line}");
    for numeric in ["operation", "elapsed_ms", "bytes_in", "bytes_out"] {
        fields[numeric]
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("{numeric} is not a number: {line}"));
    }
    assert_eq!(
        fields.len(),
        10,
        "no field beyond the documented ones: {line}"
    );
}

/// The line is built from numbers and closed names only: whatever the request carried
/// (item id, part name, file name, document text, the bearer token, the operator's paths)
/// never reaches the log.
#[test]
fn the_abort_log_line_carries_no_user_data() {
    let (response, stderr) = run(*ADMITTED + ALWAYS_ABORTS);
    assert_eq!(seen(&response), Seen::Aborted, "{response:?}");
    assert!(!stderr.is_empty(), "the abort must be logged at all");
    for canary in [
        ITEM,
        PART,
        FILE,
        "CANARY",
        "citizen",
        "900101300123",
        "contract",
        "synthetic-actor",
        "scratch",
        "audit",
        "127.0.0.1",
        env!("CARGO_TARGET_TMPDIR"),
    ] {
        assert!(
            !stderr.contains(canary),
            "{canary:?} leaked into {stderr:?}"
        );
    }
    assert!(
        stderr.trim_end().bytes().all(|b| b == b' '
            || b == b':'
            || b == b'-'
            || b == b'='
            || b == b'_'
            || b.is_ascii_alphanumeric()),
        "only closed names and numbers: {stderr:?}"
    );
}

/// A healthy stream writes nothing: the line is the abort's alone.
#[test]
fn a_completed_stream_logs_nothing() {
    let (response, stderr) = run(64 << 20);
    assert_eq!(seen(&response), Seen::Completed, "{response:?}");
    assert!(stderr.is_empty(), "{stderr:?}");
}
