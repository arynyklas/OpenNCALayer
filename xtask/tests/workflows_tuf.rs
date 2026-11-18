//! The rules for the secrets CI holds, the online TUF keys (`docs/dev/release.md`, section
//! 7g; `docs/design/publishers.md`, "Онлайн-снимок v2"), checked on the workflow files as they
//! are, and shown to catch what they claim to: the negative tests below break a copy of
//! `pages.yml` (or add a workflow) in each way a mistake or an attack would, and each must be
//! found.
//!
//! The secrets: `TUF_TIMESTAMP_KEY` and `TUF_V2_TIMESTAMP_KEY` in the environment
//! `tuf-timestamp` (job `timestamp`), `TUF_V2_SNAPSHOT_KEY` in `tuf-snapshot` (job
//! `snapshot`). The rules:
//!
//! - no workflow reads secrets wholesale (`toJSON(secrets)`, `secrets: inherit`, `secrets[`);
//! - the secrets and the environments are named in `pages.yml` only;
//! - `pages.yml` is not triggered by a pull request; each secret is read once, in the `env`
//!   of a step, of a job that runs in the secret's environment, only in this repository, only
//!   on `main`, only on events of the maintainers or the schedule (the `if` is parsed, not
//!   searched), with `contents: read` and nothing else; an environment is used by the jobs of
//!   its secrets only; every action in such a job is pinned by commit, none restores a cache
//!   or uploads an artifact; xtask is built by an earlier step; the steps with a secret are
//!   the last of the job, use no action and no `cargo`, and mask the key;
//! - `snapshot` runs before `timestamp`, but `tuf/v1` never depends on it: `timestamp` and
//!   `build` run whatever it did, and the v2 timestamp step cannot fail its job; `snapshot`
//!   starts from nothing (`--first-publication`) only when no timestamp is published (HTTP
//!   404) and the owner's variable `TUF_V2_FIRST_PUBLICATION` says so;
//! - `tuf/v2` is published, checked by the oracle and verified after the deployment only
//!   when `tuf/v2/metadata/1.root.json` is in the tree; the step that publishes `tuf/v1` does
//!   not touch `tuf/v2`; when `tuf/v2` fails, `build` publishes the served copy again (verified
//!   by the client) or none, without failing, and `tuf-v2-status` makes the run red after the
//!   deployment;
//! - only the `deploy` job may write Pages.
//!
//! `pages.yml` is read by a small parser of the block-style YAML the workflows are written in
//! (a YAML parser is not a dependency of `xtask`): it fails on what it does not understand
//! (flow mappings, anchors, tags, continuation lines), so a workflow written so that this
//! test cannot read it fails the test instead of passing it.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use serde_json::{Map, Value};

/// The secrets CI holds, each with its environment and the job that reads it.
const SECRETS: [(&str, &str, &str); 3] = [
    ("TUF_TIMESTAMP_KEY", "tuf-timestamp", "timestamp"),
    ("TUF_V2_TIMESTAMP_KEY", "tuf-timestamp", "timestamp"),
    ("TUF_V2_SNAPSHOT_KEY", "tuf-snapshot", "snapshot"),
];
const ENVIRONMENTS: [&str; 2] = ["tuf-timestamp", "tuf-snapshot"];
const PAGES: &str = "pages.yml";
const REPOSITORY: &str = "arynyklas/OpenNCALayer";
/// The events the jobs with a secret may run on: started by the maintainers or the schedule,
/// never by a pull request. `repository_dispatch` (the upstream watcher) is there because
/// `build` does not run without the timestamp they make.
const EVENTS: [&str; 5] = [
    "push",
    "schedule",
    "workflow_run",
    "workflow_dispatch",
    "repository_dispatch",
];
/// The part a condition may have besides the three gates: it only lets `timestamp` run
/// whatever `snapshot` did (`tuf/v1` never waits on `tuf/v2`), never on another ref,
/// repository or event.
const ALLOWED_EXTRA: [&str; 1] = ["!cancelled()"];

// ---- a parser for the block-style YAML of the workflows ----

struct Parser {
    lines: Vec<String>,
    i: usize,
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

impl Parser {
    fn blank(line: &str) -> bool {
        let t = line.trim();
        t.is_empty() || t.starts_with('#')
    }

    /// The next line with content: its indentation and text.
    fn peek(&mut self) -> Result<Option<(usize, String)>, String> {
        while self.i < self.lines.len() && Parser::blank(&self.lines[self.i]) {
            self.i += 1;
        }
        let Some(line) = self.lines.get(self.i) else {
            return Ok(None);
        };
        if line.trim_start_matches(' ').starts_with('\t') {
            return Err(format!("line {}: a tab in the indentation", self.i + 1));
        }
        Ok(Some((indent_of(line), line.trim().to_owned())))
    }

    fn block(&mut self, indent: usize) -> Result<Value, String> {
        let Some((n, text)) = self.peek()? else {
            return Ok(Value::Null);
        };
        if n != indent {
            return Err(format!("line {}: unexpected indentation", self.i + 1));
        }
        if text == "-" || text.starts_with("- ") {
            self.sequence(indent)
        } else if split_key(&text)?.is_some() {
            self.mapping(indent)
        } else {
            self.i += 1;
            scalar(&text)
        }
    }

    fn sequence(&mut self, n: usize) -> Result<Value, String> {
        let mut items = Vec::new();
        while let Some((ind, text)) = self.peek()? {
            if ind != n || !(text == "-" || text.starts_with("- ")) {
                break;
            }
            let rest = text[1..].trim_start();
            if rest.is_empty() {
                self.i += 1;
                items.push(match self.peek()? {
                    Some((next, _)) if next > n => self.block(next)?,
                    _ => Value::Null,
                });
            } else {
                // The item's first line is the rest of this one, further in.
                let at = n + (text.len() - rest.len());
                self.lines[self.i] = format!("{}{rest}", " ".repeat(at));
                items.push(self.block(at)?);
            }
        }
        Ok(Value::Array(items))
    }

    fn mapping(&mut self, n: usize) -> Result<Value, String> {
        let mut map = Map::new();
        while let Some((ind, text)) = self.peek()? {
            if ind < n || (ind == n && (text == "-" || text.starts_with("- "))) {
                break;
            }
            if ind > n {
                return Err(format!(
                    "line {}: unexpected indentation (a continued scalar?)",
                    self.i + 1
                ));
            }
            let Some((key, rest)) = split_key(&text)? else {
                return Err(format!("line {}: not a `key: value` line", self.i + 1));
            };
            self.i += 1;
            let value = if rest.is_empty() {
                match self.peek()? {
                    Some((next, _)) if next > n => self.block(next)?,
                    Some((next, text)) if next == n && (text == "-" || text.starts_with("- ")) => {
                        self.sequence(n)?
                    }
                    _ => Value::Null,
                }
            } else if rest.starts_with('|') || rest.starts_with('>') {
                self.block_scalar(n, &rest)?
            } else {
                scalar(&rest)?
            };
            if map.insert(key.clone(), value).is_some() {
                return Err(format!("the key {key:?} is twice in a mapping"));
            }
        }
        Ok(Value::Object(map))
    }

    fn block_scalar(&mut self, n: usize, header: &str) -> Result<Value, String> {
        let folded = header.starts_with('>');
        let mut body: Vec<String> = Vec::new();
        while let Some(line) = self.lines.get(self.i) {
            if !line.trim().is_empty() && indent_of(line) <= n {
                break;
            }
            body.push(line.clone());
            self.i += 1;
        }
        let strip = body
            .iter()
            .filter(|l| !l.trim().is_empty())
            .map(|l| indent_of(l))
            .min()
            .unwrap_or(0);
        let lines: Vec<&str> = body
            .iter()
            .map(|l| {
                if l.len() >= strip {
                    l[strip..].trim_end()
                } else {
                    ""
                }
            })
            .collect();
        let mut text = if folded {
            let mut out = String::new();
            for (k, line) in lines.iter().enumerate() {
                if k > 0 {
                    let blank = line.is_empty() || lines[k - 1].is_empty();
                    out.push(if blank { '\n' } else { ' ' });
                    if line.is_empty() && lines[k - 1].is_empty() {
                        continue;
                    }
                }
                out.push_str(line);
            }
            out
        } else {
            lines.join("\n")
        };
        text = text.trim_end_matches('\n').to_owned();
        if !header.contains('-') {
            text.push('\n');
        }
        Ok(Value::String(text))
    }
}

/// `key: rest` of a mapping line, or `None` if the line is not one.
fn split_key(text: &str) -> Result<Option<(String, String)>, String> {
    if let Some(quoted) = text.strip_prefix('"') {
        let Some(end) = quoted.find('"') else {
            return Err(format!("an unterminated key in {text:?}"));
        };
        let rest = quoted[end + 1..].strip_prefix(':').map(str::trim);
        return Ok(rest.map(|r| (quoted[..end].to_owned(), r.to_owned())));
    }
    let at = if text.ends_with(':') && !text[..text.len() - 1].contains(": ") {
        Some(text.len() - 1)
    } else {
        text.find(": ")
    };
    Ok(at.map(|at| {
        (
            text[..at].trim().to_owned(),
            text[at + 1..].trim().to_owned(),
        )
    }))
}

/// A one-line value, comments removed; what the parser does not read is an error.
fn scalar(text: &str) -> Result<Value, String> {
    let text = strip_comment(text);
    let text = text.trim();
    let Some(first) = text.chars().next() else {
        return Ok(Value::Null);
    };
    match first {
        '"' => {
            let inner = text
                .strip_prefix('"')
                .and_then(|t| t.strip_suffix('"'))
                .ok_or_else(|| format!("a quoted scalar that does not end: {text:?}"))?;
            Ok(Value::String(
                inner
                    .replace("\\\"", "\"")
                    .replace("\\\\", "\\")
                    .replace("\\n", "\n"),
            ))
        }
        '\'' => {
            let inner = text
                .strip_prefix('\'')
                .and_then(|t| t.strip_suffix('\''))
                .ok_or_else(|| format!("a quoted scalar that does not end: {text:?}"))?;
            Ok(Value::String(inner.replace("''", "'")))
        }
        '[' => {
            let inner = text
                .strip_prefix('[')
                .and_then(|t| t.strip_suffix(']'))
                .ok_or_else(|| format!("a flow sequence that does not end: {text:?}"))?;
            if inner.contains(['[', '{']) {
                return Err(format!("a nested flow collection: {text:?}"));
            }
            let mut items = Vec::new();
            for item in inner.split(',').map(str::trim).filter(|i| !i.is_empty()) {
                items.push(scalar(item)?);
            }
            Ok(Value::Array(items))
        }
        '{' | '&' | '*' | '!' | '?' | '%' | '@' | '`' => {
            Err(format!("YAML this test does not read: {text:?}"))
        }
        _ => Ok(Value::String(text.to_owned())),
    }
}

fn strip_comment(text: &str) -> &str {
    let mut quote = None;
    let bytes = text.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match (quote, b) {
            (None, b'"' | b'\'') => quote = Some(b),
            (Some(q), c) if c == q => quote = None,
            (None, b'#') if i == 0 || bytes[i - 1] == b' ' => return &text[..i],
            _ => {}
        }
    }
    text
}

fn parse_yaml(text: &str) -> Result<Value, String> {
    let mut parser = Parser {
        lines: text
            .lines()
            .map(|l| l.trim_end_matches('\r').to_owned())
            .collect(),
        i: 0,
    };
    if parser.peek()?.is_some_and(|(_, t)| t == "---") {
        return Err("a document marker".to_owned());
    }
    let value = parser.block(0)?;
    match parser.peek()? {
        None => Ok(value),
        Some(_) => Err(format!("line {}: text after the document", parser.i + 1)),
    }
}

// ---- the rules ----

/// The parts of `expr` between `op` at the top level (outside parentheses and quotes).
fn split_top<'a>(expr: &'a str, op: &str) -> Vec<&'a str> {
    let (mut parts, mut depth, mut quote, mut start) = (Vec::new(), 0usize, false, 0usize);
    let bytes = expr.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' => quote = !quote,
            b'(' if !quote => depth += 1,
            b')' if !quote => depth = depth.saturating_sub(1),
            _ if !quote && depth == 0 && expr[i..].starts_with(op) => {
                parts.push(&expr[start..i]);
                i += op.len();
                start = i;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    parts.push(&expr[start..]);
    parts
}

/// Whether `text` is one parenthesized group, not `(a) || (b)`.
fn whole_group(text: &str) -> bool {
    if !(text.starts_with('(') && text.ends_with(')')) {
        return false;
    }
    let mut depth = 0usize;
    let mut quote = false;
    for (i, b) in text.bytes().enumerate() {
        match b {
            b'\'' => quote = !quote,
            b'(' if !quote => depth += 1,
            b')' if !quote => {
                depth -= 1;
                if depth == 0 && i != text.len() - 1 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0
}

/// `github.ref == main && github.repository == ours && (event == a || event == b …)`, and
/// nothing else but [`ALLOWED_EXTRA`].
fn check_condition(raw: &str) -> Result<(), String> {
    let text = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let text = text
        .strip_prefix("${{")
        .and_then(|t| t.strip_suffix("}}"))
        .map_or(text.as_str(), str::trim);
    let conjuncts = split_top(text, "&&");
    let (mut main, mut repository, mut events) = (0, 0, 0);
    for part in conjuncts.iter().map(|p| p.trim()) {
        if ALLOWED_EXTRA.contains(&part) {
            continue;
        }
        if part == "github.ref == 'refs/heads/main'" {
            main += 1;
        } else if part == format!("github.repository == '{REPOSITORY}'") {
            repository += 1;
        } else if whole_group(part) {
            let alternatives = split_top(&part[1..part.len() - 1], "||");
            for alt in alternatives {
                let event = alt
                    .trim()
                    .strip_prefix("github.event_name == '")
                    .and_then(|a| a.strip_suffix('\''))
                    .ok_or_else(|| format!("not an event test: {}", alt.trim()))?;
                if !EVENTS.contains(&event) {
                    return Err(format!("the event {event} is not one the job may run on"));
                }
            }
            events += 1;
        } else {
            return Err(format!("not an allowed part of the condition: {part}"));
        }
    }
    if (main, repository, events) == (1, 1, 1) {
        Ok(())
    } else {
        Err(format!(
            "the condition lacks main, the repository or the events: {text}"
        ))
    }
}

/// Every string of `value` with its path.
fn leaves(value: &Value, path: &mut Vec<String>, out: &mut Vec<(Vec<String>, String)>) {
    match value {
        Value::String(s) => out.push((path.clone(), s.clone())),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                path.push(i.to_string());
                leaves(item, path, out);
                path.pop();
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                path.push(k.clone());
                leaves(v, path, out);
                path.pop();
            }
        }
        _ => {}
    }
}

fn pinned(uses: &str) -> bool {
    uses.split('@')
        .nth(1)
        .and_then(|r| r.split_whitespace().next())
        .is_some_and(|r| r.len() == 40 && r.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The environment `job` runs in (`environment: x` or `environment: {name: x}`).
fn environment_of(job: &Value) -> Option<String> {
    match job.get("environment")? {
        Value::String(s) => Some(s.clone()),
        Value::Object(m) => Some(m.get("name").map_or_else(String::new, Value::to_string)),
        other => Some(other.to_string()),
    }
}

/// Every string inside `value`, joined.
fn all_text(value: &Value) -> String {
    let mut inside = Vec::new();
    leaves(value, &mut Vec::new(), &mut inside);
    inside
        .into_iter()
        .map(|(_, v)| v)
        .collect::<Vec<_>>()
        .join("\n")
}

/// The rules of one job that reads secrets: `job_id` with the steps `secret_steps` reading
/// them.
fn check_secret_job(
    job_id: &str,
    job: &Value,
    secret_steps: &BTreeSet<usize>,
    bad: &mut Vec<String>,
) {
    match job.get("if").and_then(Value::as_str) {
        Some(condition) => {
            if let Err(e) = check_condition(condition) {
                bad.push(format!("{job_id}: {e}"));
            }
        }
        None => bad.push(format!("the job {job_id} has no `if`")),
    }
    if job.get("permissions") != Some(&serde_json::json!({"contents": "read"})) {
        bad.push(format!(
            "the job {job_id}'s permissions are not exactly `contents: read`"
        ));
    }
    if job.get("env").is_some() {
        bad.push(format!("the job {job_id} has an env of its own"));
    }
    let Some(steps) = job.get("steps").and_then(Value::as_array) else {
        bad.push(format!("the job {job_id} has no steps"));
        return;
    };
    for step in steps {
        if let Some(uses) = step.get("uses").and_then(Value::as_str) {
            if !pinned(uses) {
                bad.push(format!(
                    "an action in the secret's job {job_id} is not pinned by commit: {uses}"
                ));
            }
            if uses.contains("upload-artifact") {
                bad.push(format!("the secret's job {job_id} uploads an artifact"));
            }
            if uses.contains("cache") {
                bad.push(format!(
                    "the secret's job {job_id} restores a cache: {uses}"
                ));
            }
            if uses.starts_with("actions/checkout@")
                && step
                    .get("with")
                    .and_then(|w| w.get("persist-credentials"))
                    .and_then(Value::as_str)
                    != Some("false")
            {
                bad.push(format!(
                    "the checkout of the secret's job {job_id} keeps its credentials"
                ));
            }
        }
    }
    let Some(&first) = secret_steps.iter().next() else {
        return;
    };
    if (first..steps.len()).any(|i| !secret_steps.contains(&i)) {
        bad.push(format!(
            "a step with a secret is not the last of its job {job_id}"
        ));
    }
    let built = steps[..first].iter().any(|s| {
        s.get("run")
            .and_then(Value::as_str)
            .is_some_and(|r| r.contains("cargo build -p xtask"))
    });
    if !built {
        bad.push(format!(
            "the job {job_id} does not build xtask before the secret"
        ));
    }
    for &i in secret_steps {
        let step = &steps[i];
        if step.get("uses").is_some() {
            bad.push(format!("a step with a secret in {job_id} is an action"));
        }
        let run = step.get("run").and_then(Value::as_str).unwrap_or("");
        if !run.contains("::add-mask::$") {
            bad.push(format!("a step with a secret in {job_id} does not mask it"));
        }
        if run.contains("cargo ") {
            bad.push(format!(
                "a step with a secret in {job_id} runs cargo (builds next to the key)"
            ));
        }
    }
}

/// What is wrong with `pages_yml` (the text of `pages.yml`).
fn check_pages(text: &str) -> Vec<String> {
    let mut bad = Vec::new();
    let doc = match parse_yaml(text) {
        Ok(doc) => doc,
        Err(e) => return vec![format!("pages.yml cannot be read by this test: {e}")],
    };
    // Triggers.
    let on = doc.get("on").cloned().unwrap_or(Value::Null);
    let triggers: Vec<String> = match &on {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        Value::Object(m) => m.keys().cloned().collect(),
        _ => Vec::new(),
    };
    if triggers.is_empty() {
        bad.push("pages.yml has no triggers".to_owned());
    }
    if triggers.iter().any(|t| t.starts_with("pull_request")) {
        bad.push("pages.yml is triggered by a pull request".to_owned());
    }
    let Some(jobs) = doc.get("jobs").and_then(Value::as_object) else {
        bad.push("pages.yml has no jobs".to_owned());
        return bad;
    };
    // Where each secret is read.
    let mut all = Vec::new();
    leaves(&doc, &mut Vec::new(), &mut all);
    let mut secret_steps: std::collections::BTreeMap<String, BTreeSet<usize>> =
        std::collections::BTreeMap::new();
    for (secret, environment, owner) in SECRETS {
        let reads: Vec<&(Vec<String>, String)> = all
            .iter()
            .filter(|(_, v)| {
                v.to_lowercase()
                    .contains(&format!("secrets.{}", secret.to_lowercase()))
            })
            .collect();
        if reads.len() != 1 {
            bad.push(format!(
                "the secret {secret} is read {} times, not once",
                reads.len()
            ));
            continue;
        }
        let (path, value) = reads[0];
        let shape = path.len() == 6
            && path[0] == "jobs"
            && path[2] == "steps"
            && path[3].parse::<usize>().is_ok()
            && path[4] == "env"
            && path[5] == secret;
        if !shape || *value != format!("${{{{ secrets.{secret} }}}}") {
            bad.push(format!(
                "the secret {secret} is read at {}, not in the env of a step",
                path.join(".")
            ));
            continue;
        }
        if path[1] != owner {
            bad.push(format!(
                "the secret {secret} is read in the job {}, not {owner}",
                path[1]
            ));
        }
        if environment_of(&jobs[&path[1]]).as_deref() != Some(environment) {
            bad.push(format!(
                "the job {} reads {secret} outside the environment {environment}",
                path[1]
            ));
        }
        if let Ok(step) = path[3].parse::<usize>() {
            let run = jobs[&path[1]]["steps"][step]
                .get("run")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !run.contains(&format!("echo \"::add-mask::${secret}\"")) {
                bad.push(format!(
                    "the step with {secret} does not mask that variable"
                ));
            }
            secret_steps
                .entry(path[1].clone())
                .or_default()
                .insert(step);
        }
    }
    // One address of the site, at the top: no other place names the Pages host.
    let pages_url = doc
        .get("env")
        .and_then(|e| e.get("PAGES_URL"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if !(pages_url.starts_with("https://") && pages_url.ends_with('/')) {
        bad.push("pages.yml has no workflow-level PAGES_URL".to_owned());
    }
    if all
        .iter()
        .any(|(p, v)| v.contains("github.io") && p.as_slice() != ["env", "PAGES_URL"])
    {
        bad.push("pages.yml names the Pages host outside PAGES_URL".to_owned());
    }
    // Each environment is used by the jobs of its secrets only.
    for (id, job) in jobs {
        if let Some(env) = environment_of(job) {
            for environment in ENVIRONMENTS {
                let owns = SECRETS.iter().any(|(_, e, o)| *e == environment && o == id);
                if env.contains(environment) && !owns {
                    bad.push(format!(
                        "the environment {environment} is used by the job {id}, which holds none of its secrets"
                    ));
                }
            }
        }
        if job.get("secrets").is_some() {
            bad.push(format!("the job {id} passes secrets to a workflow"));
        }
    }
    for (job_id, steps) in &secret_steps {
        check_secret_job(job_id, &jobs[job_id], steps, &mut bad);
    }
    // The graph of jobs: nothing is deployed unless `snapshot` and `timestamp` did not fail
    // and the oracle did not fail; the oracle has no secret, no environment and writes no
    // artifact.
    let list = |v: Option<&Value>| -> Vec<String> {
        match v {
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|x| x.as_str().map(str::to_owned))
                .collect(),
            _ => Vec::new(),
        }
    };
    let text = |job: &str, key: &str| {
        jobs.get(job)
            .and_then(|j| j.get(key))
            .and_then(Value::as_str)
            .unwrap_or("")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };
    let needs = |job: &str| list(jobs.get(job).and_then(|j| j.get("needs")));
    if !needs("timestamp").contains(&"snapshot".to_owned()) {
        bad.push("timestamp does not need the snapshot job".to_owned());
    }
    // `tuf/v1` never depends on `tuf/v2`: neither `timestamp` nor `build` waits on the
    // success of `snapshot`, and the v2 timestamp step cannot fail its job.
    for job in ["timestamp", "build"] {
        if text(job, "if").contains("needs.snapshot.result") {
            bad.push(format!(
                "{job} waits on the snapshot job: tuf/v1 would depend on tuf/v2"
            ));
        }
    }
    if !text("timestamp", "if").contains("!cancelled()") {
        bad.push("timestamp does not run when the snapshot job failed".to_owned());
    }
    for id in ["unpack", "sign_v2"] {
        if step_with_id(jobs.get("timestamp"), id)
            .and_then(|s| s.get("continue-on-error"))
            .and_then(Value::as_str)
            != Some("true")
        {
            bad.push(format!(
                "the v2 timestamp step {id} can fail the timestamp job of tuf/v1"
            ));
        }
    }
    for needed in ["snapshot", "timestamp"] {
        if !needs("build").contains(&needed.to_owned()) {
            bad.push(format!("build does not need the {needed} job"));
        }
    }
    if !text("build", "if").contains("needs.timestamp.result != 'failure'") {
        bad.push("build runs although the timestamp job failed".to_owned());
    }
    let deploy_needs = needs("deploy");
    for needed in ["build", "oracle"] {
        if !deploy_needs.contains(&needed.to_owned()) {
            bad.push(format!("deploy does not need {needed}"));
        }
    }
    let deploy_if = text("deploy", "if");
    for part in [
        "needs.build.result == 'success'",
        "contains(fromJSON('[\"success\",\"skipped\"]'), needs.oracle.result)",
    ] {
        if !deploy_if.contains(part) {
            bad.push(format!("the condition of deploy lacks {part}"));
        }
    }
    match jobs.get("oracle") {
        None => bad.push("there is no oracle job".to_owned()),
        Some(oracle) => {
            if oracle.get("secrets").is_some() || oracle.get("environment").is_some() {
                bad.push("the oracle job has secrets or an environment".to_owned());
            }
            if oracle.get("permissions") != Some(&serde_json::json!({"contents": "read"})) {
                bad.push(
                    "the oracle job's permissions are not exactly `contents: read`".to_owned(),
                );
            }
            let inside = all_text(oracle);
            if inside.to_lowercase().contains("secrets.") || inside.contains("upload-") {
                bad.push("the oracle job reads secrets or uploads an artifact".to_owned());
            }
        }
    }
    check_v2_publication(jobs, &mut bad);
    // Writing Pages: the deploy job only.
    let writes = |permissions: Option<&Value>| {
        permissions.and_then(Value::as_object).is_some_and(|p| {
            p.get("pages").is_some_and(|v| v == "write")
                || p.get("id-token").is_some_and(|v| v == "write")
        })
    };
    if writes(doc.get("permissions")) {
        bad.push("the workflow's permissions write Pages".to_owned());
    }
    for (id, other) in jobs {
        if id != "deploy" && writes(other.get("permissions")) {
            bad.push(format!("the job {id} may write Pages"));
        }
    }
    bad
}

/// The step of `job` with the id `id`.
fn step_with_id<'a>(job: Option<&'a Value>, id: &str) -> Option<&'a Value> {
    job?.get("steps")?
        .as_array()?
        .iter()
        .find(|s| s.get("id").and_then(Value::as_str) == Some(id))
}

fn field<'a>(step: Option<&'a Value>, key: &str) -> &'a str {
    step.and_then(|s| s.get(key))
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// The text of `text` after the first `start` and before the next `end`.
fn between<'a>(text: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let rest = text.split_once(start)?.1;
    Some(rest.split_once(end)?.0)
}

/// The lines of the shell function `name() { … }` in `run`, trimmed, without comments.
fn function_lines<'a>(run: &'a str, name: &str) -> Option<Vec<&'a str>> {
    let body = run.split_once(&format!("\n{name}() {{\n"))?.1;
    let body = body.split_once("\n}\n")?.0;
    Some(
        body.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect(),
    )
}

/// Every command of the function stops it on failure: it ends with `|| return 1`, or is
/// the shell's own structure (`case … in`, a branch ending in `;;`, `esac`, a loop).
fn returns_on_failure(lines: &[&str]) -> bool {
    lines.iter().all(|l| {
        l.ends_with("|| return 1")
            || l.ends_with(";;")
            || l.ends_with(";; esac")
            || (l.starts_with("case ") && l.ends_with(" in"))
            || *l == "esac"
            || (l.starts_with("while ") && l.ends_with("; do"))
            || l.starts_with("done")
    }) && lines.iter().all(|l| !l.contains("|| true"))
}

/// The publication of `tuf/v2` in `build` (`publish`, the run of the step): the new
/// `tuf/v2` (`signed`) or the served one (`served`), each function returning on every
/// failure, the served one verified by the client and checked as a publication; the
/// branches: `signed` and `republished` go on, the last one fails `build`.
fn fallback_is_sound(publish: &str) -> bool {
    let (Some(signed), Some(served)) = (
        function_lines(publish, "signed"),
        function_lines(publish, "served"),
    ) else {
        return false;
    };
    let checked = |lines: &[&str], what: &str| {
        lines
            .iter()
            .any(|l| l.starts_with(what) && l.ends_with("|| return 1"))
    };
    let functions = returns_on_failure(&signed)
        && returns_on_failure(&served)
        && checked(&signed, "bash .github/scripts/tuf-v2-snapshots.sh unpack ")
        && checked(&signed, "cargo xtask tuf check ")
        && checked(&served, "cargo xtask tuf verify-published --repo v2 --dir ")
        && served.iter().any(|l| {
            l.starts_with("cargo xtask tuf check ")
                && l.contains("--served-v2")
                && l.contains("--fail-on-expiring")
                && l.ends_with("|| return 1")
        });
    let Some(branches) = publish.split_once("\nif signed ").map(|(_, b)| b) else {
        return false;
    };
    let Some((new, rest)) = branches.split_once("\nelif served ") else {
        return false;
    };
    let Some((again, rest)) = rest.split_once("\nelse\n") else {
        return false;
    };
    let Some((none, _)) = rest.split_once("\nfi") else {
        return false;
    };
    functions
        && new.contains("state=signed")
        && !new.contains("exit")
        && again.contains("state=republished")
        && !again.contains("exit")
        && none.contains("exit 1")
        && !none.contains("state=")
        && !publish.contains("|| true")
}

/// `tuf/v2`: the first publication only on HTTP 404 and the owner's variable; published,
/// checked and verified only when its root is in the tree; the `tuf/v1` step without it.
fn check_v2_publication(jobs: &Map<String, Value>, bad: &mut Vec<String>) {
    let snapshot = jobs.get("snapshot");
    let probe = step_with_id(snapshot, "published");
    let probe_env = probe.and_then(|s| s.get("env"));
    if probe_env
        .and_then(|e| e.get("FIRST"))
        .and_then(Value::as_str)
        != Some("${{ vars.TUF_V2_FIRST_PUBLICATION }}")
    {
        bad.push(
            "the probe of the published tuf/v2 does not read TUF_V2_FIRST_PUBLICATION".to_owned(),
        );
    }
    let probe_run = field(probe, "run");
    if !(probe_run.contains("404)") && probe_run.contains("[ \"$FIRST\" != true ]")) {
        bad.push(
            "the first publication of tuf/v2 is not limited to HTTP 404 with TUF_V2_FIRST_PUBLICATION=true"
                .to_owned(),
        );
    }
    if !between(probe_run, "*)", ";;").is_some_and(|branch| branch.contains("exit 1")) {
        bad.push("the probe does not fail on an answer other than 200 and 404".to_owned());
    }
    let sign = step_with_id(snapshot, "sign");
    if sign
        .and_then(|s| s.get("env"))
        .and_then(|e| e.get("MODE"))
        .and_then(Value::as_str)
        != Some("${{ steps.published.outputs.mode }}")
    {
        bad.push("the snapshot is not signed in the mode the probe decided".to_owned());
    }
    let sign_run = field(sign, "run");
    if !(sign_run.contains("tuf snapshot --out")
        && sign_run.contains("--previous \"${PAGES_URL}tuf/v2/\""))
    {
        bad.push("the snapshot does not extend the published one".to_owned());
    }
    // The snapshots between the jobs: packed by the script (gzip, the cap), unpacked by it
    // (the names allowed) in a step of `timestamp` without a key, before the keys.
    if !sign_run.contains("bash .github/scripts/tuf-v2-snapshots.sh pack ") {
        bad.push("the snapshots are not packed by tuf-v2-snapshots.sh".to_owned());
    }
    let timestamp = jobs.get("timestamp");
    let unpack = step_with_id(timestamp, "unpack");
    let unpack_plain = unpack.is_some_and(|s| {
        !all_text(s).to_lowercase().contains("secrets.")
            && field(Some(s), "run").contains("bash .github/scripts/tuf-v2-snapshots.sh unpack ")
    });
    let sign_v2 = step_with_id(timestamp, "sign_v2");
    let sign_v2_run = field(sign_v2, "run");
    if !(unpack_plain
        && field(sign_v2, "if") == "steps.unpack.outputs.ready == 'true'"
        && !sign_v2_run.contains("SNAPSHOTS")
        && !sign_v2_run.contains("tar ")
        && !sign_v2_run.contains("base64"))
    {
        bad.push(
            "the v2 snapshots are not unpacked by tuf-v2-snapshots.sh before the timestamp key"
                .to_owned(),
        );
    }
    for (id, other) in jobs {
        if id != "snapshot" && all_text(other).contains("--first-publication") {
            bad.push(format!("the job {id} signs a first publication of tuf/v2"));
        }
    }
    let build = jobs.get("build");
    if field(step_with_id(build, "tuf"), "run").contains("v2") {
        bad.push("the step that publishes tuf/v1 touches tuf/v2".to_owned());
    }
    let publish = field(step_with_id(build, "tuf_v2"), "run");
    if !publish.starts_with("if [ ! -f tuf/v2/metadata/1.root.json ]; then") {
        bad.push(
            "the publication of tuf/v2 is not gated on tuf/v2/metadata/1.root.json".to_owned(),
        );
    }
    // A v2 failure stops `tuf/v1` only when there is no `tuf/v2` at all to publish: the
    // served `tuf/v2` is published again after the checks (then the run goes red after the
    // deployment); without it `build` fails, so no site without `tuf/v2` is ever deployed
    // (the next `snapshot` would take its 404 for a first publication).
    if !fallback_is_sound(publish) {
        bad.push(
            "a failure of tuf/v2 does not fall back to the served tuf/v2, or deploys without it"
                .to_owned(),
        );
    }
    let status = jobs.get("tuf-v2-status");
    let status_if = status
        .and_then(|j| j.get("if"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let after_deploy = status
        .and_then(|j| j.get("needs"))
        .and_then(Value::as_array)
        .is_some_and(|n| n.iter().any(|x| x == "deploy"));
    let status_runs = status.is_some_and(|j| all_text(j).contains("exit 1"));
    if !(after_deploy
        && status_if.contains("needs.build.outputs.tuf_v2 == 'republished'")
        && status_runs)
    {
        bad.push("a tuf/v2 failure does not make the run red after the deployment".to_owned());
    }
    for (job, what, gate) in [
        (
            "oracle",
            "site/tuf/v2",
            "needs.build.outputs.tuf_v2 == 'signed'",
        ),
        (
            "verify",
            "--repo v2",
            "contains(fromJSON('[\"signed\",\"republished\"]'), needs.build.outputs.tuf_v2)",
        ),
    ] {
        let gated = jobs
            .get(job)
            .and_then(|j| j.get("steps"))
            .and_then(Value::as_array)
            .is_some_and(|steps| {
                steps
                    .iter()
                    .any(|s| field(Some(s), "run").contains(what) && field(Some(s), "if") == gate)
            });
        if !gated {
            bad.push(format!(
                "the job {job} does not check tuf/v2 when (and only when) it is published"
            ));
        }
    }
}

/// What is wrong with the workflows `(file name, text)`.
fn check_workflows(files: &[(String, String)]) -> Vec<String> {
    let mut bad = Vec::new();
    for (name, text) in files {
        let lower = text.to_lowercase();
        // Without white space: `toJSON( secrets )` and `secrets [` are the same thing.
        let compact: String = lower.split_whitespace().collect();
        for banned in ["tojson(secrets)", "secrets:inherit", "secrets["] {
            if compact.contains(banned) {
                bad.push(format!("{name} reads secrets wholesale ({banned})"));
            }
        }
        let named = SECRETS
            .iter()
            .any(|(s, _, _)| lower.contains(&s.to_lowercase()))
            || ENVIRONMENTS.iter().any(|e| lower.contains(e));
        if name != PAGES && named {
            bad.push(format!("{name} names a TUF secret or environment"));
        }
    }
    match files.iter().find(|(n, _)| n == PAGES) {
        Some((_, text)) => bad.extend(check_pages(text)),
        None => bad.push("there is no pages.yml".to_owned()),
    }
    bad
}

fn real_workflows() -> Vec<(String, String)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows");
    let mut files = Vec::new();
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "yml" || e == "yaml") {
            files.push((
                path.file_name().unwrap().to_string_lossy().into_owned(),
                // A Windows checkout may have CRLF line ends: the mutations are written with LF.
                fs::read_to_string(&path).unwrap().replace("\r\n", "\n"),
            ));
        }
    }
    assert!(
        files.len() > 5,
        "the workflows were not found in {}",
        dir.display()
    );
    files
}

#[test]
fn the_workflows_keep_the_rules_for_the_online_secrets() {
    let bad = check_workflows(&real_workflows());
    assert!(bad.is_empty(), "{bad:#?}");
}

/// The real workflows with `pages.yml` changed by replacing `from` with `to` (which must be
/// there) and `extra` files added.
fn mutated(from: &str, to: &str, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut files = real_workflows();
    for (name, text) in &mut files {
        if name == PAGES && !from.is_empty() {
            assert!(text.contains(from), "the mutation target is gone: {from:?}");
            *text = text.replacen(from, to, 1);
        }
    }
    files.extend(
        extra
            .iter()
            .map(|(n, t)| ((*n).to_owned(), (*t).to_owned())),
    );
    files
}

fn assert_found(files: Vec<(String, String)>, needle: &str) {
    let bad = check_workflows(&files);
    assert!(
        bad.iter().any(|b| b.contains(needle)),
        "not caught ({needle:?}): {bad:#?}"
    );
}

#[test]
fn a_pull_request_trigger_is_found() {
    assert_found(
        mutated("on:\n  push:", "on:\n  pull_request:\n  push:", &[]),
        "pull request",
    );
}

#[test]
fn a_condition_with_another_event_or_without_main_is_found() {
    assert_found(
        mutated(
            "github.event_name == 'repository_dispatch')",
            "github.event_name == 'repository_dispatch') || github.event_name == 'release'",
            &[],
        ),
        "condition",
    );
    assert_found(
        mutated(
            "github.event_name == 'push' ||",
            "github.event_name == 'pull_request' ||",
            &[],
        ),
        "not one the job may run on",
    );
    assert_found(
        mutated("      github.ref == 'refs/heads/main' &&\n", "", &[]),
        "condition",
    );
    assert_found(
        mutated(
            "      github.repository == 'arynyklas/OpenNCALayer' && (\n",
            "      (\n",
            &[],
        ),
        "condition",
    );
}

#[test]
fn the_secret_outside_one_step_env_is_found() {
    assert_found(
        mutated(
            "    environment: tuf-timestamp\n",
            "    environment: tuf-timestamp\n    env:\n      TUF_TIMESTAMP_KEY: ${{ secrets.TUF_TIMESTAMP_KEY }}\n",
            &[],
        ),
        "times, not once",
    );
    assert_found(
        mutated(
            "env:\n  CARGO_TERM_COLOR: always\n",
            "env:\n  CARGO_TERM_COLOR: always\n  TUF_TIMESTAMP_KEY: ${{ secrets.TUF_TIMESTAMP_KEY }}\n",
            &[],
        ),
        "times, not once",
    );
}

#[test]
fn the_secret_or_the_environment_in_another_workflow_is_found() {
    let other = "name: x\non:\n  pull_request:\njobs:\n  a:\n    environment: tuf-timestamp\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo ${{ secrets.TUF_TIMESTAMP_KEY }}\n";
    assert_found(mutated("", "", &[("evil.yml", other)]), "evil.yml names");
    // The `.yaml` extension is a workflow too, and a copy of pages.yml is another file.
    assert_found(mutated("", "", &[("evil.yaml", other)]), "evil.yaml names");
    let copy = real_workflows()
        .into_iter()
        .find(|(n, _)| n == PAGES)
        .unwrap()
        .1;
    assert_found(
        mutated("", "", &[("pages.yaml", &copy)]),
        "pages.yaml names",
    );
    assert_found(
        mutated(
            "",
            "",
            &[("all.yml", "name: x\njobs:\n  a:\n    secrets: inherit\n")],
        ),
        "wholesale",
    );
    assert_found(
        mutated(
            "",
            "",
            &[("all.yml", "name: x\nenv:\n  A: ${{ toJSON(secrets) }}\n")],
        ),
        "wholesale",
    );
    assert_found(
        mutated(
            "",
            "",
            &[("all.yml", "name: x\nenv:\n  A: ${{ secrets['X'] }}\n")],
        ),
        "wholesale",
    );
}

#[test]
fn an_unpinned_action_a_later_step_or_a_write_permission_in_the_secret_job_is_found() {
    assert_found(
        mutated(
            "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5",
            "actions/checkout@v5",
            &[],
        ),
        "not pinned by commit",
    );
    assert_found(
        mutated(
            "    environment: tuf-timestamp\n    permissions:\n      contents: read\n",
            "    environment: tuf-timestamp\n    permissions:\n      contents: read\n      pages: write\n",
            &[],
        ),
        "permissions are not exactly",
    );
    assert_found(
        mutated(
            "          } >> \"$GITHUB_OUTPUT\"\n\n  dispatch:",
            "          } >> \"$GITHUB_OUTPUT\"\n      - uses: actions/upload-artifact@v5\n        with:\n          path: x\n\n  dispatch:",
            &[],
        ),
        "not the last",
    );
    assert_found(
        mutated(
            "          echo \"::add-mask::$TUF_TIMESTAMP_KEY\"\n",
            "",
            &[],
        ),
        "does not mask",
    );
    assert_found(
        mutated("    environment: tuf-timestamp\n", "", &[]),
        "environment",
    );
}

#[test]
fn only_the_deploy_job_may_write_pages() {
    assert_found(
        mutated(
            "    timeout-minutes: 15\n    permissions:\n      contents: read\n    steps:\n      - uses: actions/checkout@v5\n        with:\n          persist-credentials: false\n      - uses: actions/download-artifact@v5",
            "    timeout-minutes: 15\n    permissions:\n      contents: read\n      id-token: write\n    steps:\n      - uses: actions/checkout@v5\n        with:\n          persist-credentials: false\n      - uses: actions/download-artifact@v5",
            &[],
        ),
        "may write Pages",
    );
}

#[test]
fn what_the_parser_does_not_read_is_an_error_and_not_a_pass() {
    for yaml in [
        "a: {b: c}\n",
        "a: &x 1\n",
        "a: !tag b\n",
        "a: b\n  continued\n",
        "---\na: b\n",
        "a: 1\na: 2\n",
    ] {
        assert!(parse_yaml(yaml).is_err(), "{yaml:?}");
    }
    let doc =
        parse_yaml("a:\n  - b: 1  # c\n    d: [e, \"f g\"]\n  - x\nh: >-\n  one\n  two\n").unwrap();
    assert_eq!(doc["a"][0]["b"], "1");
    assert_eq!(doc["a"][0]["d"], serde_json::json!(["e", "f g"]));
    assert_eq!(doc["a"][1], "x");
    assert_eq!(doc["h"], "one two");
    // A workflow the parser cannot read fails the rules.
    assert_found(
        mutated("name: Pages\n", "name: Pages\nanchor: &a 1\n", &[]),
        "cannot be read",
    );
    // A set of conditions the checker has to take apart correctly.
    let keep: BTreeSet<&str> = EVENTS.into_iter().collect();
    assert_eq!(keep.len(), 5);
    assert!(check_condition("github.ref == 'refs/heads/main' && github.repository == 'arynyklas/OpenNCALayer' && (github.event_name == 'push')").is_ok());
    assert!(check_condition("github.ref == 'refs/heads/main' && github.repository == 'arynyklas/OpenNCALayer' && (github.event_name == 'push') || (github.event_name == 'release')").is_err());
    assert!(check_condition("github.event_name == 'release' || github.ref == 'refs/heads/main' && github.repository == 'arynyklas/OpenNCALayer' && (github.event_name == 'push')").is_err());
}

#[test]
fn the_graph_of_jobs_is_pinned() {
    assert_found(
        mutated(
            "    needs: [snapshot, timestamp]\n",
            "    needs: [snapshot]\n",
            &[],
        ),
        "build does not need the timestamp job",
    );
    assert_found(
        mutated(
            "    needs: [snapshot, timestamp]\n",
            "    needs: [timestamp]\n",
            &[],
        ),
        "build does not need the snapshot job",
    );
    assert_found(
        mutated(
            "needs.timestamp.result != 'failure' && github",
            "needs.snapshot.result != 'failure' && needs.timestamp.result != 'failure' && github",
            &[],
        ),
        "build waits on the snapshot job",
    );
    assert_found(
        mutated("  timestamp:\n    needs: snapshot\n", "  timestamp:\n", &[]),
        "timestamp does not need the snapshot job",
    );
    assert_found(
        mutated("      !cancelled()\n", "      success()\n", &[]),
        "timestamp does not run when the snapshot job failed",
    );
    assert_found(
        mutated(
            "      !cancelled()\n",
            "      !cancelled() && needs.snapshot.result != 'failure'\n",
            &[],
        ),
        "timestamp waits on the snapshot job",
    );
    assert_found(
        mutated("        continue-on-error: true\n", "", &[]),
        "can fail the timestamp job of tuf/v1",
    );
    assert_found(
        mutated(
            "            echo \"state=republished\" >> \"$GITHUB_OUTPUT\"\n",
            "            echo \"state=republished\" >> \"$GITHUB_OUTPUT\"\n            exit 1\n",
            &[],
        ),
        "does not fall back to the served tuf/v2",
    );
    assert_found(
        mutated(
            "            cargo xtask tuf verify-published --repo v2 --dir \"$1\" || return 1\n",
            "            true\n",
            &[],
        ),
        "does not fall back to the served tuf/v2",
    );
    assert_found(
        mutated(
            "cargo xtask tuf verify-published --repo v2 --dir \"$1\" || return 1\n",
            "cargo xtask tuf verify-published --repo v2 --dir \"$1\" || true\n",
            &[],
        ),
        "does not fall back to the served tuf/v2",
    );
    assert_found(
        mutated(
            "cargo xtask tuf verify-published --repo v2 --dir \"$1\" || return 1\n",
            "cargo xtask tuf verify-published --repo v2 --dir \"$1\"\n",
            &[],
        ),
        "does not fall back to the served tuf/v2",
    );
    assert_found(
        mutated(" --served-v2 --fail-on-expiring", " --served-v2", &[]),
        "does not fall back to the served tuf/v2",
    );
    // Neither new nor served: `build` fails, never a site without tuf/v2.
    assert_found(
        mutated(
            "nothing is deployed (a site without tuf/v2 would read as never published)\"\n            exit 1\n",
            "nothing is deployed (a site without tuf/v2 would read as never published)\"\n            echo \"state=missing\" >> \"$GITHUB_OUTPUT\"\n",
            &[],
        ),
        "or deploys without it",
    );
    assert_found(
        mutated(
            "  tuf-v2-status:\n    needs: [build, deploy]\n",
            "  tuf-v2-status:\n    needs: [build]\n",
            &[],
        ),
        "red after the deployment",
    );
    assert_found(
        mutated("needs.timestamp.result != 'failure' && ", "", &[]),
        "build runs although the timestamp job failed",
    );
    assert_found(
        mutated("    needs: [build, oracle]\n", "    needs: [build]\n", &[]),
        "deploy does not need oracle",
    );
    assert_found(
        mutated("    needs: [build, oracle]\n", "    needs: [oracle]\n", &[]),
        "deploy does not need build",
    );
    assert_found(
        mutated(
            "contains(fromJSON('[\"success\",\"skipped\"]'), needs.oracle.result)",
            "needs.oracle.result != 'failure'",
            &[],
        ),
        "the condition of deploy lacks",
    );
    assert_found(
        mutated("needs.build.result == 'success' && ", "", &[]),
        "the condition of deploy lacks",
    );
    assert_found(
        mutated(
            "  oracle:\n    needs: build\n",
            "  oracle:\n    needs: build\n    environment: tuf-timestamp\n",
            &[],
        ),
        "oracle job has secrets or an environment",
    );
    assert_found(
        mutated(
            "--index \"$RUNNER_TEMP/site/updates/v1\"\n",
            "--index \"$RUNNER_TEMP/site/updates/v1\"\n      - uses: actions/upload-artifact@v5\n        with:\n          path: x\n",
            &[],
        ),
        "uploads an artifact",
    );
    assert_found(
        mutated(
            "  oracle:\n    needs: build\n",
            "  oracle:\n    needs: build\n    secrets: inherit\n",
            &[],
        ),
        "wholesale",
    );
}

#[test]
fn white_space_does_not_hide_a_wholesale_read_of_secrets() {
    for text in [
        "env:\n  A: ${{ toJSON( secrets ) }}\n",
        "env:\n  A: ${{ secrets [ 'X' ] }}\n",
        "jobs:\n  a:\n    secrets:   inherit\n",
    ] {
        assert_found(mutated("", "", &[("x.yml", text)]), "wholesale");
    }
}

#[test]
fn the_v2_secrets_keep_the_rules() {
    // Read twice, outside its job, or outside its environment.
    assert_found(
        mutated(
            "    environment: tuf-snapshot\n",
            "    environment: tuf-snapshot\n    env:\n      K: ${{ secrets.TUF_V2_SNAPSHOT_KEY }}\n",
            &[],
        ),
        "TUF_V2_SNAPSHOT_KEY is read 2 times",
    );
    assert_found(
        mutated(
            "    environment: tuf-snapshot\n",
            "    environment: tuf-timestamp\n",
            &[],
        ),
        "reads TUF_V2_SNAPSHOT_KEY outside the environment tuf-snapshot",
    );
    let moved: Vec<(String, String)> = mutated(
        "          TUF_V2_TIMESTAMP_KEY: ${{ secrets.TUF_V2_TIMESTAMP_KEY }}\n",
        "",
        &[],
    )
    .into_iter()
    .map(|(n, t)| {
        let t = t.replacen(
            "          TUF_V2_SNAPSHOT_KEY: ${{ secrets.TUF_V2_SNAPSHOT_KEY }}\n",
            "          TUF_V2_SNAPSHOT_KEY: ${{ secrets.TUF_V2_SNAPSHOT_KEY }}\n          TUF_V2_TIMESTAMP_KEY: ${{ secrets.TUF_V2_TIMESTAMP_KEY }}\n",
            1,
        );
        (n, t)
    })
    .collect();
    assert_found(
        moved,
        "TUF_V2_TIMESTAMP_KEY is read in the job snapshot, not timestamp",
    );
    // Another job in an environment, or another workflow naming the new names.
    assert_found(
        mutated(
            "  oracle:\n    needs: build\n",
            "  oracle:\n    needs: build\n    environment: tuf-snapshot\n",
            &[],
        ),
        "tuf-snapshot is used by the job oracle",
    );
    for name in [
        "TUF_V2_SNAPSHOT_KEY",
        "TUF_V2_TIMESTAMP_KEY",
        "tuf-snapshot",
    ] {
        let other = format!("name: x\njobs:\n  a:\n    steps:\n      - run: echo {name}\n");
        assert_found(mutated("", "", &[("evil.yml", &other)]), "evil.yml names");
    }
    // The snapshot job: a cache, cargo next to the key, a later step, no mask, no build.
    assert_found(
        mutated(
            "      - name: Is there a tuf/v2?\n",
            "      - uses: Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0 # v2.9.3\n      - name: Is there a tuf/v2?\n",
            &[],
        ),
        "restores a cache",
    );
    assert_found(
        mutated(
            "            previous) target/debug/xtask tuf snapshot",
            "            previous) cargo xtask tuf snapshot",
            &[],
        ),
        "runs cargo",
    );
    assert_found(
        mutated(
            "            echo \"TUF_SNAPSHOT_EOF\"\n          } >> \"$GITHUB_OUTPUT\"\n",
            "            echo \"TUF_SNAPSHOT_EOF\"\n          } >> \"$GITHUB_OUTPUT\"\n      - run: echo later\n",
            &[],
        ),
        "not the last of its job snapshot",
    );
    assert_found(
        mutated(
            "          echo \"::add-mask::$TUF_V2_SNAPSHOT_KEY\"\n",
            "",
            &[],
        ),
        "in snapshot does not mask",
    );
    assert_found(
        mutated(
            "        if: steps.tree.outputs.exists == 'true'\n        run: cargo build -p xtask\n",
            "        if: steps.tree.outputs.exists == 'true'\n        run: echo no build\n",
            &[],
        ),
        "does not build xtask before the secret",
    );
    // The v2 timestamp step must be at the end of `timestamp` too.
    assert_found(
        mutated(
            "      - name: Sign the v2 timestamp\n",
            "      - run: echo between\n      - name: Sign the v2 timestamp\n",
            &[],
        ),
        "not the last of its job timestamp",
    );
    // The condition of the snapshot job.
    assert_found(
        mutated(
            "  snapshot:\n    if: >-\n      github.ref == 'refs/heads/main' &&\n",
            "  snapshot:\n    if: >-\n",
            &[],
        ),
        "snapshot: the condition lacks",
    );
}

#[test]
fn the_first_publication_and_the_v2_gates_are_pinned() {
    assert_found(
        mutated(
            "          FIRST: ${{ vars.TUF_V2_FIRST_PUBLICATION }}\n",
            "          FIRST: \"true\"\n",
            &[],
        ),
        "does not read TUF_V2_FIRST_PUBLICATION",
    );
    assert_found(
        mutated(
            "              if [ \"$FIRST\" != true ]; then\n",
            "              if false; then\n",
            &[],
        ),
        "not limited to HTTP 404",
    );
    assert_found(
        mutated(
            "          MODE: ${{ steps.published.outputs.mode }}\n",
            "          MODE: first\n",
            &[],
        ),
        "mode the probe decided",
    );
    assert_found(
        mutated(
            " --previous \"${PAGES_URL}tuf/v2/\" ;;",
            " --first-publication ;;",
            &[],
        ),
        "does not extend the published one",
    );
    assert_found(
        mutated(
            "target/debug/xtask tuf timestamp --repo v2 --out \"$copy\"",
            "target/debug/xtask tuf timestamp --repo v2 --out \"$copy\" --first-publication",
            &[],
        ),
        "the job timestamp signs a first publication",
    );
    assert_found(
        mutated(
            "          cp -R tuf/v1 _site/tuf/v1\n",
            "          cp -R tuf/v1 _site/tuf/v1\n          cp -R tuf/v2 _site/tuf/v2\n",
            &[],
        ),
        "the step that publishes tuf/v1 touches tuf/v2",
    );
    assert_found(
        mutated(
            "          if [ ! -f tuf/v2/metadata/1.root.json ]; then\n            echo \"state=none\"",
            "          if [ ! -d tuf/v2 ]; then\n            echo \"state=none\"",
            &[],
        ),
        "not gated on tuf/v2/metadata/1.root.json",
    );
    assert_found(
        mutated(
            "      - name: python-tuf over the assembled tuf/v2\n        if: needs.build.outputs.tuf_v2 == 'signed'\n",
            "      - name: python-tuf over the assembled tuf/v2\n",
            &[],
        ),
        "the job oracle does not check tuf/v2",
    );
    assert_found(
        mutated(
            " verify-published --repo v2 --url",
            " verify-published --url",
            &[],
        ),
        "the job verify does not check tuf/v2",
    );
}

#[test]
fn the_review_rules_are_pinned() {
    // The probe fails on an answer other than 200 and 404.
    assert_found(
        mutated(
            "answered '${status}': the published snapshot cannot be extended\"\n              exit 1\n",
            "answered '${status}': the published snapshot cannot be extended\"\n",
            &[],
        ),
        "does not fail on an answer other than 200 and 404",
    );
    // The checkout of a job with a key keeps no credentials.
    assert_found(
        mutated(
            "      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5\n        with:\n          persist-credentials: false\n",
            "      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5\n        with:\n          persist-credentials: true\n",
            &[],
        ),
        "keeps its credentials",
    );
    // Each key masks its own variable.
    assert_found(
        mutated(
            "          echo \"::add-mask::$TUF_V2_TIMESTAMP_KEY\"\n",
            "          echo \"::add-mask::$TUF_TIMESTAMP_KEY\"\n",
            &[],
        ),
        "the step with TUF_V2_TIMESTAMP_KEY does not mask that variable",
    );
    // One Pages address.
    assert_found(
        mutated(
            "          served_url=\"${PAGES_URL}tuf/v2/\"\n",
            "          served_url=\"https://arynyklas.github.io/OpenNCALayer/tuf/v2/\"\n",
            &[],
        ),
        "names the Pages host outside PAGES_URL",
    );
    // The snapshots: packed by the script, unpacked before the key by it.
    assert_found(
        mutated(
            "bash .github/scripts/tuf-v2-snapshots.sh pack ",
            "bash .github/scripts/other.sh pack ",
            &[],
        ),
        "not packed by tuf-v2-snapshots.sh",
    );
    assert_found(
        mutated(
            "        if: steps.unpack.outputs.ready == 'true'\n",
            "        if: steps.tree.outputs.v2 == 'true'\n",
            &[],
        ),
        "not unpacked by tuf-v2-snapshots.sh before the timestamp key",
    );
}

fn snapshot_script() -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.github/scripts/tuf-v2-snapshots.sh"),
    )
    .unwrap()
    .replace("\r\n", "\n")
}

/// What is wrong with the script that carries the snapshots between the jobs.
fn check_snapshot_script(text: &str) -> Vec<String> {
    let mut bad = Vec::new();
    for (needle, rule) in [
        (
            "set -euo pipefail\n",
            "it does not stop on the first failure",
        ),
        ("CAP=102400\n", "the cap is not 100 KiB"),
        (
            "tar -czf - -- \"${names[@]}\" | base64 -w0",
            "it does not pack gzip",
        ),
        (
            "if [ \"${#encoded}\" -gt \"$CAP\" ]; then",
            "it does not refuse a packing over the cap",
        ),
        (
            "if [ \"${#SNAPSHOTS}\" -gt \"$CAP\" ]; then",
            "it does not refuse an input over the cap",
        ),
        (
            "[[ \"$name\" =~ ^[0-9]{1,20}\\.snapshot\\.json$ ]] || fail",
            "it does not allow only <N>.snapshot.json",
        ),
        (
            "[ \"$#\" -ge 1 ] && [ \"$#\" -le 2 ] || fail",
            "it does not allow only one or two files",
        ),
        (
            "tar -xzf \"$archive\" --no-same-owner -C \"$2\" -- \"${names[@]}\"",
            "it does not extract only the names it checked",
        ),
        (
            "echo \"::error::$1\"",
            "a refusal is not an error annotation",
        ),
    ] {
        if !text.contains(needle) {
            bad.push(rule.to_owned());
        }
    }
    let unpack = between(text, "\n  unpack)\n", "\n    ;;").unwrap_or("");
    let checked = unpack.find("check_names \"${names[@]}\"");
    let extracted = unpack.find("tar -xzf");
    if !matches!((checked, extracted), (Some(c), Some(x)) if c < x) {
        bad.push("it extracts before it checks the names".to_owned());
    }
    bad
}

#[test]
fn the_snapshot_script_keeps_its_rules() {
    let text = snapshot_script();
    let bad = check_snapshot_script(&text);
    assert!(bad.is_empty(), "{bad:#?}");
    for (from, to, needle) in [
        ("CAP=102400\n", "CAP=10240000\n", "the cap"),
        ("tar -czf -", "tar -cf -", "gzip"),
        (
            "^[0-9]{1,20}\\.snapshot\\.json$",
            "^.*$",
            "only <N>.snapshot.json",
        ),
        (
            " -- \"${names[@]}\"\n    rm -f",
            "\n    rm -f",
            "only the names it checked",
        ),
    ] {
        assert!(text.contains(from), "the mutation target is gone: {from:?}");
        let broken = check_snapshot_script(&text.replacen(from, to, 1));
        assert!(
            broken.iter().any(|b| b.contains(needle)),
            "not caught ({needle:?}): {broken:#?}"
        );
    }
    let moved = text.replacen(
        "    mapfile -t names < <(tar -tzf \"$archive\")\n    check_names \"${names[@]}\"\n    tar -xzf",
        "    mapfile -t names < <(tar -tzf \"$archive\")\n    tar -xzf",
        1,
    );
    assert_ne!(moved, text);
    assert!(
        check_snapshot_script(&moved)
            .iter()
            .any(|b| b.contains("before it checks"))
    );
}
