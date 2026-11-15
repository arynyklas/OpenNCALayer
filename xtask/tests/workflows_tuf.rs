//! The rules for the one secret CI holds, the online TUF timestamp key (`docs/dev/release.md`),
//! checked on the workflow files as they are: the secret is named only in `pages.yml`, only in
//! the `env` of one step, of a job that runs in the environment `tuf-timestamp` on `main`
//! only and on events nobody outside the project can start, with no write permission and no
//! unpinned action after the secret is in the environment; and no workflow that a pull
//! request triggers mentions the environment or the secret at all.
//!
//! The workflows are read line by line with their indentation (this repository's workflows
//! use two spaces and the block style throughout, and this test is the reason to keep it so):
//! a YAML parser is not a dependency of `xtask`.

use std::fs;
use std::path::PathBuf;

const SECRET: &str = "TUF_TIMESTAMP_KEY";
const ENVIRONMENT: &str = "tuf-timestamp";

struct Line {
    indent: usize,
    text: String,
    number: usize,
}

fn workflows() -> Vec<(String, Vec<Line>, String)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows");
    let mut found = Vec::new();
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "yml") {
            continue;
        }
        let raw = fs::read_to_string(&path).unwrap();
        let lines = raw
            .lines()
            .enumerate()
            .filter(|(_, l)| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
            .map(|(n, l)| Line {
                indent: l.len() - l.trim_start().len(),
                text: l.trim().to_owned(),
                number: n + 1,
            })
            .collect();
        found.push((
            path.file_name().unwrap().to_string_lossy().into_owned(),
            lines,
            raw,
        ));
    }
    assert!(
        found.len() > 5,
        "the workflows were not found in {}",
        dir.display()
    );
    found
}

/// The lines above `at`, nearest first, each of smaller indentation than the one before.
fn ancestors(lines: &[Line], at: usize) -> Vec<usize> {
    let mut found = Vec::new();
    let mut indent = lines[at].indent;
    for i in (0..at).rev() {
        if lines[i].indent < indent {
            found.push(i);
            indent = lines[i].indent;
        }
    }
    found
}

/// The lines below `at` that belong to it.
fn block(lines: &[Line], at: usize) -> std::ops::Range<usize> {
    let mut end = at + 1;
    while end < lines.len() && lines[end].indent > lines[at].indent {
        end += 1;
    }
    at + 1..end
}

fn on_block(lines: &[Line]) -> Vec<&Line> {
    let at = lines
        .iter()
        .position(|l| l.indent == 0 && (l.text == "on:" || l.text == "\"on\":"))
        .expect("every workflow has `on:`");
    block(lines, at).map(|i| &lines[i]).collect()
}

#[test]
fn the_secret_and_the_environment_are_named_only_in_pages_yml() {
    for (name, _, raw) in workflows() {
        if name == "pages.yml" {
            continue;
        }
        assert!(
            !raw.contains(SECRET) && !raw.contains(ENVIRONMENT),
            "{name} mentions the TUF timestamp secret or environment"
        );
    }
}

#[test]
fn no_workflow_a_pull_request_triggers_can_reach_the_secret() {
    for (name, lines, raw) in workflows() {
        let triggers = on_block(&lines);
        let by_pull_request = triggers.iter().any(|l| {
            l.text.starts_with("pull_request:") || l.text.starts_with("pull_request_target:")
        });
        if name == "pages.yml" {
            assert!(!by_pull_request, "pages.yml is triggered by a pull request");
        }
        if by_pull_request {
            assert!(
                !raw.contains(SECRET) && !raw.contains(ENVIRONMENT),
                "{name} is triggered by a pull request and names the TUF timestamp secret"
            );
        }
    }
}

#[test]
fn the_secret_is_in_the_env_of_one_step_of_one_guarded_job() {
    let (_, lines, raw) = workflows()
        .into_iter()
        .find(|(n, _, _)| n == "pages.yml")
        .unwrap();
    // Where the secret is read: `secrets.TUF_TIMESTAMP_KEY`, once.
    let reads: Vec<usize> = (0..lines.len())
        .filter(|&i| lines[i].text.contains(&format!("secrets.{SECRET}")))
        .collect();
    assert_eq!(reads.len(), 1, "the secret is read {} times", reads.len());
    let read = reads[0];
    assert_eq!(
        lines[read].text,
        format!("{SECRET}: ${{{{ secrets.{SECRET} }}}}")
    );
    // ... in the `env` of a step of a job: not of the job, not of the workflow.
    let up = ancestors(&lines, read);
    assert!(up.len() >= 5, "line {}", lines[read].number);
    assert_eq!(lines[up[0]].text, "env:", "not a step-level env");
    assert!(lines[up[1]].text.starts_with("- "), "not in a step");
    assert_eq!(lines[up[2]].text, "steps:");
    assert!(lines[up[3]].text.ends_with(':'));
    assert_eq!(lines[up[4]].text, "jobs:");
    let (step, job) = (up[1], up[3]);

    // The job: the environment, `main`, the events, no write permission.
    let children: Vec<usize> = block(&lines, job)
        .filter(|&i| lines[i].indent == lines[job].indent + 2)
        .collect();
    let child = |key: &str| {
        children
            .iter()
            .copied()
            .find(|&i| lines[i].text.starts_with(key))
            .unwrap_or_else(|| panic!("the job has no `{key}`"))
    };
    assert_eq!(
        lines[child("environment:")].text,
        format!("environment: {ENVIRONMENT}")
    );
    let guard = child("if:");
    let condition: String = std::iter::once(guard)
        .chain(block(&lines, guard))
        .map(|i| lines[i].text.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        condition.contains("github.ref == 'refs/heads/main'"),
        "{condition}"
    );
    assert!(!condition.contains("pull_request"), "{condition}");
    for event in [
        "push",
        "schedule",
        "workflow_run",
        "workflow_dispatch",
        "repository_dispatch",
    ] {
        assert!(
            condition.contains(&format!("github.event_name == '{event}'")),
            "{event}"
        );
    }
    assert!(
        children.iter().all(|&i| lines[i].text != "env:"),
        "the job has an env of its own"
    );
    let permissions = child("permissions:");
    let granted: Vec<&str> = block(&lines, permissions)
        .map(|i| lines[i].text.as_str())
        .collect();
    assert_eq!(granted, ["contents: read"]);

    // The triggers of the workflow have no pull request, and the environment is used by this
    // job alone.
    assert!(
        !on_block(&lines)
            .iter()
            .any(|l| l.text.starts_with("pull_request")),
        "pages.yml is triggered by a pull request"
    );
    assert_eq!(
        raw.matches(&format!("environment: {ENVIRONMENT}")).count(),
        1
    );

    // The step has no action, masks the key, and no action runs after it that is not pinned
    // by a commit.
    let step_lines: Vec<&str> = std::iter::once(step)
        .chain(block(&lines, step))
        .map(|i| lines[i].text.as_str())
        .collect();
    assert!(
        !step_lines.iter().any(|l| l.contains("uses:")),
        "the step uses an action"
    );
    assert!(
        step_lines.iter().any(|l| l.contains("::add-mask::$")),
        "the step does not mask the key"
    );
    let mut after = block(&lines, job)
        .filter(|&i| i >= block(&lines, step).end)
        .collect::<Vec<_>>();
    after.retain(|&i| lines[i].text.contains("uses:"));
    for i in after {
        let uses = &lines[i].text;
        let sha = uses
            .split('@')
            .nth(1)
            .is_some_and(|r| r.len() >= 40 && r[..40].bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(
            sha,
            "an action after the secret step is not pinned by a commit: {uses}"
        );
    }
    // The signed file leaves the job as an output, not as an artifact.
    assert!(!block(&lines, job).any(|i| lines[i].text.contains("upload-artifact")));
}

#[test]
fn only_the_deploy_job_may_write_pages() {
    let (_, lines, _) = workflows()
        .into_iter()
        .find(|(n, _, _)| n == "pages.yml")
        .unwrap();
    for (i, line) in lines.iter().enumerate() {
        if line.text == "pages: write" || line.text == "id-token: write" {
            let up = ancestors(&lines, i);
            let job = &lines[up[1]].text;
            assert_eq!(job, "deploy:", "{} at line {}", line.text, line.number);
        }
    }
}
