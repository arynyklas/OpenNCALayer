# Platform acceptance: the 1 GiB / 1 GiB proof (`cargo xtask platform-proof`)

For maintainers who need to prove one promise: the platform signs and verifies a document of up to **1 GiB** while each process stays within **1 GiB of memory**. This page says how to run the proof, what it covers, what it does not cover, and what the last run showed.

```text
cargo xtask platform-proof --document-bytes 1073741824 --max-rss-bytes 1073741824 \
  --scratch-bytes 17179869184 --out <dir> [--scratch-dir <dir>] [--surface sdk|cli|http|all] \
  [--jobs N] [--only <id>…] [--resume] [--reuse-data] [--skip-build]
```

This gate is separate from the normal test suite. `cargo test -p xtask --test platform_large` runs only small, deterministic cases (the generator, OS measurement, parsing, and a lxml/pyHanko check of the generator). **A big run that was not done is not a pass.**

Before you run it, set up the oracles (OpenSSL 3 and the separate Python environment) as described in [`development.md`](development.md), section «Что нужно для тестов».

## What the run does

1. **Preflight.** `--out` and `--scratch-dir` must be on a fixed local drive (removable, network and optical drives are refused). They need at least `--scratch-bytes` free, plus room for the data. If there is not enough room, the result is `BLOCKED`.
2. **Reference validation on small files**, before any large file:
   - lxml canonicalization of every `Id` element and of the whole XML document;
   - pyHanko checks of the PDF (revisions, page tree, object streams, embedded file);
   - if `ONCL_PY_TOOLS` names pikepdf/pypdf/pdfminer, qpdf/pypdf/pdfminer checks of the PDF too.
3. **An independent generator** (`xtask/src/platform/generate*`) builds the test documents:
   - XML records in a non-canonical form, with the canonical form produced by a second code path (`Id`, namespaces, `xml:lang`, CDATA, character references, comments, processing instructions; the SOAP form has none);
   - SOAP with the signed Body placed after 45 % of the document;
   - PDF with a three-level page tree, a classic xref plus two incremental revisions with xref streams (8-byte offsets) and object streams;
   - a framed pseudo-random byte stream.

   Sizes are exact.
4. **Real programs, release builds, as separate processes:** `sdk_probe large` (SDK), `oncl` (CLI), and `oncl-server` with `oncl --endpoint` as its client (HTTP). Peak working set and peak private bytes come from the OS (Windows: `GetProcessMemoryInfo` plus a job object; Linux: `/proc/<pid>/status`), never from a buffer counter. A case passes only if the stricter of the two peaks is at most `--max-rss-bytes` for every process.
5. **Independent verification of the results:**
   - OpenSSL for CMS;
   - lxml and cryptography for XMLDSig (digests against the generator's canonical digests, and the RSA `SignatureValue`);
   - hashlib, asn1crypto, cryptography and pyHanko for PDF (ByteRange arithmetic, digest of the covered bytes, signature, untouched original prefix).

   GOST has no independent oracle on this machine. Those cases are verified by the SDK itself, with a tampered copy as a contrast.
6. **A matrix per surface (SDK, CLI, HTTP):**
   - hash (known and unknown length, the document-size boundary, limit + 1). The 2 GiB and 4 GiB boundaries run only when `--document-bytes` is raised above the 1 GiB guarantee;
   - CMS with and without embedded data (output larger than the document, read back by extract, verify and OpenSSL), GOST CMS;
   - XMLDSig: far reference, whole document, GOST, WSSE Body in the second half of the document, unknown-length XML, cancellation, temp quota;
   - PDF (dense many-object and compact), PAdES-B, CAdES/PAdES/XAdES T → LT → LTA;
   - output limit, key-application counts (SDK guard, server audit journal), scratch cleanup.
7. **The overload family** (real `oncl-server`, small shared budgets, OTLP gauges collected by the harness; see below): `overload-profile`, `overload-slot-release`, `overload-token-apdu`, and the diagnostic `http-progress-frame-rate` (it runs only when named with `--only`).

## The overload cases

A request body is received under one of `max_uploads` upload slots. Only the completed body takes a `max_in_flight` slot and a native worker (see `docs/user/server.md`, «Загрузки»). So the cases are built on **observed server state, not on clocks**: a wave of clients starts only when the previous wave has produced the state it was meant to produce (`xtask/src/platform/large/barrier.rs`).

What the harness observes is one of three things:

- **What the server did to the client.** With `Expect: 100-continue`, Hyper writes `100 Continue` only when the handler first polls the body, which the server does only after the request holds its upload slot. So receiving `100 Continue` means "this client holds an upload slot" (`http_raw::Probe::continued`). The other signals are an answer or close (`Probe::answered`) and a stalled client that the harness lets go by disconnecting (`Probe::release`), so a stall lasts exactly as long as the plan wants.
- **What the server did to the disk.** Its spool files in the scratch directory (a spool holds what the SERVER received, not what the client wrote into a socket).
- **What the server exported.** Its OTLP gauges, read as the second export after the change (`otlp::second_sample_after`: the first export may have been read just before the change).

Rules of the design:
- Every barrier has a time-out, and a time-out is a failure that names what never happened.
- Every client has a *plan* (`clients::Plan`): it completes; or it is refused with `503 CapacityExceeded`/`NotApplied`; or it ends by its own disconnect; or the server ends it (`504 DeadlineExceeded`/`NotApplied`).
- No wave puts more clients into the upload phase than `max_uploads` can hold, except the one probe that is meant to be refused. So the answer of every client is fixed by the plan, not by arrival order.
- `max_uploads` is explicit in the profiles (the default follows `total_temp / (input_bytes + container_bytes)`), and the budgets leave room for the concurrent signatures of a wave (`total_memory`, `metadata_bytes`). With the default 64 MiB `metadata_bytes`, three of four concurrent signatures of the 8 MiB test document were aborted at their start with `MetadataLimit` (the documented stream abort of a resource failure before any key use; the client sees only a lost response). That is the budget doing its work, but it would decide *which* client completes. So the profile raises `metadata_bytes` (512 MiB) and `total_memory` (1 GiB) and leaves the refusals to the upload slots, whose count is exact.

### `overload-profile`

Settings: `max_in_flight 4`, `blocking_workers 4`, `max_uploads 6`; the upload idle timeout and the operation deadline are far beyond the run.

1. *Five stalled uploads* (one slot short; more than `max_in_flight` and `blocking_workers`). The exported gauges show no running or queued operation. **(a)** A small request and a CPU-bound signature are admitted and complete (the independent oracle checks the signature) while the stalls are still stalled.
2. *Every upload slot taken* (a sixth stall, after a CPU-bound signature was admitted). **(b)** A further upload is refused with `503 CapacityExceeded`/`NotApplied` before its body (no `100 Continue`, no byte sent) after `admission_wait_ms`. `/health` is answered `200` throughout. The operation admitted earlier completes.
3. *Disconnect.* **(c)** Every spool is deleted, the server sees no request in flight, and six new stalled uploads each take a slot at once (a leaked slot would leave one of them unparked, and the barrier fails).
4. *A storm.* A 1 GiB upload and a disconnecting upload are in progress, with four concurrent CPU-bound signatures and three small requests next to them. All complete or end as planned, and the 1 GiB digest is right.
5. *The idle rule*, on a second server (`upload_idle_timeout_ms 3000`, `max_uploads 2`). Two stalled uploads are ended by the server with `504 DeadlineExceeded`/`NotApplied` after about the idle timeout, and are never held to the operation deadline. **(c)** Both slots are free afterwards and the next request completes.

Over the whole run the case checks that:
- every client got an end, with no 500 and no untyped close;
- a key was never applied on a refusal;
- the shared scratch is empty;
- gauges were exported;
- peak running stays within `blocking_workers` (and the signatures did run);
- peak queued stays within `queue_capacity` (the queue stays empty by construction, because `blocking_workers >= max_in_flight`, the documented default shape, so no admitted signature waits for a worker);
- shared temp stays within `total_temp`;
- `/health` is answerable;
- a request after the storm gives the right digest;
- the server stops gracefully;
- every BEGIN in the audit has a FINAL;
- the scratch is empty after the stop.

### `overload-slot-release`

Settings: `max_in_flight 2`, `blocking_workers 2`, `max_uploads 4`, deadline 20 s, idle timeout 120 s.

Two uploads stall against `max_in_flight = 2`. Two CPU-bound signatures complete next to them (the stalls hold no in-flight slot and no worker). Then two stalls that only the operation deadline can end: the server ends them with `504 DeadlineExceeded` at about the deadline, all four upload slots are free again, and the next signature completes.

### `overload-token-apdu`

Sixteen concurrent signatures on two software cards, three times over, through the service library with a counting card backend (not the standalone binary). APDU exchanges and card transactions never overlap per reader, OpenSSL verifies the signatures, and every BEGIN in the audit has a FINAL. `max_uploads` is 8 (explicit; `total_temp` 16 GiB).

### `http-progress-frame-rate`

One 1 GiB CPU-bound signature with a raw client that keeps the response. The case records progress-frame traffic and checks that the response completes without a transport abort. It is a single request and does not depend on the upload phase.

## Limits of the proof (state them in every report)

- **Encryption and decryption** are not covered. The RSA profiles exist at library level only (`oncl_pki::cms::envelope`, rows `envelope-*` of the interop matrix); there is no CLI, HTTP or SDK surface. No Kazakh GOST profile is proven (Kalkan has none, see `[[excluded]] envelope-gost` in [`platform-interop.md`](platform-interop.md)), and no RSA result is claimed for it.
- **Tokens.** The standalone `oncl-server` uses system PC/SC only, and this stand has no virtual reader. Per-device APDU overlap is therefore measured on the same service library hosted by `platform-token-host` with a counting software card. It is labelled that way and is not the standalone binary.
- **Platform and cache effects.** The proof is Windows x64 only unless it is run elsewhere. Reads through `ReadFile` do not enter the process working set; mapped pages do. Both peaks are reported.
- **The report** (`report.json`) holds the environment, program hashes, artifact digests, per-case checks, per-process peaks, durations and temp peaks.

## Last known result

The guaranteed document size is **1 GiB**, and the control-process memory budget is 1 GiB. These are the facts from the acceptance ledger; no claim is made beyond them.

- **The 1 GiB gate has been run.** A full `cargo xtask platform-proof` run with the defaults above (`--jobs 1 --reuse-data`, 42,946 s; the report stays outside the repository) passed **70/70 cases** (SDK 23, CLI 22, HTTP 25). The maximum peak working set of any process was **20.4 MiB**, against the 1 GiB limit.
- **Later server changes are covered only for HTTP.** After that run, `oncl-server` changed (staged close of refused connections, the executor's drop order, intake). The 12 HTTP cases that exercise those changes were rerun on a later commit and passed (12/12, in two runs of 7 and 5 cases; maximum peak working set 20.4 MiB): `overload-profile`, `overload-slot-release`, `overload-token-apdu`, `cms-sign-limit-plus-one`, `hash-limit-plus-one`, `xml-temp-quota`, `xml-cancel`, `http-progress-frame-rate`, `cms-attached`, `pdf-compact-sign`, `xml-whole-document`, `hash-unknown-length`. The other HTTP cases and all SDK and CLI cases were **not** rerun on that commit; their evidence is the 70/70 run. That the server change cannot affect the SDK and CLI cases is an inference, not a check.
- **The overload family** was redesigned before the full run (the first design assumed that a stalled upload holds a worker and an in-flight slot, which stopped being true when the upload phase appeared). It passed three runs alone and three more under artificial CPU and disk contention.
- **Not done at all:** encryption and decryption. They are blocked by something outside the project (see the limits above) and have no case.
- **A larger gate was withdrawn.** A 10 GiB gate was never passed and was withdrawn when the guaranteed size was set to 1 GiB. Its only run found production defects (in PDF/CMS output limits, XAdES-T clock sampling, HTTP progress frames, dense-PDF cross-reference budget, and stalled uploads holding an admission slot); they were all fixed. A 2 GiB rerun before the change also passed for PDF, PAdES, CAdES, and XML cases, with the peak working set and private bytes at or below about 20 MiB.
