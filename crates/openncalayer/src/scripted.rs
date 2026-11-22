//! The dialogs answered from a script instead of windows: the `run` of a test build (feature
//! `e2e-prompter`, `cli::e2e_prompter`) and the tests of this crate. The library's unit
//! tests, the binary's and the integration tests compile this file as a module of their own;
//! each of them uses a part of it.

#![cfg_attr(
    test,
    allow(
        dead_code,
        reason = "each test target of the crate uses a part of the script"
    )
)]

#[cfg(test)]
use oncl_flows::RecentPathStore;
use oncl_flows::{
    Busy, BusyPrompt, ChoiceAnswer, ChoicePrompt, ConfirmPrompt, CsrAnswer, CsrPrompt, FilePrompt,
    ImportAnswer, ImportPrompt, KeyPrompt, MessagePrompt, PasswordPrompt, PathPrompt, Prompt,
    Prompter, ReaderPrompt, SavePrompt, StorageAnswer, StorageKind, StoragePrompt,
};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Barrier, Mutex, MutexGuard, PoisonError};
use zeroize::Zeroizing;

/// One scripted answer. Its `Debug` form is its kind alone: scripts carry passwords.
#[derive(Clone)]
pub(crate) enum Step {
    /// Answer a storage prompt with a PKCS#12 file.
    Storage {
        /// Key store file.
        path: PathBuf,
        /// Its password.
        password: String,
    },
    /// Cancel a storage prompt.
    CancelStorage,
    /// Answer a storage prompt with a JKS file.
    Jks {
        /// Key store file.
        path: PathBuf,
        /// Its password.
        password: String,
    },
    /// Answer a storage prompt with a hardware token.
    Token {
        /// The token's storage.
        storage: StorageKind,
        /// Its reader.
        reader: String,
        /// Its PIN.
        pin: String,
    },
    /// Answer a reader prompt with this reader.
    Reader(String),
    /// Cancel a reader prompt.
    CancelReader,
    /// Pick candidate `n` in a key prompt.
    Key(usize),
    /// Cancel a key prompt.
    CancelKey,
    /// Answer a `generateCsr` prompt with PKCS#12 key files in `dir`.
    Csr {
        /// Folder for the key files.
        dir: PathBuf,
        /// The key file password (asked only without a `defaultPassword`; pass `""` then).
        password: String,
    },
    /// Cancel a `generateCsr` prompt.
    CancelCsr,
    /// Answer an `importCertificate` prompt.
    Import {
        /// Folder (or key file) holding the keys.
        dir: PathBuf,
        /// The new key file password.
        password: String,
    },
    /// Cancel an `importCertificate` prompt.
    CancelImport,
    /// Answer a file chooser with this path.
    File(PathBuf),
    /// Cancel a file chooser.
    CancelFile,
    /// Answer a password dialog.
    Password(String),
    /// Cancel a password dialog.
    CancelPassword,
    /// Close a message with OK.
    Message,
    /// Close a message's window.
    CancelMessage,
    /// Answer a yes/no question.
    Confirm {
        /// Yes.
        yes: bool,
    },
    /// Close a yes/no question's window.
    CancelConfirm,
    /// Answer a save dialog with this path.
    Save {
        /// Where to save.
        path: PathBuf,
    },
    /// Cancel a save dialog.
    CancelSave,
    /// Answer a plugin's choice: the button pressed and the option selected.
    Choice {
        /// The button.
        button: usize,
        /// The option, if any.
        option: Option<usize>,
    },
    /// Close a plugin's choice.
    CancelChoice,
    /// Answer a plugin's path chooser with this path.
    Path(PathBuf),
    /// Cancel a plugin's path chooser.
    CancelPath,
    /// Wait on the barrier (without holding the prompter), then take the next step for the
    /// same prompt.
    Wait(Arc<Barrier>),
}

impl Step {
    /// The step's kind, for messages: never its password or path.
    fn kind(&self) -> &'static str {
        match self {
            Step::Storage { .. } => "Storage",
            Step::CancelStorage => "CancelStorage",
            Step::Jks { .. } => "Jks",
            Step::Token { .. } => "Token",
            Step::Reader(_) => "Reader",
            Step::CancelReader => "CancelReader",
            Step::Key(_) => "Key",
            Step::CancelKey => "CancelKey",
            Step::Csr { .. } => "Csr",
            Step::CancelCsr => "CancelCsr",
            Step::Import { .. } => "Import",
            Step::CancelImport => "CancelImport",
            Step::File(_) => "File",
            Step::CancelFile => "CancelFile",
            Step::Password(_) => "Password",
            Step::CancelPassword => "CancelPassword",
            Step::Message => "Message",
            Step::CancelMessage => "CancelMessage",
            Step::Confirm { .. } => "Confirm",
            Step::CancelConfirm => "CancelConfirm",
            Step::Save { .. } => "Save",
            Step::CancelSave => "CancelSave",
            Step::Choice { .. } => "Choice",
            Step::CancelChoice => "CancelChoice",
            Step::Path(_) => "Path",
            Step::CancelPath => "CancelPath",
            Step::Wait(_) => "Wait",
        }
    }
}

impl std::fmt::Debug for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.kind())
    }
}

#[derive(Default)]
struct State {
    steps: VecDeque<Step>,
    timeline: Vec<&'static str>,
    storage_prompts: Vec<StoragePrompt>,
    key_prompts: Vec<KeyPrompt>,
    password_prompts: Vec<PasswordPrompt>,
    choice_prompts: Vec<ChoicePrompt>,
}

/// A [`Prompter`] answering from a queue of [`Step`]s and recording the prompts shown. An
/// empty queue cancels. A key prompt is answered once its OCSP checks have settled, as a
/// user would pick from what the dialog ends up showing. Safe to share between threads.
///
/// A window whose next scripted step answers another kind of window is cancelled and logged,
/// never a panic: the step is dropped.
pub(crate) struct ScriptedPrompter {
    state: Arc<Mutex<State>>,
}

impl ScriptedPrompter {
    /// A prompter answering with `steps` in order.
    pub(crate) fn new(steps: Vec<Step>) -> Self {
        ScriptedPrompter {
            state: Arc::new(Mutex::new(State {
                steps: steps.into(),
                ..State::default()
            })),
        }
    }

    /// Storage prompts shown so far.
    #[cfg(test)]
    pub(crate) fn storage_prompts(&self) -> Vec<StoragePrompt> {
        self.lock().storage_prompts.clone()
    }

    /// Key prompts answered so far, with the availabilities they settled on.
    #[cfg(test)]
    pub(crate) fn key_prompts(&self) -> Vec<KeyPrompt> {
        self.lock().key_prompts.clone()
    }

    /// Password dialogs shown so far.
    #[cfg(test)]
    pub(crate) fn password_prompts(&self) -> Vec<PasswordPrompt> {
        self.lock().password_prompts.clone()
    }

    /// Plugins' choices shown so far.
    #[cfg(test)]
    pub(crate) fn choice_prompts(&self) -> Vec<ChoicePrompt> {
        self.lock().choice_prompts.clone()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        lock(&self.state)
    }

    /// A window met a scripted answer of another kind: the script and the flow disagree.
    /// Logs it and cancels the window, so the call ends with its ordinary cancel reply
    /// instead of a panic taking the connection down.
    fn mismatch<T>(&self, window: &str, step: &Step) -> Prompt<T> {
        let line = format!(
            "ScriptedPrompter: {window} met the scripted step {}; the window is cancelled",
            step.kind()
        );
        tracing::error!("{line}");
        Prompt::Cancelled
    }

    /// Records a prompt of `kind`, then takes the next answering step, waiting out `Wait`
    /// steps with the state unlocked.
    fn next(&self, kind: &'static str, record: impl FnOnce(&mut State)) -> Option<Step> {
        let mut state = self.lock();
        state.timeline.push(kind);
        record(&mut state);
        loop {
            match state.steps.pop_front() {
                Some(Step::Wait(barrier)) => {
                    drop(state);
                    barrier.wait();
                    state = self.lock();
                }
                step => return step,
            }
        }
    }
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Prompter for ScriptedPrompter {
    fn storage(&self, p: &StoragePrompt) -> Prompt<StorageAnswer> {
        match self.next("storage", |s| s.storage_prompts.push(p.clone())) {
            Some(Step::Storage { path, password }) => Prompt::Answer(StorageAnswer {
                storage: StorageKind::Pkcs12,
                path,
                password: Zeroizing::new(password),
                reader: None,
            }),
            Some(Step::Jks { path, password }) => Prompt::Answer(StorageAnswer {
                storage: StorageKind::Jks,
                path,
                password: Zeroizing::new(password),
                reader: None,
            }),
            Some(Step::Token {
                storage,
                reader,
                pin,
            }) => Prompt::Answer(StorageAnswer {
                storage,
                path: PathBuf::new(),
                password: Zeroizing::new(pin),
                reader: Some(reader),
            }),
            Some(Step::CancelStorage) | None => Prompt::Cancelled,
            Some(step) => self.mismatch("storage prompt", &step),
        }
    }

    fn busy(&self, _p: &BusyPrompt) -> Busy {
        self.lock().timeline.push("busy");
        let state = Arc::clone(&self.state);
        Busy::new(move || lock(&state).timeline.push("busy closed"))
    }

    fn key(&self, p: &KeyPrompt) -> Prompt<usize> {
        let step = self.next("key", |_| {});
        let mut settled = p.clone();
        for (candidate, availability) in settled.candidates.iter_mut().zip(p.live.wait_settled()) {
            candidate.availability = availability;
        }
        self.lock().key_prompts.push(settled);
        match step {
            Some(Step::Key(index)) => Prompt::Answer(index),
            Some(Step::CancelKey) | None => Prompt::Cancelled,
            Some(step) => self.mismatch("key prompt", &step),
        }
    }

    fn csr(&self, _p: &CsrPrompt) -> Prompt<CsrAnswer> {
        match self.next("csr", |_| {}) {
            Some(Step::Csr { dir, password }) => Prompt::Answer(CsrAnswer {
                storage: StorageKind::Pkcs12,
                dir,
                password: Zeroizing::new(password),
            }),
            Some(Step::CancelCsr) | None => Prompt::Cancelled,
            Some(step) => self.mismatch("generateCsr prompt", &step),
        }
    }

    fn import_cert(&self, _p: &ImportPrompt) -> Prompt<ImportAnswer> {
        match self.next("import", |_| {}) {
            Some(Step::Import { dir, password }) => Prompt::Answer(ImportAnswer {
                dir,
                new_password: Zeroizing::new(password),
            }),
            Some(Step::CancelImport) | None => Prompt::Cancelled,
            Some(step) => self.mismatch("importCertificate prompt", &step),
        }
    }

    fn file(&self, _p: &FilePrompt) -> Prompt<PathBuf> {
        match self.next("file", |_| {}) {
            Some(Step::File(path)) => Prompt::Answer(path),
            Some(Step::CancelFile) | None => Prompt::Cancelled,
            Some(step) => self.mismatch("file chooser", &step),
        }
    }

    fn password(&self, p: &PasswordPrompt) -> Prompt<Zeroizing<String>> {
        match self.next("password", |s| s.password_prompts.push(p.clone())) {
            Some(Step::Password(password)) => Prompt::Answer(Zeroizing::new(password)),
            Some(Step::CancelPassword) | None => Prompt::Cancelled,
            Some(step) => self.mismatch("password dialog", &step),
        }
    }

    fn message(&self, _p: &MessagePrompt) -> Prompt<()> {
        match self.next("message", |_| {}) {
            Some(Step::Message) => Prompt::Answer(()),
            Some(Step::CancelMessage) | None => Prompt::Cancelled,
            Some(step) => self.mismatch("message", &step),
        }
    }

    fn confirm(&self, _p: &ConfirmPrompt) -> Prompt<bool> {
        match self.next("confirm", |_| {}) {
            Some(Step::Confirm { yes }) => Prompt::Answer(yes),
            Some(Step::CancelConfirm) | None => Prompt::Cancelled,
            Some(step) => self.mismatch("question", &step),
        }
    }

    fn save_file(&self, _p: &SavePrompt) -> Prompt<PathBuf> {
        match self.next("save", |_| {}) {
            Some(Step::Save { path }) => Prompt::Answer(path),
            Some(Step::CancelSave) | None => Prompt::Cancelled,
            Some(step) => self.mismatch("save dialog", &step),
        }
    }

    fn choice(&self, p: &ChoicePrompt) -> Prompt<ChoiceAnswer> {
        match self.next("choice", |s| s.choice_prompts.push(p.clone())) {
            Some(Step::Choice { button, option }) => {
                Prompt::Answer(ChoiceAnswer { button, option })
            }
            Some(Step::CancelChoice) | None => Prompt::Cancelled,
            Some(step) => self.mismatch("choice", &step),
        }
    }

    fn path(&self, _p: &PathPrompt) -> Prompt<PathBuf> {
        match self.next("path", |_| {}) {
            Some(Step::Path(path)) => Prompt::Answer(path),
            Some(Step::CancelPath) | None => Prompt::Cancelled,
            Some(step) => self.mismatch("path chooser", &step),
        }
    }

    fn reader(&self, _p: &ReaderPrompt) -> Prompt<String> {
        match self.next("reader", |_| {}) {
            Some(Step::Reader(reader)) => Prompt::Answer(reader),
            Some(Step::CancelReader) | None => Prompt::Cancelled,
            Some(step) => self.mismatch("reader prompt", &step),
        }
    }
}

/// A [`RecentPathStore`] in memory.
#[cfg(test)]
pub(crate) struct MemoryRecentPath {
    initial: Option<PathBuf>,
    saved: Mutex<Option<PathBuf>>,
}

#[cfg(test)]
impl MemoryRecentPath {
    /// A store whose path is `initial` until something is saved.
    pub(crate) fn new(initial: Option<PathBuf>) -> Self {
        MemoryRecentPath {
            initial,
            saved: Mutex::new(None),
        }
    }

    /// The last path passed to [`RecentPathStore::save`].
    pub(crate) fn saved(&self) -> Option<PathBuf> {
        self.saved
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[cfg(test)]
impl RecentPathStore for MemoryRecentPath {
    fn load(&self) -> Option<PathBuf> {
        self.saved().or_else(|| self.initial.clone())
    }

    fn save(&self, p: &std::path::Path) {
        *self.saved.lock().unwrap_or_else(PoisonError::into_inner) = Some(p.to_path_buf());
    }
}
