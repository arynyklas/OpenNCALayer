//! The dialogs of these tests: a [`Prompter`] answering from a script and an in-memory
//! [`RecentPathStore`].

use oncl_flows::{
    Busy, BusyPrompt, ChoiceAnswer, ChoicePrompt, ConfirmPrompt, CsrAnswer, CsrPrompt, FilePrompt,
    ImportAnswer, ImportPrompt, KeyPrompt, MessagePrompt, PasswordPrompt, PathPrompt, Prompt,
    Prompter, ReaderPrompt, RecentPathStore, SavePrompt, StorageAnswer, StorageKind, StoragePrompt,
};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use zeroize::Zeroizing;

/// One scripted answer. Its `Debug` form is its kind alone: scripts carry passwords.
#[derive(Clone)]
pub enum Step {
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
    /// Pick candidate `n` in a key prompt.
    Key(usize),
    /// Cancel a key prompt.
    CancelKey,
    /// Close a message with OK.
    Message,
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
}

impl Step {
    /// The step's kind, for messages: never its password or path.
    fn kind(&self) -> &'static str {
        match self {
            Step::Storage { .. } => "Storage",
            Step::CancelStorage => "CancelStorage",
            Step::Jks { .. } => "Jks",
            Step::Token { .. } => "Token",
            Step::Key(_) => "Key",
            Step::CancelKey => "CancelKey",
            Step::Message => "Message",
            Step::Confirm { .. } => "Confirm",
            Step::CancelConfirm => "CancelConfirm",
            Step::Save { .. } => "Save",
            Step::CancelSave => "CancelSave",
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
    message_prompts: Vec<MessagePrompt>,
    confirm_prompts: Vec<ConfirmPrompt>,
    save_prompts: Vec<SavePrompt>,
}

/// A [`Prompter`] answering from a queue of [`Step`]s and recording the prompts shown. An
/// empty queue cancels. A key prompt is answered once its OCSP checks have settled, as a
/// user would pick from what the dialog ends up showing. Safe to share between threads.
///
/// A window whose next scripted step answers another kind of window is cancelled and logged,
/// never a panic: the step is dropped.
pub struct ScriptedPrompter {
    state: Arc<Mutex<State>>,
}

impl ScriptedPrompter {
    /// A prompter answering with `steps` in order.
    pub fn new(steps: Vec<Step>) -> Self {
        ScriptedPrompter {
            state: Arc::new(Mutex::new(State {
                steps: steps.into(),
                ..State::default()
            })),
        }
    }

    /// What was shown so far, in order: `"storage"`, `"busy"`, `"busy closed"`, `"key"`,
    /// `"csr"`, `"import"`, `"file"`, `"password"`, `"message"`, `"confirm"`, `"save"`,
    /// `"choice"`, `"path"`, `"reader"`.
    pub fn timeline(&self) -> Vec<&'static str> {
        self.lock().timeline.clone()
    }

    /// Storage prompts shown so far.
    pub fn storage_prompts(&self) -> Vec<StoragePrompt> {
        self.lock().storage_prompts.clone()
    }

    /// Key prompts answered so far, with the availabilities they settled on.
    pub fn key_prompts(&self) -> Vec<KeyPrompt> {
        self.lock().key_prompts.clone()
    }

    /// Messages shown so far.
    pub fn message_prompts(&self) -> Vec<MessagePrompt> {
        self.lock().message_prompts.clone()
    }

    /// Yes/no questions shown so far.
    pub fn confirm_prompts(&self) -> Vec<ConfirmPrompt> {
        self.lock().confirm_prompts.clone()
    }

    /// Save dialogs shown so far.
    pub fn save_prompts(&self) -> Vec<SavePrompt> {
        self.lock().save_prompts.clone()
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
        eprintln!("{line}");
        Prompt::Cancelled
    }

    /// Records a prompt of `kind`, then takes the next step.
    fn next(&self, kind: &'static str, record: impl FnOnce(&mut State)) -> Option<Step> {
        let mut state = self.lock();
        state.timeline.push(kind);
        record(&mut state);
        state.steps.pop_front()
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
            None => Prompt::Cancelled,
            Some(step) => self.mismatch("generateCsr prompt", &step),
        }
    }

    fn import_cert(&self, _p: &ImportPrompt) -> Prompt<ImportAnswer> {
        match self.next("import", |_| {}) {
            None => Prompt::Cancelled,
            Some(step) => self.mismatch("importCertificate prompt", &step),
        }
    }

    fn file(&self, _p: &FilePrompt) -> Prompt<PathBuf> {
        match self.next("file", |_| {}) {
            None => Prompt::Cancelled,
            Some(step) => self.mismatch("file chooser", &step),
        }
    }

    fn password(&self, _p: &PasswordPrompt) -> Prompt<Zeroizing<String>> {
        match self.next("password", |_| {}) {
            None => Prompt::Cancelled,
            Some(step) => self.mismatch("password dialog", &step),
        }
    }

    fn message(&self, p: &MessagePrompt) -> Prompt<()> {
        match self.next("message", |s| s.message_prompts.push(p.clone())) {
            Some(Step::Message) => Prompt::Answer(()),
            None => Prompt::Cancelled,
            Some(step) => self.mismatch("message", &step),
        }
    }

    fn confirm(&self, p: &ConfirmPrompt) -> Prompt<bool> {
        match self.next("confirm", |s| s.confirm_prompts.push(p.clone())) {
            Some(Step::Confirm { yes }) => Prompt::Answer(yes),
            Some(Step::CancelConfirm) | None => Prompt::Cancelled,
            Some(step) => self.mismatch("question", &step),
        }
    }

    fn save_file(&self, p: &SavePrompt) -> Prompt<PathBuf> {
        match self.next("save", |s| s.save_prompts.push(p.clone())) {
            Some(Step::Save { path }) => Prompt::Answer(path),
            Some(Step::CancelSave) | None => Prompt::Cancelled,
            Some(step) => self.mismatch("save dialog", &step),
        }
    }

    fn choice(&self, _p: &ChoicePrompt) -> Prompt<ChoiceAnswer> {
        match self.next("choice", |_| {}) {
            None => Prompt::Cancelled,
            Some(step) => self.mismatch("choice", &step),
        }
    }

    fn path(&self, _p: &PathPrompt) -> Prompt<PathBuf> {
        match self.next("path", |_| {}) {
            None => Prompt::Cancelled,
            Some(step) => self.mismatch("path chooser", &step),
        }
    }

    fn reader(&self, _p: &ReaderPrompt) -> Prompt<String> {
        match self.next("reader", |_| {}) {
            None => Prompt::Cancelled,
            Some(step) => self.mismatch("reader prompt", &step),
        }
    }
}

/// A [`RecentPathStore`] in memory.
pub struct MemoryRecentPath {
    initial: Option<PathBuf>,
    saved: Mutex<Option<PathBuf>>,
}

impl MemoryRecentPath {
    /// A store whose path is `initial` until something is saved.
    pub fn new(initial: Option<PathBuf>) -> Self {
        MemoryRecentPath {
            initial,
            saved: Mutex::new(None),
        }
    }

    /// The last path passed to [`RecentPathStore::save`].
    pub fn saved(&self) -> Option<PathBuf> {
        self.saved
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl RecentPathStore for MemoryRecentPath {
    fn load(&self) -> Option<PathBuf> {
        self.saved().or_else(|| self.initial.clone())
    }

    fn save(&self, p: &Path) {
        *self.saved.lock().unwrap_or_else(PoisonError::into_inner) = Some(p.to_path_buf());
    }
}
