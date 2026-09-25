# ThreatFusion: separate Gemini copy and preserved baseline

Revised 2026-09-25. This revision supersedes the previous same-directory plan.

## Meaning of the backup

A snapshot contains files as they existed when it was taken. Later work needs
later checkpoints. The baseline is not incomplete merely because future edits
are absent. Owner-supplied terminal output confirms source comparison and
SHA-256 checks of the full project archive and the external uv Python archive.
A restore rehearsal and a full operating-system backup have not been reported.

| Location | Role |
| --- | --- |
| `~/projects/threatfusion` | Preserved original; do not use for Gemini work |
| `~/projects/threatfusion-gemini` | New independent full copy; active Gemini work |
| SANDISK USB | Verified unencrypted project/Python recovery snapshots |
| GitHub `bilaldevsec/Threatfusion` main | Code checkpoint at `d3f485aa3933fda996b8784ffe11dc54d43bbb8e` |

The copy retains an independent .git directory and the existing local branch
`gemini/product-20260924`. Identical branch names in independent directories
do not share local branch pointers. A branch alone does not isolate ignored
files; this full copy copies those files as well. Both directories still share
one SSD, and both initially use the same base Python installation read-only.

## Completed Setup Record (Do Not Rerun)

The following sections (1 through 5) record the completed initial copy,
installer, and reconnaissance steps. They are historical and should not be
rerun.

### Current Starting Point

For new sessions:
1. Enter `~/projects/threatfusion-gemini`
2. Check Git state and verify the push guard
3. Use `threatfusion-venv` and the current handoff instructions

## 1. Check current storage and stop project writers

Use a fresh terminal without activating the old environment. Stop active coding
agents, tests, services and demo writers normally; no blanket process-kill command.

```bash
cd "$HOME"
df -hT "$HOME/projects" /
du -sh "$HOME/projects/threatfusion"
command -v rsync unzip git cp
ps -eo pid,ppid,stat,etimes,cmd= | rg '[p]ytest|[r]uff|[b]lack|[p]roducer_service|[a]nalyst_tls_service|[r]un_fyp_progress_demo' || true
```

If rsync/unzip are missing, install them before the copy (`sudo apt update`,
then `sudo apt install rsync unzip`). Do not run a general system upgrade.
The copy script requires current free space greater than the source's apparent
size plus 10 GiB. Earlier owner output had about 66 GiB available on /home; the
screenshot's 24.1 GB refers to the separate root volume. No partition change is
needed just to make a roughly 5 GB copy if those figures still hold.

## 2. Download and unpack this revised handoff

Save the current ZIP from ChatGPT into Downloads and verify the digest given
with the download. Extract into a NEW directory outside either project:

```bash
ZIP="$HOME/Downloads/ThreatFusion_Gemini_Handoff_2026-09-24.zip"
HANDOFF=$(mktemp -d "$HOME/Downloads/threatfusion-handoff.XXXXXX")
unzip "$ZIP" -d "$HANDOFF"
bash -n "$HANDOFF/PREPARE_GEMINI_COPY.sh"
bash "$HANDOFF/PREPARE_GEMINI_COPY.sh"
```

Run the final command once. If the destination exists or any check fails, stop
and share the output; do not delete or overwrite it. The script:

- checks the expected original HEAD/branch and absence of staged/tracked edits;
- refuses existing destinations and unexpected shared Git metadata;
- copies all source entries with GNU cp archive mode, without hardlinking to
  original files or excluding .git, ignored data, models or the existing .venv;
- performs a read-only rsync content checksum and metadata comparison;
- verifies the copy's own .git and branch;
- sets the copy's push guard and replaces ONLY its three handoff documents with
  this revision, retaining any prior drafts under the copy's .git directory;
- reports source and destination Git status without refreshing the source index.

The script does not modify the original project contents, invoke model code,
rebuild environments, commit, push, or touch the USB. The owner reported
successful verification of the copy. Do not activate the copied .venv.

## 3. Verify the original commit's CI, from the new copy

```bash
cd "$HOME/projects/threatfusion-gemini"
git status --short --branch
git rev-parse --show-toplevel
git rev-parse --absolute-git-dir
git config --get remote.origin.pushurl
gh run list --repo bilaldevsec/Threatfusion \
  --commit d3f485aa3933fda996b8784ffe11dc54d43bbb8e --limit 5 \
  --json databaseId,name,status,conclusion,headSha,url,event
```

The owner supplied `gh run list` output showing Backend quality run 36008647379
succeeded for baseline commit d3f485aa3933fda996b8784ffe11dc54d43bbb8e
(owner-supplied command output).

## 4. Install the coding client

Use Antigravity CLI as the initial terminal coding client. Google's official
installation guide is https://antigravity.google/docs/cli/install . Commands:

```bash
cd "$HOME"
installer=$(mktemp /tmp/agy-install.XXXXXXXX.sh)
curl -fsSL https://antigravity.google/cli/install.sh -o "$installer"
less "$installer"
bash "$installer" --dir "$HOME/.local/bin"
"$HOME/.local/bin/agy" --version
```

Inspect the downloaded script in less; q exits less. Do not execute the file if
download failed. No sudo is needed for this per-user installer. The `--dir` flag
selects the install directory. The installer separately added PATH exports to
shell profiles. Continue invoking the binary by full path.
Do not install the legacy Gemini CLI as an additional route for this migration.
No API key or Google Cloud project is needed for personal Google account login.

Safely eject and disconnect the USB, then start from the new copy:

```bash
cd "$HOME/projects/threatfusion-gemini"
"$HOME/.local/bin/agy"
```

Use Google OAuth with the personal account carrying the Google AI Pro student
offer. Enter login credentials or authorization codes only in the official
login flow. Trust only this workspace. Do not add the original checkout, home
or USB to the project.

Inspect /config and /permissions: request-review tool permission, non-workspace
access off, terminal sandbox enabled where supported. Do not select Turbo,
full-machine access, always-proceed or dangerously-skip-permissions. Inspect
/usage; set AI Credit Overages to Never / Use AI Credits off for subscription
quota-only use. Model availability and plan recognition must be checked on the
actual account. Ignore files and prose rules alone are not hard isolation from
approved shell commands; inspect requests for access outside the copy.

## 5. First prompt: Gemini Flash, read-only reconnaissance

Work only in ~/projects/threatfusion-gemini on branch gemini/product-20260924.
The original ~/projects/threatfusion is a preserved reference: do not access or
modify it. Read AGENTS.md, GEMINI.md, docs/product_charter.md,
docs/project_status.md, docs/issue_register.md and
docs/ai_handoff_2026-09-24.md. Verify current Git paths/HEAD and reconcile the
implemented, experimental, blocked and absent capabilities with source/contracts.
Read-only shell/git commands are allowed; do not run tests, code from the copied
.venv, models or demos. Explicitly distinguish the frozen Random Forest (product
inference path) from the v2 autoencoder (experimental/unfused path).
Inspect only relevant environment configuration/path metadata and tracked lock/install files. Do not read or expose private keys,
credentials, ignored data/model payloads or full raw reports. Identify copied
activation/entrypoint/editable-install references and runtime references into
the original folder. Report the exact baseline CI result only if verified.
The owner has reported an offline build of `threatfusion-venv` and three
passing focused unit tests, which do not validate the full product. Make no
file edits, installations, training, scoring, commits or pushes. Stop after
reporting evidence, blockers and the next concrete action.

## 6. Environment and product stages

Python virtual environments contain absolute paths and are not generally
portable: https://docs.python.org/3.11/library/venv.html . The owner reported
an offline build of `threatfusion-venv` and three passing focused unit tests.
Validate that the interpreter, threatfusion imports, editable installation
and new output paths resolve to the Gemini copy, not the original.
These tests do not validate the full product. Stop if frozen artifact identity
bindings cannot be preserved; never silently rewrite old manifests.

Then use an available Gemini Pro model to design the next bounded browser-safe
analyst UI milestone. Establish actor/session/origin/CSRF and failure contracts,
review the plan, implement a small scope, run meaningful focused tests, then
review before checkpointing. Do not train models or add product integrations
merely because they appear on the roadmap. Use Flash for routine doc/status work
and narrow edits after the contract is fixed; use Pro for authentication,
concurrency, architecture and scientific decisions. Model choice is a workflow
judgment, not a guarantee of correctness or quota cost.

Optional graphical surface: https://antigravity.google/download/linux has
Google's Ubuntu repository instructions. Install the GUI when wanted; open only
~/projects/threatfusion-gemini, choose Local Mode, keep review permissions and
Respect .gitignore enabled. Do not run GUI and CLI writers concurrently.
Gemini web chat may explain/review sanitized source and this handoff; it does
not automatically share local CLI context or the ChatGPT transcript. No need
for extra Google Cloud services, paid API integration, or project dependencies
just to use the coding subscription.

## 7. Ongoing backups and returning to Codex

Leave both original USB archives unchanged. After a reviewed milestone,
checkpoint the code on the Gemini branch. A local commit still lives on the
same SSD; arrange an explicitly authorized push of ONLY the Gemini branch and
verify its exact-SHA CI, or create a fresh dated USB snapshot. Ignored data,
models and evidence require a new file snapshot if they change; Git does not
back them up. Retain at least the original baseline and a recent verified
checkpoint. Use the existing project's source-comparison/SHA-256 procedure
with a new name; never overwrite the baseline. Stop writers while snapshotting.

At the end of each session, update a sanitized handoff with SHA, branch, files,
tests performed, remaining failures, generated artifacts, and next task. When
returning to Codex, open the Gemini directory and those current notes, and review
the delta before merging. Do not copy entire directories back over the original.
The USB snapshot is a last-resort recovery point, not a daily reset routine.

## 8. Windows space

Free space inside NTFS is not unallocated space available to ext4. Windows can
potentially be shrunk later, but current partition order, encryption, boot state
and both operating systems' backups must be reviewed first. Creating a separate
Linux data partition can be simpler than moving partitions to expand /home.
No partition resize/move/format command is authorized by this setup guide.
