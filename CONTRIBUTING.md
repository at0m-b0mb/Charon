# Contributing

Bug reports and patches are welcome.

## Getting set up

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
```

```bash
.venv/bin/python -m pytest
```

Run the app from the checkout with `.venv/bin/python run.py`.

## Regenerating the artwork

Both are generated, not hand-drawn, so they can be rebuilt at any size:

```bash
.venv/bin/python scripts/make_banner.py && .venv/bin/python scripts/capture_screenshots.py
```

The screenshot tool drives the real widget classes offscreen — if a pane is
broken it produces a broken picture, which is the point.

## House rules

**Security decisions live in one place.** Anything that decides whether a
connection may proceed belongs in `charon/core/policy.py` or
`charon/core/trust.py`, not in dialog code. A refusal spread across the UI is a
refusal that a later edit can quietly drop.

**No blocking dialogs on the worker thread.** Transports *raise* when they need
a trust decision; the GUI catches, prompts, pins, and retries. Please keep it
that way — a security prompt that can be opened from a background thread is one
that can be raced.

**Remote data is hostile.** Anything from a directory listing goes through
`charon/core/safety.py` before it becomes a local path.

**Be honest in the UI.** If Charon cannot verify something, it says so. Please
don't add a reassuring green tick for a check that did not actually happen.

**Tests for security behaviour go over the wire** where they can —
`tests/test_sftp_live.py` runs a real SSH server in-process. Mocking the thing
under test proves only that the mock behaves.

## Commits

Small, focused commits with a plain description of what changed and why.
