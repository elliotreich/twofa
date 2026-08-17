# TwoFA

A native macOS daemon that watches for incoming SMS 2FA codes and automatically copies them to your clipboard with a subtle notification. Built as an Apple Silicon replacement for [2FHey](https://github.com/structure/2FHey), which stopped working after Rosetta 2 was deprecated.

## What It Does

- Monitors `~/Library/Messages/chat.db` for incoming SMS messages
- Detects 2FA/verification codes using keyword + pattern matching
- Copies the code to your clipboard automatically
- Shows a bottom-left popup notification with the code and sender
- Restores your previous clipboard content after 15 seconds (if unchanged)
- Ignores messages older than 3 minutes to avoid replaying stale codes on wake/reboot

## Requirements

- macOS 13+ (Ventura or later)
- Apple Silicon (ARM64) — no Rosetta needed
- Xcode 16+ or Swift 6+ (for `swift build`)
- Full Disk Access permission for `~/Library/Messages/chat.db`

## Build & Run

```bash
# Clone
git clone https://github.com/elliotreich/twofa.git
cd twofa

# Build (SwiftPM — preferred)
swift build -c release
.build/release/twofa

# Or run directly (requires Full Disk Access)
swift run twofa

# Single-file alternative (no Package.swift needed)
swiftc -O -framework AppKit -framework SQLite3 -o twofa main.swift
./twofa
```

### Full Disk Access

The app needs Full Disk Access to read `~/Library/Messages/chat.db`:

1. System Settings → Privacy & Security → Full Disk Access
2. Add your terminal (or the built binary) and enable it
3. Restart the app

## How It Works

### Message Database Polling

The daemon polls the Messages SQLite database every 2 seconds, tracking the last seen `ROWID` to avoid reprocessing. On first run with no saved state, it starts from the newest message (no history replay).

### Attributed Body Decoding

Modern macOS stores SMS bodies in a binary `attributedBody` column (NSKeyedArchiver "streamtyped" format) rather than the plain `text` column. TwoFA decodes this format to extract the message text.

### 2FA Detection

Two-stage detection:
1. **Keyword match** — looks for terms like "code", "verification", "OTP", "passcode", "2FA", "login", "sign in", "authenticate" (multilingual)
2. **Code pattern** — extracts 4-8 digit codes or `XXX-XXX` patterns
3. **Exclusion filter** — ignores codes preceded by "ending in", "account", "card", "invoice", "order", "$", "#" (these are account numbers, not 2FA codes)

### Clipboard Management

- Saves your current clipboard before overwriting
- Restores it after 15 seconds *only if* the clipboard still contains the 2FA code
- Prevents clobbering something you intentionally copied after the code arrived

## Configuration (Environment Variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `TWOFA_DB` | `~/Library/Messages/chat.db` | Override database path (useful for testing) |

## Command Line Flags

| Flag | Description |
|------|-------------|
| `--parse-hex <file>` | Decode a hex-dumped `attributedBody` blob and exit |
| `--test-popup` | Show the popup once with a test code and exit after 6s |

## Tests

No automated test suite yet — verification is via real and synthetic `chat.db` files:

```bash
# Test attributedBody decoding from a hex dump
swift run twofa --parse-hex /path/to/blob.hex

# Test popup without needing an SMS
swift run twofa --test-popup

# Point at a synthetic DB (no FDA needed)
TWOFA_DB=/tmp/test.db swift run twofa
```

The core detection (keyword + code pattern + exclusion) is deliberately small and pure — a good candidate for future `swift test` coverage.

## Maintenance

- **State file:** `~/.cache/twofa-state.json` stores last-seen `ROWID`. Delete it to re-process from newest.
- **Launch at login:** copy `.build/release/twofa` to a fixed path and add a LaunchAgent plist with `RunAtLoad`.
- **Updates:** `git pull && swift build -c release` — no migrations.
- **Debugging:** logs go to stdout with ISO timestamps; DB errors are rate-limited to once per 5 min.

## Design Decisions

- **Accessory app** — runs as `NSApplicationActivationPolicy.accessory` (no Dock icon, no menubar)
- **No dependencies** — pure Swift + SQLite3, ~350 lines
- **Stateless polling** — opens DB fresh each poll (avoids "database disk image is malformed" errors from long-held connections)
- **Rate-limited error logging** — identical DB errors logged at most once per 5 minutes

## License

MIT License — see [LICENSE](LICENSE).

## Acknowledgments

Inspired by [2FHey](https://github.com/structure/2FHey) by Structure. TwoFA is a clean-room rewrite for Apple Silicon with modern macOS API support.
