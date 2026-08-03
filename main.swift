// TwoFA v4 — SMS 2FA auto-copy daemon (2FHey replacement, Apple Silicon)
//
// Watches ~/Library/Messages/chat.db for incoming 2FA codes, copies them to the
// clipboard, shows a bottom-left popup, and restores the previous clipboard after
// 15 seconds (only if the clipboard still holds our code).
//
// v4 fixes the mid-June 2026 breakage: macOS stopped populating message.text for
// SMS — the body now lives only in the attributedBody typedstream blob, which we
// decode here. Also drops immutable=1 (caused "database disk image is malformed"
// log storms) by opening the DB fresh on every poll.
//
// Env/flags:
//   TWOFA_DB=<path>          watch a different sqlite db (testing without FDA)
//   --parse-hex <file>       decode a hex-dumped attributedBody blob and exit
//   --test-popup             show the popup once and exit after 6s

import AppKit
import SQLite3

let home = FileManager.default.homeDirectoryForCurrentUser.path
let dbPath = ProcessInfo.processInfo.environment["TWOFA_DB"] ?? "\(home)/Library/Messages/chat.db"
let statePath = "\(home)/.cache/twofa-state.json"
let pollInterval: TimeInterval = 2.0
let clipboardRestoreDelay: TimeInterval = 15.0
let popupDuration: TimeInterval = 4.0
// Ignore messages older than this — prevents replaying a backlog of stale codes
// after a reboot or long sleep (v2 once pasted 7 old codes in one burst).
let maxMessageAge: TimeInterval = 180

func log(_ msg: String) {
    let ts = ISO8601DateFormatter().string(from: Date())
    FileHandle.standardOutput.write("[\(ts)] \(msg)\n".data(using: .utf8)!)
}

// MARK: - attributedBody (typedstream) decoding

/// Fallback: salvage the longest printable run from the blob.
func salvageText(_ bytes: [UInt8]) -> String? {
    var runs: [[UInt8]] = []
    var cur: [UInt8] = []
    for b in bytes {
        if b >= 0x20 && b != 0x7f { cur.append(b) }
        else if !cur.isEmpty { runs.append(cur); cur = [] }
    }
    if !cur.isEmpty { runs.append(cur) }
    let best = runs.max(by: { $0.count < $1.count })
    guard let best, best.count > 8 else { return nil }
    return String(bytes: best, encoding: .utf8)
}

func findSubsequence(_ haystack: [UInt8], _ needle: [UInt8], from: Int = 0) -> Int? {
    guard needle.count <= haystack.count else { return nil }
    for i in from...(haystack.count - needle.count) {
        if Array(haystack[i..<i+needle.count]) == needle { return i }
    }
    return nil
}

/// Decode the message text out of a legacy NSArchiver "streamtyped" blob.
/// Layout after the "NSString" class name: 0x01 0x94 0x84 0x01 0x2B ('+'),
/// then a length (1 byte, or 0x81 + uint16 LE, or 0x82 + uint32 LE), then UTF-8.
func decodeAttributedBody(_ data: Data) -> String? {
    let bytes = [UInt8](data)
    guard let ns = findSubsequence(bytes, Array("NSString".utf8)) else {
        return salvageText(bytes)
    }
    var plus: Int? = nil
    var j = ns + 8
    while j < min(ns + 24, bytes.count) {
        if bytes[j] == 0x2B { plus = j; break }
        j += 1
    }
    guard let p = plus, p + 1 < bytes.count else { return salvageText(bytes) }
    var len = 0
    var start = 0
    let b = bytes[p + 1]
    if b == 0x81, p + 3 < bytes.count {
        len = Int(bytes[p + 2]) | (Int(bytes[p + 3]) << 8)
        start = p + 4
    } else if b == 0x82, p + 5 < bytes.count {
        len = Int(bytes[p + 2]) | (Int(bytes[p + 3]) << 8) | (Int(bytes[p + 4]) << 16) | (Int(bytes[p + 5]) << 24)
        start = p + 6
    } else {
        len = Int(b)
        start = p + 2
    }
    guard len > 0, start + len <= bytes.count else { return salvageText(bytes) }
    return String(bytes: bytes[start..<start+len], encoding: .utf8) ?? salvageText(bytes)
}

// MARK: - 2FA detection

let keywordRegex = try! NSRegularExpression(
    pattern: "(?i)\\b(code|c[oó]digo|verification|verify|passcode|one[- ]?time|otp|2fa|security code|login|sign[- ]?in|authenticat)\\b")
let codeRegex = try! NSRegularExpression(
    pattern: "(?<![A-Za-z0-9/-])(?:[A-Z]-)?(\\d{4,8}|\\d{3}-\\d{3})(?![A-Za-z0-9/-])")
// Digits preceded by these are account numbers / money / dates, not codes.
let exclusionRegex = try! NSRegularExpression(
    pattern: "(?i)(ending in|acct|account|card|invoice|order|\\$|#|call |dial )\\s*[A-Z-]*$")

func extractCode(_ text: String) -> String? {
    let nsText = text as NSString
    let full = NSRange(location: 0, length: nsText.length)
    guard keywordRegex.firstMatch(in: text, range: full) != nil else { return nil }
    for m in codeRegex.matches(in: text, range: full) {
        let codeRange = m.range(at: 1)
        let ctxStart = max(0, m.range.location - 15)
        let context = nsText.substring(with: NSRange(location: ctxStart, length: m.range.location - ctxStart))
        if exclusionRegex.firstMatch(in: context, range: NSRange(location: 0, length: (context as NSString).length)) != nil {
            continue
        }
        let digits = nsText.substring(with: codeRange).filter(\.isNumber)
        // 4-digit years in sentences like "code expires 2026" are unlikely to lead
        if digits.count == 4, let n = Int(digits), (1990...2035).contains(n) { continue }
        return digits
    }
    return nil
}

// MARK: - Popup

final class Popup {
    static var current: NSPanel?

    static func show(code: String, sender: String) {
        current?.orderOut(nil)
        let width: CGFloat = 300, height: CGFloat = 68
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: width, height: height),
                            styleMask: [.nonactivatingPanel, .borderless],
                            backing: .buffered, defer: false)
        panel.level = .statusBar
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.ignoresMouseEvents = true
        panel.collectionBehavior = [.canJoinAllSpaces, .transient]
        panel.isReleasedWhenClosed = false

        let effect = NSVisualEffectView(frame: NSRect(x: 0, y: 0, width: width, height: height))
        effect.material = .hudWindow
        effect.state = .active
        effect.blendingMode = .behindWindow
        effect.wantsLayer = true
        effect.layer?.cornerRadius = 14

        let title = NSTextField(labelWithString: "\(code)  copied")
        title.font = .monospacedDigitSystemFont(ofSize: 20, weight: .semibold)
        title.textColor = .labelColor
        title.frame = NSRect(x: 18, y: 32, width: width - 36, height: 26)

        let sub = NSTextField(labelWithString: "from \(sender) · clipboard restores in 15s")
        sub.font = .systemFont(ofSize: 11)
        sub.textColor = .secondaryLabelColor
        sub.frame = NSRect(x: 18, y: 12, width: width - 36, height: 16)

        effect.addSubview(title)
        effect.addSubview(sub)
        panel.contentView = effect

        if let screen = NSScreen.main {
            let f = screen.visibleFrame
            panel.setFrameOrigin(NSPoint(x: f.minX + 16, y: f.minY + 16))
        }
        panel.alphaValue = 0
        panel.orderFrontRegardless()
        NSAnimationContext.runAnimationGroup { ctx in
            ctx.duration = 0.25
            panel.animator().alphaValue = 1
        }
        current = panel
        DispatchQueue.main.asyncAfter(deadline: .now() + popupDuration) { [weak panel] in
            guard let panel, panel === current else { return }
            NSAnimationContext.runAnimationGroup({ ctx in
                ctx.duration = 0.4
                panel.animator().alphaValue = 0
            }, completionHandler: {
                panel.orderOut(nil)
                if current === panel { current = nil }
            })
        }
    }
}

// MARK: - Clipboard

func copyCode(_ code: String) {
    let pb = NSPasteboard.general
    let saved = pb.string(forType: .string)
    pb.clearContents()
    pb.setString(code, forType: .string)
    let ourChange = pb.changeCount
    DispatchQueue.main.asyncAfter(deadline: .now() + clipboardRestoreDelay) {
        if pb.changeCount == ourChange {
            pb.clearContents()
            if let saved { pb.setString(saved, forType: .string) }
            log("Clipboard restored")
        }
    }
}

// MARK: - State

func loadLastRowId() -> Int64? {
    guard let data = FileManager.default.contents(atPath: statePath),
          let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let n = obj["lastRowId"] as? NSNumber else { return nil }
    return n.int64Value
}

func saveLastRowId(_ id: Int64) {
    let data = try! JSONSerialization.data(withJSONObject: ["lastRowId": id])
    try? data.write(to: URL(fileURLWithPath: statePath))
}

// MARK: - Database polling

var lastRowId: Int64 = -1
var lastErrorMsg = ""
var lastErrorLogged = Date.distantPast

func logDbError(_ msg: String) {
    // Rate-limit: identical errors at most once per 5 min (v3 once wrote 17k lines)
    if msg != lastErrorMsg || Date().timeIntervalSince(lastErrorLogged) > 300 {
        log("DB error: \(msg)")
        lastErrorMsg = msg
        lastErrorLogged = Date()
    }
}

let appleEpochOffset = Date(timeIntervalSince1970: 978307200) // 2001-01-01

func poll() {
    var db: OpaquePointer?
    guard sqlite3_open_v2(dbPath, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK, let db else {
        logDbError("cannot open \(dbPath)" + (db != nil ? ": \(String(cString: sqlite3_errmsg(db)))" : ""))
        if db != nil { sqlite3_close(db) }
        return
    }
    defer { sqlite3_close(db) }
    sqlite3_busy_timeout(db, 500)

    if lastRowId < 0 {
        // First run with no state: start from the newest message, don't replay history
        var stmt: OpaquePointer?
        if sqlite3_prepare_v2(db, "SELECT COALESCE(MAX(ROWID),0) FROM message", -1, &stmt, nil) == SQLITE_OK,
           sqlite3_step(stmt) == SQLITE_ROW {
            lastRowId = sqlite3_column_int64(stmt, 0)
            saveLastRowId(lastRowId)
            log("No saved state — starting from rowId \(lastRowId)")
        }
        sqlite3_finalize(stmt)
        return
    }

    let sql = """
        SELECT m.ROWID, m.text, m.attributedBody, m.date, COALESCE(h.id,'?')
        FROM message m LEFT JOIN handle h ON m.handle_id = h.ROWID
        WHERE m.ROWID > ? AND m.is_from_me = 0
        ORDER BY m.ROWID
        """
    var stmt: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
        logDbError(String(cString: sqlite3_errmsg(db)))
        return
    }
    defer { sqlite3_finalize(stmt) }
    sqlite3_bind_int64(stmt, 1, lastRowId)

    var newest = lastRowId
    while sqlite3_step(stmt) == SQLITE_ROW {
        let rowId = sqlite3_column_int64(stmt, 0)
        newest = max(newest, rowId)

        var body: String? = nil
        if let cText = sqlite3_column_text(stmt, 1) {
            body = String(cString: cText)
        }
        if body == nil || body!.isEmpty, sqlite3_column_type(stmt, 2) == SQLITE_BLOB {
            let n = Int(sqlite3_column_bytes(stmt, 2))
            if n > 0, let blob = sqlite3_column_blob(stmt, 2) {
                body = decodeAttributedBody(Data(bytes: blob, count: n))
            }
        }
        guard let text = body, !text.isEmpty else { continue }

        let dateNs = sqlite3_column_int64(stmt, 3)
        let msgDate = appleEpochOffset.addingTimeInterval(TimeInterval(dateNs) / 1_000_000_000)
        guard Date().timeIntervalSince(msgDate) < maxMessageAge else { continue }

        guard let code = extractCode(text) else { continue }
        let sender = String(cString: sqlite3_column_text(stmt, 4))
        log("✓ MATCH rowId=\(rowId) sender=\(sender) code=\(code)")
        copyCode(code)
        Popup.show(code: code, sender: sender)
    }
    if newest != lastRowId {
        lastRowId = newest
        saveLastRowId(newest)
    }
}

// MARK: - Entry point

setvbuf(stdout, nil, _IOLBF, 0)
let args = CommandLine.arguments

if let i = args.firstIndex(of: "--parse-hex"), i + 1 < args.count {
    let hex = (try! String(contentsOfFile: args[i + 1], encoding: .utf8))
        .trimmingCharacters(in: .whitespacesAndNewlines)
    var data = Data()
    var idx = hex.startIndex
    while idx < hex.endIndex {
        let next = hex.index(idx, offsetBy: 2)
        data.append(UInt8(hex[idx..<next], radix: 16)!)
        idx = next
    }
    if let text = decodeAttributedBody(data) {
        print("DECODED: \(text)")
        print("CODE: \(extractCode(text) ?? "<none>")")
    } else {
        print("DECODE FAILED")
    }
    exit(0)
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)

if args.contains("--test-popup") {
    DispatchQueue.main.async { Popup.show(code: "482913", sender: "TEST") }
    DispatchQueue.main.asyncAfter(deadline: .now() + 6) { exit(0) }
    app.run()
}

log("TwoFA v4 starting (pid \(ProcessInfo.processInfo.processIdentifier))")
lastRowId = loadLastRowId() ?? -1
log("Watching \(dbPath) every \(Int(pollInterval))s (from rowId \(lastRowId))")

let timer = Timer(timeInterval: pollInterval, repeats: true) { _ in poll() }
RunLoop.main.add(timer, forMode: .common)
poll()
app.run()
