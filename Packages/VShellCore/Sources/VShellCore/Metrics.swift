import Foundation

/// A user-defined value read from one of their servers by a read-only command.
public struct Metric: Codable, Identifiable, Hashable, Sendable {
    public enum Kind: String, Codable, CaseIterable, Sendable { case number, percent, text, status }

    public var id: UUID
    public var hostID: UUID
    public var title: String
    public var command: String
    public var kind: Kind
    public var unit: String
    public var warnAbove: Double?
    public var critAbove: Double?
    /// For "lower is worse" values (free space, days until TLS expiry).
    public var invert: Bool
    public var refreshSeconds: Int
    public var pinned: Bool
    /// One line shown under suggestions ("Shows free space so you know before it fills").
    public var why: String

    public init(id: UUID = UUID(), hostID: UUID, title: String, command: String, kind: Kind, unit: String = "",
                warnAbove: Double? = nil, critAbove: Double? = nil, invert: Bool = false,
                refreshSeconds: Int = 60, pinned: Bool = true, why: String = "") {
        self.id = id; self.hostID = hostID; self.title = title; self.command = command; self.kind = kind
        self.unit = unit; self.warnAbove = warnAbove; self.critAbove = critAbove; self.invert = invert
        self.refreshSeconds = refreshSeconds; self.pinned = pinned; self.why = why
    }
}

public enum MetricState: Equatable, Sendable { case ok, warn, crit, error }

public struct MetricReading: Equatable, Sendable {
    public var display: String
    public var number: Double?
    public var state: MetricState
    public var raw: String
    public var at: Date
    public init(display: String, number: Double?, state: MetricState, raw: String, at: Date) {
        self.display = display; self.number = number; self.state = state; self.raw = raw; self.at = at
    }
    public func isStale(refreshSeconds: Int, now: Date = Date()) -> Bool {
        now.timeIntervalSince(at) > Double(max(refreshSeconds, 15) * 2)
    }
}

public enum MetricParser {
    /// Turns command output into a reading. Exit status nil/0 = success.
    public static func read(_ m: Metric, output: String, status: Int?, at: Date = Date()) -> MetricReading {
        let lines = output.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        let last = lines.last ?? ""
        let ok = (status ?? 0) == 0
        switch m.kind {
        case .status:
            return MetricReading(display: ok ? (last.isEmpty ? "OK" : String(last.prefix(24))) : "DOWN",
                                 number: nil, state: ok ? .ok : .crit, raw: output, at: at)
        case .text:
            guard ok else { return error(output, at) }
            return MetricReading(display: String(last.prefix(60)), number: nil, state: .ok, raw: output, at: at)
        case .number, .percent:
            guard ok, let n = firstNumber(in: last) else { return error(output.isEmpty ? "no number in output" : output, at) }
            let shown = format(n) + (m.kind == .percent ? "%" : (m.unit.isEmpty ? "" : " " + m.unit))
            return MetricReading(display: shown, number: n, state: evaluate(n, m), raw: output, at: at)
        }
    }

    public static func evaluate(_ n: Double, _ m: Metric) -> MetricState {
        func past(_ t: Double?) -> Bool { guard let t else { return false }; return m.invert ? n <= t : n >= t }
        if past(m.critAbove) { return .crit }
        if past(m.warnAbove) { return .warn }
        return .ok
    }

    public static func firstNumber(in s: String) -> Double? {
        let pattern = #"-?\d+(?:[.,]\d+)?"#
        guard let r = s.range(of: pattern, options: .regularExpression) else { return nil }
        return Double(s[r].replacingOccurrences(of: ",", with: "."))
    }

    static func format(_ n: Double) -> String {
        if n == n.rounded() && abs(n) < 1e9 { return String(Int(n)) }
        return abs(n) < 10 ? String(format: "%.2f", n) : String(format: "%.1f", n)
    }

    static func error(_ out: String, _ at: Date) -> MetricReading {
        let first = out.split(whereSeparator: \.isNewline).first.map(String.init) ?? "failed"
        return MetricReading(display: "ERR", number: nil, state: .error, raw: String(first.prefix(120)), at: at)
    }
}

/// Metric commands must only read. Applied to AI suggestions and imported templates
/// (users may still write anything themselves, behind a warning).
///
/// Allowlist: a command passes only if every part is a known read-only tool used in a
/// read-only way. Built-in templates (reviewed code) are trusted as written, with the
/// domain names people are told to edit swapped out before comparing.
public enum CommandSafety {
    public static func isReadOnly(_ cmd: String) -> Bool {
        isBuiltIn(cmd) || problem(in: cmd) == nil
    }

    /// True for a built-in template (or the scan command), allowing edited domain names.
    public static func isBuiltIn(_ cmd: String) -> Bool {
        let c = normalised(cmd)
        return c == normalised(ServerScan.command) || MetricTemplate.all.contains { normalised($0.command) == c }
    }

    static func normalised(_ s: String) -> String {
        s.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: #"https?://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?"#, with: "URL", options: .regularExpression)
            .replacingOccurrences(of: #"\b[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+\b"#, with: "HOST", options: .regularExpression)
    }

    /// Why the command is not accepted, or nil when it only reads.
    public static func problem(in raw: String) -> String? {
        let cmd = raw.trimmingCharacters(in: .whitespaces)
        if cmd.isEmpty { return "empty" }
        if cmd.count > 400 { return "too long" }
        if cmd.unicodeScalars.contains(where: { $0.value < 0x20 && $0 != "\t" }) { return "control characters or several lines" }
        for bad in ["`", "$(", "${", "<(", ">(", ";", "<", "&>", ">>"] where cmd.contains(bad) { return "uses \(bad)" }
        let c = cmd.replacingOccurrences(of: "2>/dev/null", with: " ")
        if c.contains(">") { return "writes to a file" }
        guard let lists = split(c) else { return "unbalanced quotes or a shell feature v-Shell does not allow" }
        for pipeline in lists {
            for (i, words) in pipeline.enumerated() {
                if let p = check(words, piped: i > 0) { return p }
            }
        }
        return nil
    }

    // MARK: rules

    /// Read-only tools that may start a command.
    static let first: Set<String> = [
        "df", "du", "free", "uptime", "ps", "top", "vm_stat", "sysctl", "docker", "systemctl", "uname", "who", "w",
        "nproc", "sensors", "nvidia-smi", "zpool", "smartctl", "ip", "ss", "netstat", "curl", "date", "cat", "ls",
        "hostname", "whoami", "id", "getconf", "pgrep", "pidof", "pg_isready", "lsblk", "echo", "true", "find",
        "memory_pressure", "tmux", "tailscale",
    ]
    /// Text filters that may read a pipe.
    static let filters: Set<String> = ["grep", "egrep", "awk", "sed", "head", "tail", "wc", "sort", "uniq", "cut", "tr"]
    /// Named so the reason is clear; none of these are in the allowlist anyway.
    static let neverAllowed: Set<String> = [
        "rm", "mv", "cp", "dd", "chmod", "chown", "kill", "killall", "pkill", "sudo", "su", "doas", "eval", "exec",
        "sh", "bash", "zsh", "dash", "ksh", "fish", "python", "python3", "perl", "ruby", "node", "php", "lua", "tee",
        "rsync", "scp", "base64", "xargs", "env", "nohup", "wget", "nc", "ncat", "socat", "crontab", "shutdown",
        "reboot", "mkfs", "truncate", "ln", "install", "openssl", "source", ".",
    ]
    static let sensitive = [".ssh", "id_rsa", "id_ed25519", "id_ecdsa", "shadow", "sudoers", ".env", ".aws", ".netrc",
                            ".gnupg", ".kube", ".docker", "credential", "secret", "token", "password", "passwd",
                            "private", ".pem", ".key", "/root", "history", "keychain", ".config"]

    static func check(_ w: [String], piped: Bool) -> String? {
        var words = w
        while let a = words.first, a == "LC_ALL=C" || a == "LANG=C" { words.removeFirst() }
        guard let tool = words.first else { return "empty command" }
        let args = Array(words.dropFirst())
        if neverAllowed.contains(tool) { return "\(tool) is not allowed" }
        if tool.contains("/") || tool.contains("=") || tool.contains("$") { return "\(tool) is not a plain read-only tool" }
        guard filters.contains(tool) || (!piped && first.contains(tool)) else {
            return piped ? "\(tool) cannot read a pipe here" : "\(tool) is not on the read-only list"
        }
        for a in args {
            let l = a.lowercased()
            if let s = sensitive.first(where: { l.contains($0) }) { return "reads a private path (\(s))" }
            if a.hasPrefix("#") { return "comments are not allowed" }
        }
        let flags = args.filter { $0.hasPrefix("-") }
        let plain = args.filter { !$0.hasPrefix("-") }
        switch tool {
        case "top":
            guard args.contains("-bn1") || (args.contains("-b") && args.contains("-n")) || args.contains("-l") else { return "top must run once (top -bn1)" }
        case "sysctl":
            if args.contains("-w") || args.contains(where: { $0.contains("=") }) { return "sysctl may only read" }
        case "docker":
            guard let sub = plain.first, ["ps", "stats", "inspect", "info", "version", "images"].contains(sub) else { return "docker may only ps, stats, inspect" }
            if sub == "stats", !args.contains("--no-stream") { return "docker stats needs --no-stream" }
        case "systemctl":
            if let sub = plain.first, !["is-active", "is-enabled", "is-failed", "status", "list-units", "show"].contains(sub) { return "systemctl may only check status" }
        case "nvidia-smi":
            if !args.allSatisfy({ $0.hasPrefix("--query-") || $0.hasPrefix("--format") || ["-q", "-L", "--list-gpus"].contains($0) }) { return "nvidia-smi may only query" }
        case "zpool":
            guard let sub = plain.first, ["status", "list"].contains(sub) else { return "zpool may only status or list" }
        case "smartctl":
            if !args.allSatisfy({ ["-H", "-A", "-i", "-a", "-x", "--health", "--attributes", "--info"].contains($0) || $0.hasPrefix("/dev/") }) { return "smartctl may only read health" }
        case "ip":
            if let bad = args.first(where: { ["add", "del", "delete", "set", "flush", "change", "replace", "append", "exec", "netns", "-batch", "-b", "-force"].contains($0) }) { return "ip \(bad) changes things" }
        case "ss":
            if args.contains(where: { $0 == "--kill" || ($0.hasPrefix("-") && !$0.hasPrefix("--") && $0.contains("K")) }) { return "ss -K closes connections" }
        case "curl":
            return curlProblem(args)
        case "tmux":
            guard let sub = plain.first, ["ls", "list-sessions", "list-windows", "has-session"].contains(sub) else { return "tmux may only list" }
        case "tailscale":
            guard let sub = plain.first, ["status", "ip", "version", "ping"].contains(sub) else { return "tailscale may only report status" }
        case "find":
            if let bad = args.first(where: { ["-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"].contains($0) }) { return "find \(bad) is not allowed" }
        case "awk":
            if args.contains(where: { $0 == "-f" || $0.hasPrefix("-f") }) { return "awk -f is not allowed" }
            if args.contains(where: { a in ["system", "getline", "|", "close(", "fflush"].contains { a.contains($0) } }) { return "awk may only print" }
        case "sed":
            return sedProblem(args)
        case "sort":
            if args.contains(where: { $0.hasPrefix("-o") || $0.hasPrefix("--output") || $0 == "-T" }) { return "sort -o writes a file" }
        case "uniq":
            if !plain.isEmpty { return "uniq may only read a pipe" }
        case "head", "tail":
            if flags.contains(where: { $0 == "-f" || $0 == "-F" || $0.hasPrefix("--follow") }) { return "tail -f never ends" }
        default: break
        }
        return nil
    }

    /// curl only as an HTTP status check: curl -s -o /dev/null -w '%{http_code}' https://...
    static func curlProblem(_ args: [String]) -> String? {
        var i = 0, url = 0, devnull = false, format = false
        while i < args.count {
            let a = args[i]
            let next = i + 1 < args.count ? args[i + 1] : nil
            switch a {
            case "-o", "--output":
                guard next == "/dev/null" else { return "curl may only discard the page (-o /dev/null)" }
                devnull = true; i += 2; continue
            case "-w", "--write-out":
                guard let n = next, !n.hasPrefix("@") else { return "curl -w needs a format" }
                format = true; i += 2; continue
            case "-m", "--max-time", "--connect-timeout":
                guard let n = next, Double(n) != nil else { return "curl timeout must be a number" }
                i += 2; continue
            case "--silent", "--show-error", "--fail", "--head", "--location", "--insecure": i += 1; continue
            default: break
            }
            if a.hasPrefix("-"), !a.hasPrefix("--"), a.count > 1, a.dropFirst().allSatisfy({ "sSfILk".contains($0) }) { i += 1; continue }
            if a.hasPrefix("http://") || a.hasPrefix("https://") { url += 1; i += 1; continue }
            return "curl \(a) is not allowed in a check"
        }
        return (url == 1 && devnull && format) ? nil : "curl may only check a website's status"
    }

    /// sed only as a filter: substitutions, line printing, deleting or quitting. Never -i, w, e or r.
    static func sedProblem(_ args: [String]) -> String? {
        var scripts: [String] = []
        var i = 0, sawScript = false
        while i < args.count {
            let a = args[i]
            if a == "-e", i + 1 < args.count { scripts.append(args[i + 1]); sawScript = true; i += 2; continue }
            if ["-n", "-E", "-r", "-u", "--quiet", "-nE", "-En", "-nr", "-rn"].contains(a) { i += 1; continue }
            if a.hasPrefix("-") { return "sed \(a) is not allowed" }
            if !sawScript { scripts.append(a); sawScript = true }   // later plain words are input files
            i += 1
        }
        guard !scripts.isEmpty else { return "sed needs a script" }
        for s in scripts where !sedScriptIsSafe(s) { return "sed script may change files or run commands" }
        return nil
    }

    static func sedScriptIsSafe(_ s: String) -> Bool {
        if s.range(of: #"^((\d+|\$)(,(\d+|\$))?|/[^/]*/)?[pdq]$"#, options: .regularExpression) != nil { return true }
        guard s.hasPrefix("s"), s.count >= 4 else { return false }
        let chars = Array(s)
        let d = chars[1]
        if d == "\\" || d == "\n" || d.isLetter || d.isNumber { return false }
        var parts = 0, j = 2
        while j < chars.count && parts < 2 {
            if chars[j] == "\\" { j += 2; continue }
            if chars[j] == d { parts += 1 }
            j += 1
        }
        guard parts == 2 else { return false }
        return chars[j...].allSatisfy { "gIip0123456789".contains($0) }
    }

    /// Splits on && and || into pipelines, each a list of commands of dequoted words.
    /// Nil for anything outside the small grammar (subshells, background jobs, open quotes).
    static func split(_ s: String) -> [[[String]]]? {
        var lists: [[[String]]] = [], pipeline: [[String]] = [], words: [String] = []
        var word = "", inWord = false
        var quote: Character? = nil
        let cs = Array(s)
        var i = 0
        func endWord() { if inWord { words.append(word) }; word = ""; inWord = false }
        func endCommand() -> Bool { endWord(); if words.isEmpty { return false }; pipeline.append(words); words = []; return true }
        while i < cs.count {
            let ch = cs[i]
            if let q = quote {
                if ch == q { quote = nil }
                else if q == "\"" && ch == "\\" && i + 1 < cs.count { word.append(cs[i + 1]); i += 1 }
                else { word.append(ch) }
                i += 1; continue
            }
            switch ch {
            case "'", "\"": quote = ch; inWord = true
            case "\\":
                guard i + 1 < cs.count else { return nil }
                word.append(cs[i + 1]); inWord = true; i += 1
            case " ", "\t": endWord()
            case "|":
                if i + 1 < cs.count && cs[i + 1] == "|" {
                    guard endCommand() else { return nil }; lists.append(pipeline); pipeline = []; i += 1
                } else { guard endCommand() else { return nil } }
            case "&":
                guard i + 1 < cs.count && cs[i + 1] == "&" else { return nil }
                guard endCommand() else { return nil }; lists.append(pipeline); pipeline = []; i += 1
            case "(", ")": return nil
            default: word.append(ch); inWord = true
            }
            i += 1
        }
        if quote != nil { return nil }
        guard endCommand() else { return nil }
        lists.append(pipeline)
        return lists
    }
}
