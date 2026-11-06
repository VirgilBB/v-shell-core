import Foundation

// MARK: - Connection log (for support)

/// A small, redacted, on-device log of connection events. Nothing leaves the device unless the
/// user copies or emails the support report themselves. Never log passwords or private keys:
/// callers pass only our own event text, and `redact` masks addresses on the way in.
public final class SupportLog: @unchecked Sendable {
    public static let shared = SupportLog()
    public static let maxLines = 120

    private let lock = NSLock()
    private var lines: [String]
    private let defaults: UserDefaults?
    private let key = "supportLog.v1"

    public init(defaults: UserDefaults? = .standard) {
        self.defaults = defaults
        self.lines = defaults?.stringArray(forKey: key) ?? []
    }

    public func add(_ event: String, at date: Date = Date()) {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        let line = "\(f.string(from: date)) \(SupportLog.redact(event))"
        lock.lock()
        lines.append(line)
        if lines.count > Self.maxLines { lines.removeFirst(lines.count - Self.maxLines) }
        let snapshot = lines
        lock.unlock()
        defaults?.set(snapshot, forKey: key)
    }

    public var recent: [String] { lock.lock(); defer { lock.unlock() }; return lines }

    public func clear() {
        lock.lock(); lines.removeAll(); lock.unlock()
        defaults?.removeObject(forKey: key)
    }

    /// Masks IPv4 addresses (keeps the network kind) and anything after "password".
    public static func redact(_ s: String) -> String {
        var out = s
        if let re = try? NSRegularExpression(pattern: #"\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b"#) {
            let ns = out as NSString
            var result = ""
            var last = 0
            for m in re.matches(in: out, range: NSRange(location: 0, length: ns.length)) {
                result += ns.substring(with: NSRange(location: last, length: m.range.location - last))
                let ip = ns.substring(with: m.range)
                result += SupportLog.maskIP(ip)
                last = m.range.location + m.range.length
            }
            result += ns.substring(from: last)
            out = result
        }
        if let re = try? NSRegularExpression(pattern: #"(?i)(password|passwd|passphrase)\s*[:=]\s*\S+"#) {
            out = re.stringByReplacingMatches(in: out, range: NSRange(location: 0, length: (out as NSString).length),
                                              withTemplate: "$1=<hidden>")
        }
        return out
    }

    static func maskIP(_ ip: String) -> String {
        let p = ip.split(separator: ".")
        guard p.count == 4 else { return "<ip>" }
        let kind = NetworkHint.isTailscale(ip) ? "tailscale" : NetworkHint.isPrivateLAN(ip) ? "lan" : "public"
        return "\(p[0]).x.x.x(\(kind))"
    }
}

// MARK: - "Ask an AI" prompts

/// What the user is stuck on. Each one becomes a ready-to-paste prompt for ChatGPT, Claude, Gemini.
public enum HelpTopic: String, CaseIterable, Identifiable, Sendable {
    case setUpServer, fixError, addKey, tailscale, tmux

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .setUpServer: return "Set up my computer"
        case .fixError: return "Fix a connection error"
        case .addKey: return "My computer doesn't allow passwords"
        case .tailscale: return "Use it away from home"
        case .tmux: return "Keep sessions running"
        }
    }

    public var symbol: String {
        switch self {
        case .setUpServer: return "desktopcomputer"
        case .fixError: return "exclamationmark.triangle"
        case .addKey: return "key"
        case .tailscale: return "network"
        case .tmux: return "infinity"
        }
    }
}

/// Facts the app knows that make an AI's answer specific. Only non-secret values.
public struct HelpContext: Sendable, Equatable {
    public var serverKind: String?      // "Mac", "Linux", "Raspberry Pi", nil = unknown
    public var address: String?         // shown to the user's own AI; masked in support reports
    public var user: String?
    public var port: Int?
    public var lastError: String?
    public var devicePublicKey: String?
    public var appVersion: String
    public var deviceOS: String

    public init(serverKind: String? = nil, address: String? = nil, user: String? = nil, port: Int? = nil,
                lastError: String? = nil, devicePublicKey: String? = nil, appVersion: String = "1.0", deviceOS: String = "iOS") {
        self.serverKind = serverKind; self.address = address; self.user = user; self.port = port
        self.lastError = lastError; self.devicePublicKey = devicePublicKey; self.appVersion = appVersion; self.deviceOS = deviceOS
    }
}

public enum AIHelpPrompt {
    public static func make(_ topic: HelpTopic, _ c: HelpContext) -> String {
        if topic == .tailscale { return tailscaleWalkthrough(kind: c.serverKind) }
        var p: [String] = []
        p.append("I use v-Shell \(c.appVersion), an SSH terminal app on my \(c.deviceOS) device. Please be my patient step-by-step guide. Ask me one question at a time, give me exact commands to copy, and tell me what I should see after each one. I may not be technical.")
        p.append("")
        p.append("Rules: never ask me to paste a password, private key or recovery code into this chat. Only use commands that are safe and that you explain first.")
        p.append("")
        p.append("What I know:")
        p.append("- Computer type: \(c.serverKind ?? "not sure, help me find out")")
        if let a = c.address, !a.isEmpty { p.append("- Address I typed: \(a)\(c.port.map { $0 == 22 ? "" : ", port \($0)" } ?? "")") }
        if let u = c.user, !u.isEmpty { p.append("- User name: \(u)") }
        if let e = c.lastError, !e.isEmpty { p.append("- v-Shell said: \"\(e)\"") }
        p.append("")
        p.append("What I want:")
        switch topic {
        case .setUpServer:
            p.append("Get this computer ready so v-Shell can log in with a user name and password once. v-Shell then installs its own key and never needs the password again.")
            p.append("1. Turn on the SSH server (Mac: System Settings > General > Sharing > Remote Login; Linux: install and enable openssh-server).")
            p.append("2. Find the user name and the address to type into v-Shell.")
            p.append("3. Check the firewall allows SSH (port 22) on the home network. Never open it to the internet.")
            p.append("4. Optional: install tmux so sessions survive disconnects.")
        case .fixError:
            p.append("Find out why v-Shell can't connect and fix it. Check, in order: is the computer on and awake; is the SSH server running; is the address right and reachable from my phone's network (same Wi-Fi, or Tailscale on both); is the user name right; are password logins allowed; is a firewall blocking SSH on the home network.")
        case .addKey:
            p.append("My computer only accepts keys. Add this device's public key to ~/.ssh/authorized_keys for my user, from a computer that can already log in, with the right permissions (700 on ~/.ssh, 600 on the file). This is a public key, safe to share:")
            p.append(c.devicePublicKey ?? "(open v-Shell > Settings > This device's key, and copy it here)")
        case .tmux:
            p.append("Install tmux on my computer so long jobs and coding agents keep running when my phone disconnects. v-Shell re-attaches automatically to a tmux session named \"vshell\" when \"Keep sessions alive\" is on.")
        case .tailscale: break
        }
        p.append("")
        p.append("When we're done, give me the exact values to type into v-Shell's Add computer screen: address, user name, and port if it's not 22.")
        return p.joined(separator: "\n")
    }

    /// "Walk me through it": for a chat AI on the phone. No secrets, one step at a time.
    public static func tailscaleWalkthrough(kind: String?) -> String {
        let what: String
        switch kind {
        case "Mac": what = "Mac"
        case "Linux", "Raspberry Pi": what = "Linux computer"
        case "Windows": what = "Windows PC"
        default: what = "computer"
        }
        return """
        I use v-Shell, an SSH app on my iPhone. I want to reach my \(what) when I'm away from home, using Tailscale, without opening any ports on my router. Walk me through it one step at a time, and wait for me to say "done" before the next step:
        1. Install Tailscale on the computer and sign in.
        2. Install Tailscale on my iPhone from the App Store and sign in to the same account.
        3. Make sure SSH is on (on a Mac: System Settings > General > Sharing > Remote Login).
        4. Show me how to find the computer's Tailscale address. It starts with 100.
        Never ask me for passwords, sign-in codes or auth keys, and never tell me to paste them into this chat. At the end, tell me to open v-Shell > Add computer > Use Tailscale and type the 100.x address.
        """
    }

    /// "Do it for me": paste into Claude Code or another AI running on the computer itself.
    public static let tailscaleOnComputer = """
    Set up this computer so I can SSH to it from my iPhone over Tailscale.
    1. First only check and report: the OS, whether SSH is on, and whether Tailscale is installed and signed in (`tailscale status`; on a Mac the tool may be /Applications/Tailscale.app/Contents/MacOS/Tailscale).
    2. Show me your plan and ask before you install anything or run anything with sudo.
    3. Install Tailscale only from tailscale.com or the Mac App Store. Show me the sign-in link and I'll open it myself. Never create or print an auth key.
    4. Don't change my router or firewall, and don't expose port 22 to the internet.
    5. Finish by printing only: the output of `tailscale ip -4`, the output of `whoami`, and this line filled in:
       vshell://add?host=<100.x address>&user=<user>&port=22&name=<short hostname>
    """
}

// MARK: - Support report

public struct SupportReport: Sendable {
    public struct HostSummary: Sendable {
        public var label: String       // masked address kind, never the real name
        public var port: Int
        public var useTmux: Bool
        public var metrics: Int
        public init(label: String, port: Int, useTmux: Bool, metrics: Int) {
            self.label = label; self.port = port; self.useTmux = useTmux; self.metrics = metrics
        }
    }

    public var appVersion: String
    public var build: String
    public var deviceModel: String
    public var deviceOS: String
    public var plan: String
    public var hosts: [HostSummary]
    public var keyFingerprint: String?
    public var lastError: String?
    public var log: [String]

    public init(appVersion: String, build: String, deviceModel: String, deviceOS: String, plan: String,
                hosts: [HostSummary], keyFingerprint: String?, lastError: String?, log: [String]) {
        self.appVersion = appVersion; self.build = build; self.deviceModel = deviceModel; self.deviceOS = deviceOS
        self.plan = plan; self.hosts = hosts; self.keyFingerprint = keyFingerprint; self.lastError = lastError; self.log = log
    }

    /// A host's address reduced to what support needs: its kind, not the name or IP.
    public static func label(forAddress a: String) -> String {
        if NetworkHint.isTailscale(a) { return "tailscale" }
        if NetworkHint.isPrivateLAN(a) { return "lan" }
        if a.split(separator: ".").count == 4, a.allSatisfy({ $0.isNumber || $0 == "." }) { return "public-ip" }
        return "hostname"
    }

    public var text: String {
        var t: [String] = []
        t.append("v-Shell support report")
        t.append("app \(appVersion) (\(build)) · \(deviceModel) · \(deviceOS) · \(plan)")
        t.append("device key: \(keyFingerprint ?? "none yet")")
        if let e = lastError, !e.isEmpty { t.append("last error: \(SupportLog.redact(e))") }
        t.append("computers: \(hosts.count)")
        for (i, h) in hosts.enumerated() {
            t.append("  \(i + 1). \(h.label) port \(h.port) tmux \(h.useTmux ? "on" : "off") metrics \(h.metrics)")
        }
        t.append("log (newest last):")
        t.append(contentsOf: log.suffix(60).map { "  " + $0 })
        t.append("")
        t.append("No passwords, keys or computer addresses are included.")
        return t.joined(separator: "\n")
    }
}
