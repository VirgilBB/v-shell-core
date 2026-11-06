import Foundation

/// A saved server. Passwords are never stored; auth is by device key.
public struct Host: Codable, Identifiable, Hashable, Sendable {
    public var id: UUID
    public var name: String
    public var hostname: String
    public var port: Int
    public var user: String
    /// Keychain label of the private key used for this host.
    public var keyID: String
    /// Run `tmux new -A -s <tmuxSession>` on connect (falls back to the login shell).
    public var useTmux: Bool
    public var tmuxSession: String
    /// Show tmux's own status line. Off by default: hidden (per session) when the server has no
    /// tmux config of its own, because first-time users can't tell what the green bar is.
    public var showTmuxStatus: Bool
    /// Optional command sent after the shell starts (e.g. `cd ~/code && claude`).
    public var startupCommand: String
    public var createdAt: Date
    /// Second address that works away from home (a Tailscale 100.x or *.ts.net name). Same computer,
    /// same pinned host key; tried first on cellular. nil = home address only.
    public var awayAddress: String?
    /// Shared hosting that refuses keys: v-Shell asks for the password on each connect and keeps it
    /// in memory for that session only. Never saved.
    public var passwordEachTime: Bool

    public init(id: UUID = UUID(), name: String = "", hostname: String, port: Int = 22,
                user: String, keyID: String = KeyManager.defaultKeyID, useTmux: Bool = true,
                tmuxSession: String = "vshell", showTmuxStatus: Bool = false,
                startupCommand: String = "", createdAt: Date = Date(), awayAddress: String? = nil, passwordEachTime: Bool = false) {
        self.id = id
        self.name = name.isEmpty ? hostname : name
        self.hostname = hostname
        self.port = port
        self.user = user
        self.keyID = keyID
        self.useTmux = useTmux
        self.tmuxSession = tmuxSession
        self.showTmuxStatus = showTmuxStatus
        self.startupCommand = startupCommand
        self.createdAt = createdAt
        self.awayAddress = awayAddress
        self.passwordEachTime = passwordEachTime
    }

    private enum CodingKeys: String, CodingKey {
        case id, name, hostname, port, user, keyID, useTmux, tmuxSession, showTmuxStatus, startupCommand, createdAt, awayAddress, passwordEachTime
    }

    /// Tolerant decoding: hosts saved by older versions lack newer fields.
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id)
        hostname = try c.decode(String.self, forKey: .hostname)
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? hostname
        port = try c.decodeIfPresent(Int.self, forKey: .port) ?? 22
        user = try c.decode(String.self, forKey: .user)
        keyID = try c.decodeIfPresent(String.self, forKey: .keyID) ?? KeyManager.defaultKeyID
        useTmux = try c.decodeIfPresent(Bool.self, forKey: .useTmux) ?? true
        tmuxSession = try c.decodeIfPresent(String.self, forKey: .tmuxSession) ?? "vshell"
        showTmuxStatus = try c.decodeIfPresent(Bool.self, forKey: .showTmuxStatus) ?? false
        startupCommand = try c.decodeIfPresent(String.self, forKey: .startupCommand) ?? ""
        createdAt = try c.decodeIfPresent(Date.self, forKey: .createdAt) ?? Date()
        awayAddress = try c.decodeIfPresent(String.self, forKey: .awayAddress)
        passwordEachTime = try c.decodeIfPresent(Bool.self, forKey: .passwordEachTime) ?? false
    }

    /// A public internet address (VPS, cloud, hosting): say "server", never mention Wi-Fi.
    public var isPublicAddress: Bool { NetworkHint.kind(of: hostname) == .publicAddress }
    /// "server" for public hosts, "computer" otherwise.
    public var noun: String { isPublicAddress ? "server" : "computer" }

    /// True when this computer can be reached away from home.
    public var worksAway: Bool { isPublicAddress || NetworkHint.isTailscale(hostname) || !(awayAddress ?? "").isEmpty }

    /// Addresses to try, in order. On cellular the home address can't work, so the away one goes
    /// first; on Wi-Fi home goes first (fast, no Tailscale needed).
    public func addresses(onCellular: Bool) -> [String] {
        guard let away = awayAddress, !away.isEmpty, away != hostname else { return [hostname] }
        return onCellular ? [away, hostname] : [hostname, away]
    }

    /// tmux session for the n-th tab (0-based) on this host: vshell, vshell-2, vshell-3...
    /// Separate tabs must not mirror one shared session.
    public func tmuxSessionName(tab n: Int) -> String { n == 0 ? tmuxSession : "\(tmuxSession)-\(n + 1)" }

    public var displayAddress: String { port == 22 ? "\(user)@\(hostname)" : "\(user)@\(hostname):\(port)" }
    public var sshURL: String { "ssh://\(user)@\(hostname)\(port == 22 ? "" : ":\(port)")" }

    /// Validation used by the add-host form. Returns a human message or nil.
    public var validationError: String? {
        if hostname.trimmingCharacters(in: .whitespaces).isEmpty { return "Enter a host name or IP address." }
        if hostname.contains(" ") { return "The host can't contain spaces." }
        if user.trimmingCharacters(in: .whitespaces).isEmpty { return "Enter the user name you log in with." }
        if !(1...65535).contains(port) { return "Port must be between 1 and 65535." }
        return nil
    }
}

public struct Snippet: Codable, Identifiable, Hashable, Sendable {
    public var id: UUID
    public var title: String
    public var command: String
    /// Send a trailing return after the command.
    public var runImmediately: Bool
    public init(id: UUID = UUID(), title: String, command: String, runImmediately: Bool = true) {
        self.id = id; self.title = title; self.command = command; self.runImmediately = runImmediately
    }
    public var payload: String { runImmediately ? command + "\r" : command }
}
