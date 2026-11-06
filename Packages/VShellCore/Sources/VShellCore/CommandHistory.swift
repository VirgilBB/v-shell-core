import Foundation

/// Commands v-Shell itself sent to a server (from Saved, Learn, Recent). Never keystrokes: over
/// SSH a password prompt looks like any other prompt, so typed text is never recorded.
/// On this device only, never synced. At most `limit` per server, newest first, no duplicates.
public final class CommandHistory: @unchecked Sendable {
    public static let limit = 200
    private let defaults: UserDefaults
    private let lock = NSLock()

    public init(defaults: UserDefaults = .standard) { self.defaults = defaults }

    private func key(_ host: UUID) -> String { "history.\(host.uuidString)" }

    public func recent(for host: UUID) -> [String] {
        lock.lock(); defer { lock.unlock() }
        return defaults.stringArray(forKey: key(host)) ?? []
    }

    /// `cursorLine` is the text on the terminal's cursor line when the command was sent; nothing
    /// is recorded at a password-style prompt.
    public func record(_ command: String, host: UUID, cursorLine: String = "") {
        let c = command.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !c.isEmpty, !CommandHistory.looksLikeSecretPrompt(cursorLine) else { return }
        lock.lock(); defer { lock.unlock() }
        var list = defaults.stringArray(forKey: key(host)) ?? []
        list.removeAll { $0 == c }
        list.insert(c, at: 0)
        if list.count > Self.limit { list = Array(list.prefix(Self.limit)) }
        defaults.set(list, forKey: key(host))
    }

    public func remove(_ command: String, host: UUID) {
        lock.lock(); defer { lock.unlock() }
        var list = defaults.stringArray(forKey: key(host)) ?? []
        list.removeAll { $0 == command }
        defaults.set(list, forKey: key(host))
    }

    public func clear(host: UUID) {
        lock.lock(); defer { lock.unlock() }
        defaults.removeObject(forKey: key(host))
    }

    public static func looksLikeSecretPrompt(_ line: String) -> Bool {
        line.range(of: #"(?i)(password|passphrase|passcode|pin|token|secret)[^:]*:\s*$"#, options: .regularExpression) != nil
    }
}

/// Beginner cheat sheet. Tapping types the command; nothing runs until the user presses return.
public enum LearnCommands {
    public struct Item: Identifiable, Hashable, Sendable {
        public let command: String
        public let meaning: String
        public var id: String { command }
    }
    public static let all: [Item] = [
        Item(command: "ls", meaning: "List files here"),
        Item(command: "cd ", meaning: "Go into a folder (type its name)"),
        Item(command: "cd ..", meaning: "Go up a folder"),
        Item(command: "cd ~", meaning: "Go to your home folder"),
        Item(command: "pwd", meaning: "Where am I?"),
        Item(command: "clear", meaning: "Clear the screen"),
        Item(command: "claude", meaning: "Start Claude Code in this folder"),
        Item(command: "codex", meaning: "Start Codex in this folder"),
        Item(command: "git status", meaning: "What changed in this project"),
        Item(command: "open .", meaning: "Mac: show this folder in Finder"),
        Item(command: "exit", meaning: "Log out of this shell"),
    ]
}
