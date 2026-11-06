import Foundation

/// Keys in the row above the on-screen keyboard.
public enum SmartKey: String, Codable, CaseIterable, Identifiable, Sendable {
    case esc, tab, ctrl, alt, up, down, left, right, pipe, tilde, slash, dash, paste, snippets
    /// Opens the Commands sheet (recent, saved, folders, learn). Words, not an icon: first-time
    /// users can't decode a lightning bolt.
    case commands
    /// Ctrl-C, named for what it does.
    case stop

    public var id: String { rawValue }
    public static let defaultOrder: [SmartKey] = [.commands, .stop, .tab, .esc, .up, .down, .ctrl, .left, .right, .tilde, .slash, .paste, .alt, .pipe, .dash]

    public var label: String {
        switch self {
        case .esc: return "esc"; case .tab: return "tab"; case .ctrl: return "ctrl"; case .alt: return "alt"
        case .up: return "↑"; case .down: return "↓"; case .left: return "←"; case .right: return "→"
        case .pipe: return "|"; case .tilde: return "~"; case .slash: return "/"; case .dash: return "-"
        case .paste: return "paste"; case .snippets: return "⚡︎"
        case .commands: return "Commands"; case .stop: return "Stop"
        }
    }
    public var isModifier: Bool { self == .ctrl || self == .alt }

    /// Bytes for plain keys. `applicationCursor` mirrors DECCKM (vim, less, claude).
    public func bytes(applicationCursor: Bool = false) -> [UInt8]? {
        let csi: [UInt8] = applicationCursor ? [0x1B, 0x4F] : [0x1B, 0x5B]
        switch self {
        case .esc: return [0x1B]
        case .tab: return [0x09]
        case .up: return csi + [0x41]
        case .down: return csi + [0x42]
        case .right: return csi + [0x43]
        case .left: return csi + [0x44]
        case .pipe: return Array("|".utf8)
        case .tilde: return Array("~".utf8)
        case .slash: return Array("/".utf8)
        case .dash: return Array("-".utf8)
        case .stop: return [0x03]
        case .ctrl, .alt, .paste, .snippets, .commands: return nil
        }
    }

    /// Ctrl+<char>: a-z and @[\]^_ map to 0x00-0x1F, ? maps to DEL.
    public static func control(_ c: Character) -> UInt8? {
        guard let a = c.lowercased().unicodeScalars.first?.value, c.unicodeScalars.count == 1 else { return nil }
        switch a {
        case 0x61...0x7A: return UInt8(a - 0x60)
        case 0x40, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F: return UInt8(a & 0x1F)
        case 0x20: return 0x00
        case 0x3F: return 0x7F
        default: return nil
        }
    }

    /// Alt = ESC prefix (xterm meta-sends-escape).
    public static func alt(_ bytes: [UInt8]) -> [UInt8] { [0x1B] + bytes }

    /// Persisted order from settings; unknown values dropped, missing keys appended.
    public static func order(from raw: [String]) -> [SmartKey] {
        var seen = Set<SmartKey>(); var out: [SmartKey] = []
        // Orders saved before Commands/Stop existed get them in front; the old snippets key is
        // replaced by Commands.
        let raw = raw.map { $0 == SmartKey.snippets.rawValue ? SmartKey.commands.rawValue : $0 }
        if !raw.isEmpty, !raw.contains(SmartKey.commands.rawValue) { out = [.commands, .stop]; seen = [.commands, .stop] }
        for r in raw { if let k = SmartKey(rawValue: r), !seen.contains(k) { out.append(k); seen.insert(k) } }
        for k in defaultOrder where !seen.contains(k) { out.append(k) }
        return out
    }
}
