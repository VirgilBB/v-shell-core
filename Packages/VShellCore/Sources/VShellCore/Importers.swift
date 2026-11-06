import Foundation

/// Parses what people paste or scan: ssh://user@host:port, user@host, `ssh -p 2222 user@host`,
/// and QR payloads from server/setup.sh (vshell://add?host=..&user=..&port=..&name=..).
public enum SSHLinkParser {
    /// Host key fingerprint carried by a setup link (vshell://add?...&fp=SHA256:...), printed by
    /// setup.sh on the computer itself. Lets v-Shell verify the first connection with no prompt.
    public static func fingerprint(in raw: String) -> String? {
        guard raw.hasPrefix("vshell://"), let c = URLComponents(string: raw.trimmingCharacters(in: .whitespacesAndNewlines)),
              var fp = c.queryItems?.first(where: { $0.name == "fp" })?.value, fp.hasPrefix("SHA256:") else { return nil }
        fp = fp.replacingOccurrences(of: " ", with: "+")   // '+' read as a space in query strings
        return fp
    }

    /// `ssh -i key.pem ubuntu@host` from a provider's instructions: a key file is needed.
    public static func mentionsKeyFile(_ raw: String) -> Bool {
        raw.range(of: #"(^|\s)-i\s+\S+"#, options: .regularExpression) != nil
    }

    public static func parse(_ raw: String) -> Host? {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.isEmpty { return nil }

        if s.hasPrefix("vshell://") || s.hasPrefix("ssh://") {
            guard let c = URLComponents(string: s) else { return nil }
            let q = Dictionary((c.queryItems ?? []).map { ($0.name, $0.value ?? "") }, uniquingKeysWith: { a, _ in a })
            let host = (s.hasPrefix("vshell://") ? q["host"] : c.host) ?? ""
            let user = (s.hasPrefix("vshell://") ? q["user"] : c.user) ?? ""
            let port = (s.hasPrefix("vshell://") ? Int(q["port"] ?? "") : c.port) ?? 22
            guard !host.isEmpty, !user.isEmpty else { return nil }
            return Host(name: q["name"] ?? "", hostname: host, port: port, user: user)
        }

        // macOS Sharing > Remote Login shows a sentence: To log in to this computer remotely,
        // type "ssh ann@192.168.1.20". People copy all of it, with quotes and the full stop.
        s = s.replacingOccurrences(of: "\n", with: " ")
        for q in ["\u{201C}", "\u{201D}", "\u{2018}", "\u{2019}", "\"", "'", "`"] { s = s.replacingOccurrences(of: q, with: " ") }
        if !s.hasPrefix("ssh "), let r = s.range(of: #"(^|\s)ssh\s"#, options: [.regularExpression, .backwards]) {
            s = String(s[r.lowerBound...]).trimmingCharacters(in: .whitespaces)
        }

        // `ssh [-p N] user@host` or `user@host[:port]`
        var port = 22
        var tokens = s.split(separator: " ").map(String.init)
        if tokens.first == "ssh" { tokens.removeFirst() }
        var target: String?
        var i = 0
        while i < tokens.count {
            let t = tokens[i]
            if t == "-p", i + 1 < tokens.count { port = Int(tokens[i + 1]) ?? 22; i += 2; continue }
            if t.hasPrefix("-") { i += (t.count == 2 && i + 1 < tokens.count && "-i-l-o-F-J".contains(t)) ? 2 : 1; continue }
            if target == nil, t.contains("@") { target = t }  // the user@host word; ignore trailing words
            i += 1
        }
        guard var t = target?.trimmingCharacters(in: CharacterSet(charactersIn: ".,;:!?)")),
              let at = t.lastIndex(of: "@") else { return nil }
        let user = String(t[..<at]); t = String(t[t.index(after: at)...])
        if let colon = t.lastIndex(of: ":"), !t.contains("]"), t.filter({ $0 == ":" }).count == 1 {
            port = Int(t[t.index(after: colon)...]) ?? port; t = String(t[..<colon])
        }
        s = t.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        guard !user.isEmpty, !s.isEmpty else { return nil }
        return Host(hostname: s, port: port, user: user)
    }
}

/// Minimal ~/.ssh/config reader: Host, HostName, User, Port. Wildcard blocks are skipped.
public enum SSHConfigImporter {
    public static func parse(_ text: String, defaultUser: String = "") -> [Host] {
        var result: [Host] = []
        var alias: String?; var hostname: String?; var user: String?; var port = 22
        func flush() {
            if let a = alias, !a.contains("*"), !a.contains("?") {
                let h = Host(name: a, hostname: hostname ?? a, port: port, user: user ?? defaultUser)
                if h.validationError == nil { result.append(h) }
            }
            alias = nil; hostname = nil; user = nil; port = 22
        }
        for rawLine in text.components(separatedBy: .newlines) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            let parts = line.split(maxSplits: 1, whereSeparator: { $0 == " " || $0 == "\t" || $0 == "=" })
            guard parts.count == 2 else { continue }
            let key = parts[0].lowercased(); let value = parts[1].trimmingCharacters(in: .whitespaces)
            switch key {
            case "host": flush(); alias = value.split(separator: " ").first.map(String.init)
            case "hostname": hostname = value
            case "user": user = value
            case "port": port = Int(value) ?? 22
            default: break
            }
        }
        flush()
        return result
    }
}

public enum NetworkHint {
    /// Tailscale uses 100.64.0.0/10 and MagicDNS *.ts.net names.
    public static func isTailscale(_ host: String) -> Bool {
        let h = host.lowercased()
        if h.hasSuffix(".ts.net") { return true }
        let o = h.split(separator: ".").compactMap { Int($0) }
        guard o.count == 4, o.allSatisfy({ (0...255).contains($0) }) else { return false }
        return o[0] == 100 && (64...127).contains(o[1])
    }

    public enum Kind: Equatable { case home, tailscale, publicAddress, unknown }

    /// Home network, Tailscale, or the public internet. Empty or bare names ("mini") are unknown.
    public static func kind(of host: String) -> Kind {
        let h = host.trimmingCharacters(in: .whitespaces).lowercased()
        if h.isEmpty { return .unknown }
        if isTailscale(h) { return .tailscale }
        if isPrivateLAN(h) || h == "localhost" || h.hasPrefix("127.") || h.hasPrefix("169.254.") { return .home }
        if !h.contains(".") && !h.contains(":") { return .unknown }   // bare LAN name
        if h.hasSuffix(".lan") || h.hasSuffix(".home") || h.hasSuffix(".internal") || h.hasSuffix(".home.arpa") { return .home }
        return .publicAddress
    }

    public static func isPrivateLAN(_ host: String) -> Bool {
        let o = host.split(separator: ".").compactMap { Int($0) }
        guard o.count == 4 else { return host.lowercased().hasSuffix(".local") }
        return o[0] == 10 || (o[0] == 192 && o[1] == 168) || (o[0] == 172 && (16...31).contains(o[1]))
    }

    /// Text shown when a connection can't be made.
    public static func unreachableAdvice(for host: String) -> String {
        if isTailscale(host) { return "This is a Tailscale address. Check that Tailscale is connected on this device and on your computer, signed in to the same account." }
        if isPrivateLAN(host) { return "This is a home-network address. It only works on the same Wi-Fi as your computer. Away from home? Use Tailscale." }
        if kind(of: host) == .publicAddress { return "Check the address and port, that the server is running, and that your provider's firewall allows SSH." }
        return "Check the address, that your computer is on and awake, and that Remote Login (SSH) is on."
    }
}


/// Finds a computer's Tailscale address over an SSH session v-Shell already has. Read-only.
public enum TailscaleLookup {
    /// Works on Linux (tailscale on PATH) and the Mac App Store / standalone app.
    public static let command = #"for t in tailscale /Applications/Tailscale.app/Contents/MacOS/Tailscale /usr/local/bin/tailscale /opt/homebrew/bin/tailscale; do if command -v "$t" >/dev/null 2>&1 || [ -x "$t" ]; then "$t" ip -4 2>/dev/null && exit 0; fi; done; exit 127"#

    /// First Tailscale IPv4 address in the output, or nil.
    public static func parse(_ output: String) -> String? {
        output.split(whereSeparator: { $0 == "\n" || $0 == " " || $0 == "\r" })
            .map { String($0).trimmingCharacters(in: .whitespaces) }
            .first { NetworkHint.isTailscale($0) && $0.split(separator: ".").count == 4 }
    }
}

/// Guesses from what a computer calls itself on the network.
public enum ComputerHint {
    /// "Ann's Mac mini" -> "ann". Macs name themselves after the account owner, and the
    /// first name is often the account short name. Only ever offered as a suggestion, never filled.
    public static func userSuggestion(fromComputerName name: String) -> String? {
        guard let r = name.range(of: #"^(.+?)['\u{2019}]s "#, options: .regularExpression) else { return nil }
        var owner = String(name[r]).dropLast(3)  // drop "'s "
        owner = owner.split(separator: " ").first ?? owner
        let u = owner.lowercased().filter { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" || $0 == "." }
        return u.isEmpty ? nil : u
    }

    /// SF Symbol for a found computer, by its name.
    public static func symbol(forComputerName name: String) -> String {
        let n = name.lowercased()
        if n.contains("mac mini") { return "macmini" }
        if n.contains("macbook") || n.contains("laptop") { return "laptopcomputer" }
        if n.contains("imac") { return "desktopcomputer" }
        if n.contains("pi") || n.contains("raspberry") { return "cpu" }
        return "desktopcomputer"
    }
}
