import Foundation

/// Built-in metrics. Commands are POSIX sh and work on Linux and macOS where noted.
public struct MetricTemplate: Identifiable, Hashable, Sendable {
    public let id: String
    public let group: String
    public let title: String
    public let command: String
    public let kind: Metric.Kind
    public let unit: String
    public let warn: Double?
    public let crit: Double?
    public let invert: Bool
    public let why: String
    /// Probe keys from ServerScan that make this template relevant ("docker", "system" ...).
    public let needs: String

    public func metric(for host: UUID) -> Metric {
        Metric(hostID: host, title: title, command: command, kind: kind, unit: unit, warnAbove: warn, critAbove: crit,
               invert: invert, why: why)
    }

    static let P = "PATH=\"$PATH:/opt/homebrew/bin:/usr/local/bin:/usr/sbin:/sbin\"; "

    public static let all: [MetricTemplate] = [
        .init(id: "disk", group: "System", title: "Disk used /", command: "df -P / | awk 'NR==2{print $5}'",
              kind: .percent, unit: "%", warn: 80, crit: 90, invert: false, why: "Warns before your disk fills up.", needs: "system"),
        .init(id: "load", group: "System", title: "CPU busy",
              command: "n=$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu); uptime | awk -F'load average[s]*: ' '{print $2}' | cut -d, -f1 | tr -d ' ' | awk -v n=\"$n\" '{printf \"%d\\n\", $1*100/n}'",
              kind: .percent, unit: "%", warn: 100, crit: 200, invert: false, why: "How busy the server is, per CPU core (100% = fully busy).", needs: "system"),
        .init(id: "mem", group: "System", title: "Memory used",
              command: "if [ -r /proc/meminfo ]; then awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{printf \"%d\\n\",(t-a)*100/t}' /proc/meminfo; else memory_pressure 2>/dev/null | awk '/free percentage/{print 100-$5}'; fi",
              kind: .percent, unit: "%", warn: 85, crit: 95, invert: false, why: "Shows when memory is running out.", needs: "system"),
        .init(id: "uptime", group: "System", title: "Up for",
              command: "uptime | sed -E 's/.*up +//; s/, *[0-9]+ users?.*//; s/,.*load.*//'",
              kind: .text, unit: "", warn: nil, crit: nil, invert: false, why: "Tells you if it rebooted.", needs: "system"),
        .init(id: "temp", group: "System", title: "CPU temp",
              command: "cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null | awk '{print $1/1000}'",
              kind: .number, unit: "°C", warn: 70, crit: 82, invert: false, why: "Catches overheating (Raspberry Pi, mini PCs).", needs: "thermal"),
        .init(id: "docker", group: "Docker", title: "Containers running", command: P + "docker ps -q | wc -l",
              kind: .number, unit: "", warn: nil, crit: nil, invert: false, why: "How many containers are up.", needs: "docker"),
        .init(id: "docker-unhealthy", group: "Docker", title: "Unhealthy containers",
              command: P + "docker ps --filter health=unhealthy -q | wc -l",
              kind: .number, unit: "", warn: 1, crit: 2, invert: false, why: "Flags containers failing health checks.", needs: "docker"),
        .init(id: "failed-units", group: "Services", title: "Failed services", command: "systemctl --failed --no-legend 2>/dev/null | wc -l",
              kind: .number, unit: "", warn: 1, crit: 3, invert: false, why: "Any service that crashed.", needs: "systemd"),
        .init(id: "tmux", group: "Dev", title: "tmux sessions", command: P + "tmux ls 2>/dev/null | wc -l",
              kind: .number, unit: "", warn: nil, crit: nil, invert: false, why: "Sessions waiting for you.", needs: "tmux"),
        .init(id: "agents", group: "Dev", title: "AI agents running",
              command: "ps -A -o comm= | grep -Eic '(^|/)(claude|codex|aider|gemini)$' || true",
              kind: .number, unit: "", warn: nil, crit: nil, invert: false, why: "Claude Code / Codex / aider still working.", needs: "system"),
        .init(id: "updates", group: "System", title: "Updates waiting",
              command: "apt list --upgradable 2>/dev/null | grep -c upgradable || true",
              kind: .number, unit: "", warn: 20, crit: 60, invert: false, why: "Security updates you haven't installed.", needs: "apt"),
        .init(id: "tailscale", group: "Network", title: "Tailscale", command: P + "tailscale status --peers=false >/dev/null && echo online",
              kind: .status, unit: "", warn: nil, crit: nil, invert: false, why: "Is this server reachable from anywhere.", needs: "tailscale"),
        .init(id: "gpu", group: "System", title: "GPU used",
              command: P + "nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits | head -1",
              kind: .percent, unit: "%", warn: nil, crit: nil, invert: false, why: "GPU load for AI or transcoding.", needs: "nvidia"),
        .init(id: "web", group: "Web", title: "Website up",
              command: "curl -s -o /dev/null -m 8 -w '%{http_code}' https://example.com",
              kind: .number, unit: "", warn: 400, crit: 500, invert: false, why: "HTTP status of a site you run. Edit the URL.", needs: "curl"),
        .init(id: "tls", group: "Web", title: "TLS days left",
              command: "echo | openssl s_client -servername example.com -connect example.com:443 2>/dev/null | openssl x509 -noout -enddate | cut -d= -f2 | xargs -I{} sh -c 'echo $(( ($(date -d \"{}\" +%s 2>/dev/null || date -j -f \"%b %e %T %Y %Z\" \"{}\" +%s) - $(date +%s)) / 86400 ))'",
              kind: .number, unit: "days", warn: 14, crit: 5, invert: true, why: "Certificate expiry. Edit the domain.", needs: "openssl"),
        .init(id: "plex", group: "Home lab", title: "Plex running", command: "pgrep -f '[P]lex Media Server' >/dev/null && echo running",
              kind: .status, unit: "", warn: nil, crit: nil, invert: false, why: "Is Plex up.", needs: "plex"),
        .init(id: "pg", group: "Databases", title: "Postgres", command: P + "pg_isready -q && echo accepting",
              kind: .status, unit: "", warn: nil, crit: nil, invert: false, why: "Is the database accepting connections.", needs: "postgres"),
    ]

    public static var groups: [String] { var seen: [String] = []; for t in all where !seen.contains(t.group) { seen.append(t.group) }; return seen }
}

/// "Scan this server": one read-only command that reports what is installed.
public enum ServerScan {
    public static let command = """
    PATH="$PATH:/opt/homebrew/bin:/usr/local/bin:/usr/sbin:/sbin"; echo "os=$(uname -s)"; \
    for t in docker systemctl tmux tailscale nvidia-smi apt curl openssl pg_isready nginx caddy node python3 git; do \
    command -v $t >/dev/null 2>&1 && echo "has=$t"; done; \
    [ -r /sys/class/thermal/thermal_zone0/temp ] && echo has=thermal; \
    pgrep -f '[P]lex Media Server' >/dev/null 2>&1 && echo has=plex; true
    """

    public struct Result: Equatable, Sendable {
        public var os: String
        public var tools: Set<String>
        public var summary: String {
            "OS \(ServerScan.token(os, lowercase: true) ?? "unknown"); has " + tools.compactMap { ServerScan.token($0, lowercase: true) }.sorted().prefix(40).joined(separator: ", ")
        }
    }

    public static func parse(_ out: String) -> Result {
        var os = "unknown"; var tools = Set<String>()
        for line in out.split(whereSeparator: \.isNewline) {
            if line.hasPrefix("os="), let t = token(line.dropFirst(3)) { os = t }
            if line.hasPrefix("has="), tools.count < 40, let t = token(line.dropFirst(4)) { tools.insert(t) }
        }
        return Result(os: os, tools: tools)
    }

    /// The server writes these, and `summary` feeds them to the AI assistant: keep only
    /// [a-z0-9._-] (case kept when parsing, lowercased for the prompt), at most 40 characters.
    public static func token<S: StringProtocol>(_ raw: S, lowercase: Bool = false) -> String? {
        let allowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        let s = lowercase ? raw.lowercased() : String(raw)
        let t = String(s.filter { allowed.contains($0) }.prefix(40))
        return t.isEmpty ? nil : t
    }

    /// Templates that fit this server, in library order.
    public static func suggest(_ r: Result) -> [MetricTemplate] {
        let keys = r.tools.union(["system"]).union(r.tools.contains("systemctl") ? ["systemd"] : [])
            .union(r.tools.contains("nvidia-smi") ? ["nvidia"] : []).union(r.tools.contains("pg_isready") ? ["postgres"] : [])
        let base = ["disk", "load", "mem", "uptime", "temp", "docker", "docker-unhealthy", "failed-units", "tmux", "agents", "tailscale", "gpu", "plex", "pg", "updates"]
        return base.compactMap { id in MetricTemplate.all.first { $0.id == id } }.filter { keys.contains($0.needs) }
    }
}
