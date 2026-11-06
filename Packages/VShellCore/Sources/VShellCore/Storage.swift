import Foundation

/// Persists Codable values. File-backed in the app, in-memory in tests.
public protocol KeyValueBacking: AnyObject {
    func data(forKey key: String) -> Data?
    func set(_ data: Data?, forKey key: String)
}

public final class MemoryBacking: KeyValueBacking {
    private var store: [String: Data] = [:]
    public init() {}
    public func data(forKey key: String) -> Data? { store[key] }
    public func set(_ data: Data?, forKey key: String) { store[key] = data }
}

/// JSON files in a directory (Application Support in the app).
public final class FileBacking: KeyValueBacking {
    let dir: URL
    public init(directory: URL) {
        dir = directory
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }
    private func url(_ key: String) -> URL { dir.appendingPathComponent(key + ".json") }
    public func data(forKey key: String) -> Data? { try? Data(contentsOf: url(key)) }
    public func set(_ data: Data?, forKey key: String) {
        if let data { try? data.write(to: url(key), options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication]) }
        else { try? FileManager.default.removeItem(at: url(key)) }
    }
}

extension JSONEncoder {
    static let vshell: JSONEncoder = {
        let e = JSONEncoder(); e.dateEncodingStrategy = .iso8601; e.outputFormatting = [.sortedKeys]; return e
    }()
}
extension JSONDecoder {
    static let vshell: JSONDecoder = { let d = JSONDecoder(); d.dateDecodingStrategy = .iso8601; return d }()
}

public enum HostStoreError: Error, Equatable, LocalizedError {
    case limitReached(Int)
    case invalid(String)
    case duplicate
    case metricLimit(Int)
    public var errorDescription: String? {
        switch self {
        case .limitReached(let n): return "The free version keeps \(n) host. Unlock Pro for unlimited hosts."
        case .invalid(let m): return m
        case .duplicate: return "That host is already saved."
        case .metricLimit(let n): return "The free version keeps \(n) metrics. Unlock Pro for unlimited."
        }
    }
}

/// Hosts + snippets, ordered, persisted as JSON.
public final class HostStore {
    public private(set) var hosts: [Host]
    public private(set) var snippets: [Snippet]
    public private(set) var metrics: [Metric]
    private let backing: KeyValueBacking
    public var onChange: (() -> Void)?

    public init(backing: KeyValueBacking) {
        self.backing = backing
        hosts = backing.data(forKey: "hosts").flatMap { try? JSONDecoder.vshell.decode([Host].self, from: $0) } ?? []
        snippets = backing.data(forKey: "snippets").flatMap { try? JSONDecoder.vshell.decode([Snippet].self, from: $0) } ?? []
        metrics = backing.data(forKey: "metrics").flatMap { try? JSONDecoder.vshell.decode([Metric].self, from: $0) } ?? []
    }

    public func addMetric(_ m: Metric, entitlements: Entitlements) throws {
        if !entitlements.canAddMetric(currentCount: metrics.count) { throw HostStoreError.metricLimit(entitlements.maxMetrics ?? 0) }
        metrics.append(m); save()
    }
    public func updateMetric(_ m: Metric) {
        guard let i = metrics.firstIndex(where: { $0.id == m.id }) else { return }
        metrics[i] = m; save()
    }
    public func deleteMetric(id: UUID) { metrics.removeAll { $0.id == id }; save() }
    public func metrics(for host: UUID) -> [Metric] { metrics.filter { $0.hostID == host } }

    public func add(_ host: Host, entitlements: Entitlements) throws {
        if let m = host.validationError { throw HostStoreError.invalid(m) }
        if hosts.contains(where: { $0.hostname.lowercased() == host.hostname.lowercased() && $0.user == host.user && $0.port == host.port }) {
            throw HostStoreError.duplicate
        }
        if let max = entitlements.maxHosts, hosts.count >= max { throw HostStoreError.limitReached(max) }
        hosts.append(host); save()
    }

    public func update(_ host: Host) throws {
        if let m = host.validationError { throw HostStoreError.invalid(m) }
        guard let i = hosts.firstIndex(where: { $0.id == host.id }) else { return }
        hosts[i] = host; save()
    }

    public func delete(id: UUID) { hosts.removeAll { $0.id == id }; metrics.removeAll { $0.hostID == id }; save() }
    public func move(from: IndexSet, to: Int) {
        let moving = from.sorted().map { hosts[$0] }
        var rest = hosts.enumerated().filter { !from.contains($0.offset) }.map(\.element)
        let dest = to - from.filter { $0 < to }.count
        rest.insert(contentsOf: moving, at: max(0, min(dest, rest.count)))
        hosts = rest; save()
    }

    public func upsertSnippet(_ s: Snippet) {
        if let i = snippets.firstIndex(where: { $0.id == s.id }) { snippets[i] = s } else { snippets.append(s) }
        save()
    }
    public func deleteSnippet(id: UUID) { snippets.removeAll { $0.id == id }; save() }

    /// Merge hosts from another device (iCloud). Newer-by-id wins; nothing local is deleted.
    /// iCloud merge. Anything arriving from the cloud is treated as untrusted input: a synced entry
    /// can never carry something that runs by itself on a server (startup command), never points at
    /// another device's key, and synced snippets need a tap plus Return.
    public func merge(remoteHosts: [Host], remoteSnippets: [Snippet]) {
        for var h in remoteHosts where !hosts.contains(where: { $0.id == h.id }) {
            guard h.validationError == nil,
                  !hosts.contains(where: { $0.hostname.lowercased() == h.hostname.lowercased() && $0.user == h.user && $0.port == h.port }) else { continue }
            h.startupCommand = ""
            h.keyID = KeyManager.defaultKeyID
            hosts.append(h)
        }
        for var sn in remoteSnippets where !snippets.contains(where: { $0.id == sn.id }) {
            sn.runImmediately = false
            sn.command = ShellQuote.typeOnly(sn.command)   // no hidden Return / Ctrl keys inside
            sn.title = ShellQuote.typeOnly(sn.title)
            snippets.append(sn)
        }
        save()
    }

    public func exportJSON() -> Data { (try? JSONEncoder.vshell.encode(hosts)) ?? Data("[]".utf8) }
    public func exportSnippetsJSON() -> Data { (try? JSONEncoder.vshell.encode(snippets)) ?? Data("[]".utf8) }

    private func save() {
        backing.set(exportJSON(), forKey: "hosts")
        backing.set(exportSnippetsJSON(), forKey: "snippets")
        backing.set(try? JSONEncoder.vshell.encode(metrics), forKey: "metrics")
        onChange?()
    }
}
