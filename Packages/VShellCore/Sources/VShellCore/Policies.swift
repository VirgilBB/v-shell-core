import Foundation

/// Exponential backoff with a cap. Attempt 0 is immediate.
public struct ReconnectPolicy: Equatable, Sendable {
    public var base: Double = 0.5
    public var cap: Double = 15
    public var maxAttempts: Int = 12
    public init(base: Double = 0.5, cap: Double = 15, maxAttempts: Int = 12) {
        self.base = base; self.cap = cap; self.maxAttempts = maxAttempts
    }
    /// nil = give up and show the Reconnect button.
    public func delay(forAttempt n: Int) -> Double? {
        guard n < maxAttempts else { return nil }
        if n == 0 { return 0 }
        return min(cap, base * pow(2, Double(n - 1)))
    }
}

/// Ask for a rating only when things are going well.
public struct ReviewPolicy {
    let backing: KeyValueBacking
    public init(backing: KeyValueBacking) { self.backing = backing }
    public static let threshold = 3

    private func int(_ k: String) -> Int { backing.data(forKey: k).flatMap { Int(String(decoding: $0, as: UTF8.self)) } ?? 0 }
    private func setInt(_ k: String, _ v: Int) { backing.set(Data(String(v).utf8), forKey: k) }
    private func str(_ k: String) -> String? { backing.data(forKey: k).map { String(decoding: $0, as: UTF8.self) } }

    public var successes: Int { int("review.successes") }

    /// Call when a session ended cleanly or ran for 2+ minutes without error.
    /// Returns true when the app should call requestReview now.
    public func recordSuccess(appVersion: String, hadErrorThisSession: Bool) -> Bool {
        if hadErrorThisSession { return false }
        let n = successes + 1
        setInt("review.successes", n)
        guard n >= Self.threshold, str("review.askedVersion") != appVersion else { return false }
        backing.set(Data(appVersion.utf8), forKey: "review.askedVersion")
        return true
    }
}

/// Trust on first use for server host keys (like ~/.ssh/known_hosts).
public final class HostKeyTrust {
    public enum Verdict: Equatable { case trusted, firstUse, mismatch(expected: String) }
    let backing: KeyValueBacking
    private var table: [String: String]
    public init(backing: KeyValueBacking) {
        self.backing = backing
        table = backing.data(forKey: "known_hosts").flatMap { try? JSONDecoder().decode([String: String].self, from: $0) } ?? [:]
    }
    static func key(_ host: String, _ port: Int) -> String { "\(host.lowercased()):\(port)" }

    public func check(host: String, port: Int, fingerprint: String) -> Verdict {
        guard let known = table[Self.key(host, port)] else { return .firstUse }
        return known == fingerprint ? .trusted : .mismatch(expected: known)
    }
    public func trust(host: String, port: Int, fingerprint: String) {
        table[Self.key(host, port)] = fingerprint
        backing.set(try? JSONEncoder().encode(table), forKey: "known_hosts")
    }
    public func forget(host: String, port: Int) {
        table[Self.key(host, port)] = nil
        backing.set(try? JSONEncoder().encode(table), forKey: "known_hosts")
    }
}
