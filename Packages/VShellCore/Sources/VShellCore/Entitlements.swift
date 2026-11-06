import Foundation

public enum Tier: String, Codable, Sendable { case free, pro }

/// Everything the free/pro split decides, in one place.
public struct Entitlements: Equatable, Sendable {
    public let tier: Tier
    public init(tier: Tier) { self.tier = tier }

    public static let free = Entitlements(tier: .free)
    public static let pro = Entitlements(tier: .pro)
    public static let productID = "vshell.pro"
    public static let trialProductID = "vshell.trial"

    public var isPro: Bool { tier == .pro }
    /// nil = unlimited
    public var maxHosts: Int? { isPro ? nil : 1 }
    public var maxTabs: Int? { isPro ? nil : 1 }
    public var canSplit: Bool { isPro }
    /// Saved commands: 3 free (a beginner saving `claude` must not hit a paywall), unlimited Pro.
    public var maxSavedCommands: Int? { isPro ? nil : 3 }
    public func canSaveCommand(currentCount: Int) -> Bool { maxSavedCommands.map { currentCount < $0 } ?? true }
    public var canSync: Bool { isPro }
    /// nil = unlimited
    public var maxMetrics: Int? { isPro ? nil : 3 }
    public func canAddMetric(currentCount: Int) -> Bool { maxMetrics.map { currentCount < $0 } ?? true }

    public func canOpenTab(currentCount: Int) -> Bool { maxTabs.map { currentCount < $0 } ?? true }
    public func canAddHost(currentCount: Int) -> Bool { maxHosts.map { currentCount < $0 } ?? true }
}

/// 14-day full-Pro trial, started by a $0 non-consumable purchase (App Store guideline 3.1.1).
/// The purchase date from StoreKit is the start, so reinstalling can't restart it.
public enum TrialPolicy {
    public static let days = 14

    public static func endDate(start: Date) -> Date { start.addingTimeInterval(Double(days) * 86_400) }

    public static func isActive(start: Date?, now: Date = Date()) -> Bool {
        guard let start else { return false }
        return now >= start.addingTimeInterval(-300) && now < endDate(start: start)
    }

    /// Whole days left, rounded up ("1 day left" on the last day).
    public static func daysLeft(start: Date?, now: Date = Date()) -> Int {
        guard let start, isActive(start: start, now: now) else { return 0 }
        return Int(ceil(endDate(start: start).timeIntervalSince(now) / 86_400))
    }
}
