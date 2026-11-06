import Foundation

/// Watches server output for DECCKM (ESC[?1h / ESC[?1l) so the smart-key arrows send
/// the same bytes a hardware keyboard would. Survives sequences split across reads.
public struct ModeTracker: Sendable {
    public private(set) var applicationCursor = false
    private var tail: [UInt8] = []
    public init() {}

    static let set: [UInt8] = [0x1B, 0x5B, 0x3F, 0x31, 0x68]   // ESC [ ? 1 h
    static let reset: [UInt8] = [0x1B, 0x5B, 0x3F, 0x31, 0x6C] // ESC [ ? 1 l

    public mutating func feed(_ bytes: [UInt8]) {
        let data = tail + bytes
        var i = 0
        while i + 5 <= data.count {
            if data[i] == 0x1B && data[i + 1] == 0x5B && data[i + 2] == 0x3F && data[i + 3] == 0x31 {
                if data[i + 4] == 0x68 { applicationCursor = true }
                else if data[i + 4] == 0x6C { applicationCursor = false }
            }
            i += 1
        }
        tail = Array(data.suffix(4))
    }

    /// A reconnect starts a fresh remote program state.
    public mutating func reset() { applicationCursor = false; tail = [] }
}
