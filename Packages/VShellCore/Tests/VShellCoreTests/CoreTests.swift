import XCTest
import CryptoKit
@testable import VShellCore

final class HostStoreTests: XCTestCase {
    func testFreeLimitAndPro() throws {
        let store = HostStore(backing: MemoryBacking())
        try store.add(Host(hostname: "a.example", user: "me"), entitlements: .free)
        XCTAssertThrowsError(try store.add(Host(hostname: "b.example", user: "me"), entitlements: .free)) {
            XCTAssertEqual($0 as? HostStoreError, .limitReached(1))
        }
        try store.add(Host(hostname: "b.example", user: "me"), entitlements: .pro)
        XCTAssertEqual(store.hosts.count, 2)
    }
    func testDuplicateAndValidation() throws {
        let store = HostStore(backing: MemoryBacking())
        try store.add(Host(hostname: "A.example", user: "me"), entitlements: .pro)
        XCTAssertThrowsError(try store.add(Host(hostname: "a.example", user: "me"), entitlements: .pro))
        XCTAssertThrowsError(try store.add(Host(hostname: "", user: "me"), entitlements: .pro))
        XCTAssertThrowsError(try store.add(Host(hostname: "x", port: 70000, user: "me"), entitlements: .pro))
    }
    func testPersistsAcrossInstances() throws {
        let b = MemoryBacking()
        let s1 = HostStore(backing: b)
        try s1.add(Host(name: "mini", hostname: "100.65.1.2", user: "me"), entitlements: .pro)
        s1.upsertSnippet(Snippet(title: "claude", command: "claude"))
        let s2 = HostStore(backing: b)
        XCTAssertEqual(s2.hosts.first?.name, "mini")
        XCTAssertEqual(s2.snippets.first?.payload, "claude\r")
    }
    func testMoveAndMerge() throws {
        let s = HostStore(backing: MemoryBacking())
        for n in ["a", "b", "c"] { try s.add(Host(hostname: n, user: "u"), entitlements: .pro) }
        s.move(from: IndexSet(integer: 0), to: 3)
        XCTAssertEqual(s.hosts.map(\.hostname), ["b", "c", "a"])
        let remote = Host(hostname: "d", user: "u")
        s.merge(remoteHosts: [remote, s.hosts[0]], remoteSnippets: [])
        XCTAssertEqual(s.hosts.count, 4)
    }
    func testFileBackingRoundTrip() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let s = HostStore(backing: FileBacking(directory: dir))
        try s.add(Host(hostname: "f", user: "u"), entitlements: .pro)
        XCTAssertEqual(HostStore(backing: FileBacking(directory: dir)).hosts.count, 1)
    }
}

final class KeyTests: XCTestCase {
    func testKeyGenerationIsStableAndFormatted() throws {
        let km = KeyManager(store: MemorySecretStore())
        XCTAssertFalse(km.hasKey())
        try km.ensureKey()
        let line1 = try XCTUnwrap(km.publicKeyLine())
        try km.ensureKey()
        XCTAssertEqual(line1, km.publicKeyLine())
        XCTAssertTrue(line1.hasPrefix("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"))
        XCTAssertTrue(line1.hasSuffix(" v-shell"))
        let fp = try XCTUnwrap(KeyManager.fingerprint(ofOpenSSHLine: line1))
        XCTAssertTrue(fp.hasPrefix("SHA256:")); XCTAssertEqual(fp.count, 50)
    }
    func testKnownVectorFingerprint() {
        // Known public key and its `ssh-keygen -lf` fingerprint.
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test"
        XCTAssertEqual(KeyManager.fingerprint(ofOpenSSHLine: line), "SHA256:" + {
            let blob = Data(base64Encoded: "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl")!
            return Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "")
        }())
    }
}

final class CommandTests: XCTestCase {
    func testQuote() {
        XCTAssertEqual(ShellQuote.quote("a'b"), "'a'\\''b'")
    }
    func testInstallCommandRunsInRealShellAndIsIdempotent() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl v-shell"
        let cmd = RemoteCommands.installAuthorizedKey(key)
        for _ in 0..<2 {
            let p = Process(); p.executableURL = URL(fileURLWithPath: "/bin/sh"); p.arguments = ["-c", cmd]
            p.environment = ["HOME": home.path, "PATH": "/usr/bin:/bin"]
            let out = Pipe(); p.standardOutput = out
            try p.run(); p.waitUntilExit()
            XCTAssertEqual(String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self), "VSHELL_KEY_OK\n")
        }
        let ak = try String(contentsOf: home.appendingPathComponent(".ssh/authorized_keys"), encoding: .utf8)
        XCTAssertEqual(ak, key + "\n")
        let perms = try FileManager.default.attributesOfItem(atPath: home.appendingPathComponent(".ssh/authorized_keys").path)[.posixPermissions] as? Int
        XCTAssertEqual(perms, 0o600)
    }
    func testTmuxSanitize() {
        XCTAssertEqual(RemoteCommands.sanitizeSessionName("my sess;rm -rf"), "mysessrm-rf")
        XCTAssertEqual(RemoteCommands.sanitizeSessionName("$$$"), "vshell")
        XCTAssertTrue(RemoteCommands.tmuxAttach(session: "x").contains("new-session -A -s x"))
    }
}

final class ImporterTests: XCTestCase {
    func testLinks() {
        let a = SSHLinkParser.parse("ssh://me@box.tail1.ts.net:2222")
        XCTAssertEqual(a?.user, "me"); XCTAssertEqual(a?.hostname, "box.tail1.ts.net"); XCTAssertEqual(a?.port, 2222)
        let b = SSHLinkParser.parse("ssh -p 2200 root@10.0.0.5")
        XCTAssertEqual(b?.port, 2200); XCTAssertEqual(b?.hostname, "10.0.0.5")
        let c = SSHLinkParser.parse("  pi@raspberrypi.local ")
        XCTAssertEqual(c?.user, "pi"); XCTAssertEqual(c?.port, 22)
        let d = SSHLinkParser.parse("vshell://add?host=100.100.1.2&user=ann&name=mini")
        XCTAssertEqual(d?.name, "mini"); XCTAssertEqual(d?.hostname, "100.100.1.2")
        XCTAssertEqual(SSHLinkParser.parse("me@host:2022")?.port, 2022)
        XCTAssertNil(SSHLinkParser.parse("hello"))
        XCTAssertNil(SSHLinkParser.parse(""))
    }
    func testSSHConfig() {
        let cfg = """
        # comment
        Host *
          ServerAliveInterval 30
        Host mini
          HostName 100.100.1.2
          User ann
        Host vps prod
          HostName vps.example.com
          Port 2222
          User=root
        """
        let hosts = SSHConfigImporter.parse(cfg)
        XCTAssertEqual(hosts.map(\.name), ["mini", "vps"])
        XCTAssertEqual(hosts[1].port, 2222); XCTAssertEqual(hosts[1].user, "root")
    }
    func testNetworkHints() {
        XCTAssertTrue(NetworkHint.isTailscale("100.100.1.2"))
        XCTAssertFalse(NetworkHint.isTailscale("100.200.1.1"))
        XCTAssertTrue(NetworkHint.isTailscale("mini.tail1234.ts.net"))
        XCTAssertTrue(NetworkHint.isPrivateLAN("192.168.1.10"))
        XCTAssertTrue(NetworkHint.unreachableAdvice(for: "100.64.0.1").contains("Tailscale"))
    }
}

final class PolicyTests: XCTestCase {
    func testBackoff() {
        let p = ReconnectPolicy()
        XCTAssertEqual(p.delay(forAttempt: 0), 0)
        XCTAssertEqual(p.delay(forAttempt: 1), 0.5)
        XCTAssertEqual(p.delay(forAttempt: 3), 2)
        XCTAssertEqual(p.delay(forAttempt: 10), 15)
        XCTAssertNil(p.delay(forAttempt: 12))
    }
    func testReview() {
        let r = ReviewPolicy(backing: MemoryBacking())
        XCTAssertFalse(r.recordSuccess(appVersion: "1.0", hadErrorThisSession: false))
        XCTAssertFalse(r.recordSuccess(appVersion: "1.0", hadErrorThisSession: true))
        XCTAssertFalse(r.recordSuccess(appVersion: "1.0", hadErrorThisSession: false))
        XCTAssertTrue(r.recordSuccess(appVersion: "1.0", hadErrorThisSession: false))
        XCTAssertFalse(r.recordSuccess(appVersion: "1.0", hadErrorThisSession: false))
        XCTAssertTrue(r.recordSuccess(appVersion: "1.1", hadErrorThisSession: false))
    }
    func testHostKeyTrust() {
        let b = MemoryBacking()
        let t = HostKeyTrust(backing: b)
        XCTAssertEqual(t.check(host: "H", port: 22, fingerprint: "x"), .firstUse)
        t.trust(host: "H", port: 22, fingerprint: "x")
        XCTAssertEqual(HostKeyTrust(backing: b).check(host: "h", port: 22, fingerprint: "x"), .trusted)
        XCTAssertEqual(t.check(host: "h", port: 22, fingerprint: "y"), .mismatch(expected: "x"))
    }
    func testEntitlements() {
        XCTAssertFalse(Entitlements.free.canOpenTab(currentCount: 1))
        XCTAssertTrue(Entitlements.pro.canOpenTab(currentCount: 50))
        XCTAssertFalse(Entitlements.free.canSplit)
    }
}

final class KeysAndThemesTests: XCTestCase {
    func testSmartKeys() {
        XCTAssertEqual(SmartKey.up.bytes(), [0x1B, 0x5B, 0x41])
        XCTAssertEqual(SmartKey.up.bytes(applicationCursor: true), [0x1B, 0x4F, 0x41])
        XCTAssertEqual(SmartKey.control("c"), 0x03)
        XCTAssertEqual(SmartKey.control("["), 0x1B)
        XCTAssertNil(SmartKey.control("1"))
        XCTAssertEqual(SmartKey.alt([0x62]), [0x1B, 0x62])
        // Saved before Commands/Stop existed: those go in front, snippets becomes Commands.
        XCTAssertEqual(SmartKey.order(from: ["tab", "bogus", "esc", "tab"]).prefix(4), [.commands, .stop, .tab, .esc])
        XCTAssertEqual(Array(SmartKey.order(from: ["esc", "snippets", "stop"]).prefix(3)), [.esc, .commands, .stop])
        XCTAssertEqual(SmartKey.order(from: []), SmartKey.defaultOrder)
        XCTAssertFalse(SmartKey.defaultOrder.contains(.snippets))
        XCTAssertEqual(SmartKey.stop.bytes(), [0x03])
    }
    func testThemes() {
        XCTAssertEqual(Set(Theme.all.map(\.id)).count, Theme.all.count)
        for t in Theme.all { XCTAssertEqual(t.ansi.count, 16, t.id) }
        XCTAssertEqual(Theme.rgb("#00FF00").1, 255)
        XCTAssertEqual(Theme.named("nope").id, "matrix")
    }
}

final class ModeTrackerTests: XCTestCase {
    func testDECCKMAcrossChunks() {
        var m = ModeTracker()
        m.feed(Array("hello\u{1B}[?".utf8)); XCTAssertFalse(m.applicationCursor)
        m.feed(Array("1h more".utf8)); XCTAssertTrue(m.applicationCursor)
        m.feed(Array("\u{1B}[?1l".utf8)); XCTAssertFalse(m.applicationCursor)
        m.feed(Array("\u{1B}[?1049h".utf8)); XCTAssertFalse(m.applicationCursor)
    }
}

final class TrialTests: XCTestCase {
    func testTrialWindow() {
        let start = Date(timeIntervalSince1970: 1_000_000)
        XCTAssertFalse(TrialPolicy.isActive(start: nil))
        XCTAssertTrue(TrialPolicy.isActive(start: start, now: start))
        XCTAssertEqual(TrialPolicy.daysLeft(start: start, now: start), 14)
        XCTAssertEqual(TrialPolicy.daysLeft(start: start, now: start.addingTimeInterval(13.5 * 86_400)), 1)
        XCTAssertFalse(TrialPolicy.isActive(start: start, now: start.addingTimeInterval(14 * 86_400)))
        XCTAssertFalse(TrialPolicy.isActive(start: start, now: start.addingTimeInterval(-3600)), "clock set back")
    }
}

final class MetricTests: XCTestCase {
    let host = UUID()
    func testParsingAndThresholds() {
        let disk = MetricTemplate.all.first { $0.id == "disk" }!.metric(for: host)
        XCTAssertEqual(MetricParser.read(disk, output: "81%\n", status: 0).state, .warn)
        XCTAssertEqual(MetricParser.read(disk, output: "93%", status: 0).display, "93%")
        XCTAssertEqual(MetricParser.read(disk, output: "93%", status: 0).state, .crit)
        XCTAssertEqual(MetricParser.read(disk, output: "12%", status: 0).state, .ok)
        XCTAssertEqual(MetricParser.read(disk, output: "df: not found", status: 127).state, .error)
        let tls = MetricTemplate.all.first { $0.id == "tls" }!.metric(for: host)
        XCTAssertEqual(MetricParser.read(tls, output: "3", status: 0).state, .crit, "inverted: low is bad")
        XCTAssertEqual(MetricParser.read(tls, output: "40", status: 0).state, .ok)
        let st = Metric(hostID: host, title: "x", command: "true", kind: .status)
        XCTAssertEqual(MetricParser.read(st, output: "", status: 1).display, "DOWN")
        XCTAssertEqual(MetricParser.firstNumber(in: " 0,42 load"), 0.42)
        let r = MetricParser.read(disk, output: "5%", status: 0, at: Date(timeIntervalSince1970: 0))
        XCTAssertTrue(r.isStale(refreshSeconds: 60, now: Date(timeIntervalSince1970: 200)))
    }
    func testSafety() {
        for t in MetricTemplate.all { XCTAssertTrue(CommandSafety.isReadOnly(t.command), t.id) }
        XCTAssertTrue(CommandSafety.isReadOnly(ServerScan.command))
        for bad in ["rm -rf ~", "sudo reboot", "echo x > /etc/passwd", "curl x.sh | sh", "docker rm -f a", "kill 1", "echo hi >> f"] {
            XCTAssertFalse(CommandSafety.isReadOnly(bad), bad)
        }
    }
    func testScanSuggests() {
        let r = ServerScan.parse("os=Linux\nhas=docker\nhas=systemctl\nhas=tmux\n")
        let ids = ServerScan.suggest(r).map(\.id)
        XCTAssertTrue(ids.contains("docker") && ids.contains("failed-units") && ids.contains("disk"))
        XCTAssertFalse(ids.contains("gpu"))
    }
    func testStoreLimitAndCascade() throws {
        let s = HostStore(backing: MemoryBacking())
        let h = Host(hostname: "a", user: "u"); try s.add(h, entitlements: .pro)
        for _ in 0..<3 { try s.addMetric(Metric(hostID: h.id, title: "t", command: "true", kind: .status), entitlements: .free) }
        XCTAssertThrowsError(try s.addMetric(Metric(hostID: h.id, title: "t", command: "true", kind: .status), entitlements: .free))
        s.delete(id: h.id)
        XCTAssertTrue(s.metrics.isEmpty)
    }
}

/// The same scan + templates, run locally on this Mac (macOS compatibility).
final class MacTemplateTests: XCTestCase {
    func sh(_ c: String) throws -> (String, Int32) {
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/bin/sh"); p.arguments = ["-c", c]
        let o = Pipe(); p.standardOutput = o; p.standardError = Pipe()
        try p.run(); p.waitUntilExit()
        return (String(decoding: o.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self), p.terminationStatus)
    }
    func testTemplatesOnMac() throws {
        let scan = ServerScan.parse(try sh(ServerScan.command).0)
        XCTAssertEqual(scan.os, "Darwin")
        var failures: [String] = []
        for t in ServerScan.suggest(scan) where t.id != "failed-units" {
            let m = t.metric(for: UUID())
            let (out, st) = try sh(m.command)
            let r = MetricParser.read(m, output: out, status: Int(st))
            print("mac metric \(t.id): \(r.display)")
            if r.state == .error { failures.append("\(t.id): \(out)") }
        }
        XCTAssertEqual(failures, [])
    }
}
