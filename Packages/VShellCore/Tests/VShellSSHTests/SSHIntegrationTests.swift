import XCTest
import Crypto
@testable import VShellSSH
@testable import VShellCore

/// Runs against a throwaway sshd: scripts/test-sshd.sh starts it on 127.0.0.1:2222
/// (user vshell / password vshell-test). Skipped when it is not running.
final class SSHIntegrationTests: XCTestCase {
    let host = "127.0.0.1", port = 2222, user = "vshell", password = "vshell-test"

    /// What the app does on first contact: fetch the fingerprint, the user confirms it, then pin.
    func confirmedTrust(port p: Int? = nil) async throws -> HostKeyTrust {
        let t = HostKeyTrust(backing: MemoryBacking())
        let fp = try await SSHConnection.fetchFingerprint(host: host, port: p ?? port)
        XCTAssertTrue(fp.hasPrefix("SHA256:"))
        t.trust(host: host, port: p ?? port, fingerprint: fp)
        return t
    }

    /// No silent first-use trust: an unconfirmed server is refused before any password is sent.
    func testFirstUseIsNeverSilent() async throws {
        try requireServer()
        let t = HostKeyTrust(backing: MemoryBacking())
        let c = SSHConnection(host: host, port: port, user: user, auth: [.password(password)], hostKeyValidator: t.validator(host: host, port: port))
        do { try await c.connect(); XCTFail("must not log in to an unconfirmed server") }
        catch let e as SSHError { guard case .hostKeyUnconfirmed = e else { return XCTFail("\(e)") } }
        XCTAssertEqual(t.check(host: host, port: port, fingerprint: "x"), .firstUse, "nothing pinned")
    }

    func requireServer() throws {
        if ProcessInfo.processInfo.environment["VSHELL_SSHD"] == nil { throw XCTSkip("set VSHELL_SSHD=1 with scripts/test-sshd.sh running") }
    }

    func testWrongPassword() async throws {
        try requireServer()
        let c = SSHConnection(host: host, port: port, user: user, auth: [.password("nope")], hostKeyValidator: { _, _ in nil })
        do { try await c.connect(); XCTFail("should fail") }
        catch let e as SSHError { XCTAssertEqual(e, .authFailed(triedPassword: true)) }
    }

    /// macOS-style server: only publickey + keyboard-interactive. Setup must still work.
    func testKeyboardInteractiveOnlyServer() async throws {
        try requireServer()
        let methods = try sshMethods(port: 2223)
        XCTAssertTrue(methods.contains("keyboard-interactive") && !methods.contains("password"), methods)
        let trust = try await confirmedTrust(port: 2223)
        let key = Curve25519.Signing.PrivateKey()
        try await KeySetup.installKey(host: host, port: 2223, user: user, password: password, key: key,
                                      comment: "kbd", hostKeyValidator: trust.validator(host: host, port: 2223))
        let bad = SSHConnection(host: host, port: 2223, user: user, auth: [.password("wrong")], hostKeyValidator: { _, _ in nil })
        do { try await bad.connect(); XCTFail("wrong password must fail") }
        catch let e as SSHError { XCTAssertEqual(e, .authFailed(triedPassword: true)) }
    }

    /// A provider's ECDSA key file (imported, not v-Shell's own key) signs in.
    func testImportedECDSAKeyLogsIn() async throws {
        try requireServer()
        let trust = try await confirmedTrust()
        let imported = SigningKey.p256(P256.Signing.PrivateKey())
        // Put its public half on the server using a password session, as a provider would at creation.
        let pw = SSHConnection(host: host, port: port, user: user, auth: [.password(password)], hostKeyValidator: trust.validator(host: host, port: port))
        try await pw.connect()
        let (_, out) = try await pw.exec(RemoteCommands.installAuthorizedKey(imported.publicKeyLine(comment: "imported-test")))
        pw.close()
        XCTAssertTrue(out.contains("VSHELL_KEY_OK"))
        let c = SSHConnection(host: host, port: port, user: user, auth: [.signing(imported)], hostKeyValidator: trust.validator(host: host, port: port))
        try await c.connect()
        let (_, who) = try await c.exec("whoami")
        XCTAssertEqual(who.trimmingCharacters(in: .whitespacesAndNewlines), user)
        c.close()
    }

    /// What the server offers, via the system ssh client.
    func sshMethods(port: Int) throws -> String {
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
        p.arguments = ["-v", "-p", String(port), "-o", "BatchMode=yes", "-o", "PreferredAuthentications=none",
                       "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "vshell@127.0.0.1", "true"]
        let err = Pipe(); p.standardError = err; p.standardOutput = Pipe()
        try p.run(); p.waitUntilExit()
        let out = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        return out.components(separatedBy: "\n").first { $0.contains("can continue") } ?? out
    }

    /// Scan + every suggested template must produce a value on a real Linux box.
    func testScanAndTemplatesOnLinux() async throws {
        try requireServer()
        let key = Curve25519.Signing.PrivateKey()
        let trust = try await confirmedTrust()
        try await KeySetup.installKey(host: host, port: port, user: user, password: password, key: key,
                                      comment: "m", hostKeyValidator: trust.validator(host: host, port: port))
        let c = SSHConnection(host: host, port: port, user: user, auth: [.key(key)], hostKeyValidator: trust.validator(host: host, port: port))
        try await c.connect()
        let scan = ServerScan.parse(try await c.exec(ServerScan.command).output)
        XCTAssertEqual(scan.os, "Linux")
        XCTAssertTrue(scan.tools.contains("tmux"))
        var failures: [String] = []
        for t in ServerScan.suggest(scan) {
            let m = t.metric(for: UUID())
            let r = try await c.exec(m.command)
            let reading = MetricParser.read(m, output: r.output, status: r.status)
            print("metric \(t.id): \(reading.display) [\(r.output.trimmingCharacters(in: .whitespacesAndNewlines))]")
            if reading.state == .error { failures.append("\(t.id): \(r.output)") }
        }
        XCTAssertEqual(failures, [])
        c.close()
    }

    func testUnreachable() async throws {
        let c = SSHConnection(host: "127.0.0.1", port: 1, user: "x", auth: [.password("x")], hostKeyValidator: { _, _ in nil })
        do { try await c.connect(); XCTFail() } catch let e as SSHError {
            guard case .unreachable = e else { return XCTFail("\(e)") }
        }
    }

    func testKeySetupThenShellAndTOFU() async throws {
        try requireServer()
        let trust = try await confirmedTrust()
        let key = Curve25519.Signing.PrivateKey()
        try await KeySetup.installKey(host: host, port: port, user: user, password: password, key: key,
                                      comment: "v-shell-test", hostKeyValidator: trust.validator(host: host, port: port))
        XCTAssertNotEqual(trust.check(host: host, port: port, fingerprint: "x"), .firstUse)

        let c = SSHConnection(host: host, port: port, user: user, auth: [.key(key)], hostKeyValidator: trust.validator(host: host, port: port))
        try await c.connect()
        let (status, out) = try await c.exec("echo hello-$((40+2))")
        XCTAssertEqual(status, 0); XCTAssertEqual(out, "hello-42\n")

        let got = expectation(description: "pty output")
        let box = Box()
        let shell = try await c.openShell(cols: 100, rows: 30, command: nil, onData: { b in
            if box.append(b, lookingFor: "30 100") { got.fulfill() }
        }, onExit: { _ in })
        shell.write(Array("stty size\n".utf8))
        await fulfillment(of: [got], timeout: 10)
        shell.close(); c.close()

        // Changed host key must be refused.
        let liar = HostKeyTrust(backing: MemoryBacking())
        liar.trust(host: host, port: port, fingerprint: "SHA256:something-else")
        let c2 = SSHConnection(host: host, port: port, user: user, auth: [.key(key)], hostKeyValidator: liar.validator(host: host, port: port))
        do { try await c2.connect(); XCTFail() } catch let e as SSHError {
            guard case .hostKeyChanged = e else { return XCTFail("\(e)") }
        }
    }

    /// The mosh replacement: a tmux session survives a dropped connection and is re-attached.
    func testTmuxSurvivesDisconnect() async throws {
        try requireServer()
        let key = Curve25519.Signing.PrivateKey()
        let trust = try await confirmedTrust()
        try await KeySetup.installKey(host: host, port: port, user: user, password: password, key: key,
                                      comment: "t", hostKeyValidator: trust.validator(host: host, port: port))
        let session = "persist\(Int.random(in: 1000...9999))"

        // First attach: set a shell variable that only exists inside this tmux session.
        let c1 = SSHConnection(host: host, port: port, user: user, auth: [.key(key)], hostKeyValidator: trust.validator(host: host, port: port))
        try await c1.connect()
        let sh1 = try await c1.openShell(cols: 80, rows: 24, command: RemoteCommands.tmuxAttach(session: session), onData: { _ in }, onExit: { _ in })
        try await Task.sleep(nanoseconds: 1_000_000_000)
        sh1.write(Array("export SURVIVOR=still-here\r".utf8))
        try await Task.sleep(nanoseconds: 500_000_000)
        c1.close()   // simulate losing the network

        // Second attach: the variable must still be set.
        let c2 = SSHConnection(host: host, port: port, user: user, auth: [.key(key)], hostKeyValidator: trust.validator(host: host, port: port))
        try await c2.connect()
        let seen = expectation(description: "survivor")
        let box = Box()
        let sh2 = try await c2.openShell(cols: 80, rows: 24, command: RemoteCommands.tmuxAttach(session: session), onData: { b in
            if box.append(b, lookingFor: "VAL=still-here") { seen.fulfill() }
        }, onExit: { _ in })
        try await Task.sleep(nanoseconds: 1_000_000_000)
        sh2.write(Array("echo VAL=$SURVIVOR\r".utf8))
        await fulfillment(of: [seen], timeout: 10)
        // No ~/.tmux.conf on the test server: status line hidden, mouse on, only for this session.
        let opts = try await c2.exec("tmux show-options -t \(session) status; tmux show-options -t \(session) mouse; tmux show-options -g status")
        XCTAssertTrue(opts.output.contains("status off"), opts.output)
        XCTAssertTrue(opts.output.contains("mouse on"), opts.output)
        XCTAssertTrue(opts.output.contains("status on"), "global option must be untouched: \(opts.output)")
        sh2.write(Array("tmux kill-session\r".utf8))
        c2.close()
    }

    /// Run-on-connect runs once when the session is created, never again on re-attach.
    func testStartupCommandRunsOnlyForNewSession() async throws {
        try requireServer()
        let key = Curve25519.Signing.PrivateKey()
        let trust = try await confirmedTrust()
        try await KeySetup.installKey(host: host, port: port, user: user, password: password, key: key,
                                      comment: "t", hostKeyValidator: trust.validator(host: host, port: port))
        let session = "start\(Int.random(in: 1000...9999))"
        let cmd = RemoteCommands.tmuxAttach(session: session, startup: "echo started >> /tmp/\(session).log")
        for _ in 0..<2 {
            let c = SSHConnection(host: host, port: port, user: user, auth: [.key(key)], hostKeyValidator: trust.validator(host: host, port: port))
            try await c.connect()
            _ = try await c.openShell(cols: 80, rows: 24, command: cmd, onData: { _ in }, onExit: { _ in })
            try await Task.sleep(nanoseconds: 1_500_000_000)
            c.close()
            try await Task.sleep(nanoseconds: 500_000_000)
        }
        let c = SSHConnection(host: host, port: port, user: user, auth: [.key(key)], hostKeyValidator: trust.validator(host: host, port: port))
        try await c.connect()
        let r = try await c.exec("grep -c started /tmp/\(session).log; tmux kill-session -t \(session)")
        XCTAssertEqual(r.output.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: "\n").first, "1", r.output)
        c.close()
    }
}

final class Box: @unchecked Sendable {
    private var buf = [UInt8](); private var hit = false; private let lock = NSLock()
    func append(_ b: [UInt8], lookingFor s: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        buf += b
        if !hit && String(decoding: buf, as: UTF8.self).contains(s) { hit = true; return true }
        return false
    }
}
