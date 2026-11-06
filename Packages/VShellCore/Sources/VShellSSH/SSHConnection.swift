import Foundation
import Crypto
import NIOCore
import NIOPosix
import NIOSSH
import VShellCore

public enum SSHAuth {
    /// Tries `password`, then `keyboard-interactive` with the same secret.
    case password(String)
    case key(Curve25519.Signing.PrivateKey)
    /// Device key or an imported Ed25519/ECDSA key.
    case signing(SigningKey)
    /// Internal: the keyboard-interactive retry of a password.
    case keyboardOnly(String)
}

extension SSHAuth {
    var logName: String {
        switch self { case .password: return "password"; case .key, .signing: return "key"; case .keyboardOnly: return "keyboard" }
    }
}

/// Every error carries the sentence the user sees.
public enum SSHError: Error, LocalizedError, Equatable {
    case unreachable(advice: String)
    case authFailed(triedPassword: Bool)
    case hostKeyChanged(expected: String, got: String)
    case hostKeyRejected
    case channelFailed(String)
    case closed
    /// The key was installed but the server still refuses key logins (some shared hosting).
    case keyRefused
    /// First time seeing this computer: the user must confirm its identity before anything is sent.
    case hostKeyUnconfirmed(fingerprint: String)

    public var errorDescription: String? {
        switch self {
        case .unreachable(let advice): return "Can't reach it. " + advice
        case .authFailed(let pw):
            return pw ? "The server rejected the user name or password. On a Mac, use your Mac account (not your Apple ID)."
                      : "The server didn't accept this device's key. Open the server's settings and use \"Re-add this device's key\"."
        case .hostKeyChanged(let e, let g):
            return "Security warning: this isn't the computer v-Shell knows (its identity changed from \(e.prefix(19))… to \(g.prefix(19))…). Something on this network may be pretending to be it, so v-Shell stopped before sending anything. Don't type its password here. Only if you reinstalled that computer: its settings > Forget this computer's identity."
        case .hostKeyRejected: return "Connection cancelled: server identity not trusted."
        case .channelFailed(let m): return "The server refused to open a terminal (\(m))."
        case .closed: return "The connection closed."
        case .keyRefused: return "This server doesn't accept keys, so v-Shell can't sign in by itself."
        case .hostKeyUnconfirmed: return "v-Shell hasn't seen this computer's identity before. Confirm it to continue."
        }
    }
}

/// Decides whether to trust a server key. Return nil to accept, or an error to refuse.
public typealias HostKeyValidator = (_ openSSHLine: String, _ fingerprint: String) -> SSHError?

public extension HostKeyTrust {
    /// TOFU validator for a host: first use is remembered, a mismatch is refused.
    /// Strict: only an already-confirmed key is accepted. A first-time key is never trusted silently;
    /// callers show the fingerprint (`SSHConnection.fetchFingerprint`) and the user confirms first.
    func validator(host: String, port: Int) -> HostKeyValidator {
        return { [weak self] _, fp in
            guard let self else { return .hostKeyRejected }
            switch self.check(host: host, port: port, fingerprint: fp) {
            case .trusted: return nil
            case .firstUse: return .hostKeyUnconfirmed(fingerprint: fp)
            case .mismatch(let expected): return .hostKeyChanged(expected: expected, got: fp)
            }
        }
    }

    /// For a computer's second (away) address: accept only the key already pinned for its home
    /// address, then pin it under the away name too. A different key is refused, never learned.
    func sameComputerValidator(home: String, away: String, port: Int) -> HostKeyValidator {
        return { [weak self] _, fp in
            guard let self else { return .hostKeyRejected }   // fail closed
            switch self.check(host: away, port: port, fingerprint: fp) {
            case .trusted: return nil
            case .mismatch(let expected): return .hostKeyChanged(expected: expected, got: fp)
            case .firstUse:
                guard case .trusted = self.check(host: home, port: port, fingerprint: fp) else {
                    return .hostKeyChanged(expected: "the key of this computer's home address", got: fp)
                }
                self.trust(host: away, port: port, fingerprint: fp)
                return nil
            }
        }
    }
}

// MARK: - Delegates

final class AuthDelegate: NIOSSHClientUserAuthenticationDelegate, @unchecked Sendable {
    let user: String
    var remaining: [SSHAuth]
    private(set) var triedPassword = false
    init(user: String, auth: [SSHAuth]) { self.user = user; self.remaining = auth }

    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods,
                                nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
        var offered: [String] = []
        if availableMethods.contains(.publicKey) { offered.append("publickey") }
        if availableMethods.contains(.password) { offered.append("password") }
        if availableMethods.contains(.keyboardInteractive) { offered.append("keyboard-interactive") }
        SupportLog.shared.add("server offers auth: \(offered.joined(separator: ","))")
        while !remaining.isEmpty {
            let next = remaining.removeFirst()
            switch next {
            case .key(let k) where availableMethods.contains(.publicKey):
                nextChallengePromise.succeed(.init(username: user, serviceName: "",
                    offer: .privateKey(.init(privateKey: NIOSSHPrivateKey(ed25519Key: k)))))
                return
            case .signing(let k) where availableMethods.contains(.publicKey):
                let nk: NIOSSHPrivateKey
                switch k {
                case .ed25519(let e): nk = NIOSSHPrivateKey(ed25519Key: e)
                case .p256(let e): nk = NIOSSHPrivateKey(p256Key: e)
                case .p384(let e): nk = NIOSSHPrivateKey(p384Key: e)
                case .p521(let e): nk = NIOSSHPrivateKey(p521Key: e)
                }
                nextChallengePromise.succeed(.init(username: user, serviceName: "", offer: .privateKey(.init(privateKey: nk))))
                return
            case .password(let p) where availableMethods.contains(.password) || availableMethods.contains(.keyboardInteractive):
                triedPassword = true
                // Prefer plain password; macOS and PAM-only servers offer just keyboard-interactive.
                if availableMethods.contains(.password) {
                    if availableMethods.contains(.keyboardInteractive) { remaining.insert(.keyboardOnly(p), at: 0) }
                    nextChallengePromise.succeed(.init(username: user, serviceName: "", offer: .password(.init(password: p))))
                } else {
                    nextChallengePromise.succeed(.init(username: user, serviceName: "", offer: .keyboardInteractive(.init(password: p))))
                }
                return
            case .keyboardOnly(let p) where availableMethods.contains(.keyboardInteractive):
                nextChallengePromise.succeed(.init(username: user, serviceName: "", offer: .keyboardInteractive(.init(password: p))))
                return
            default: continue
            }
        }
        nextChallengePromise.fail(SSHError.authFailed(triedPassword: triedPassword))
    }
}

final class HostKeyDelegate: NIOSSHClientServerAuthenticationDelegate, @unchecked Sendable {
    let validate: HostKeyValidator
    var failure: SSHError?
    init(_ v: @escaping HostKeyValidator) { validate = v }
    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        let line = String(openSSHPublicKey: hostKey)
        // A key we can't fingerprint is refused, never compared as "unknown".
        guard let fp = KeyManager.fingerprint(ofOpenSSHLine: line) else {
            failure = .hostKeyRejected; validationCompletePromise.fail(SSHError.hostKeyRejected); return
        }
        if let err = validate(line, fp) { failure = err; validationCompletePromise.fail(err) }
        else { validationCompletePromise.succeed(()) }
    }
}

/// Sits after NIOSSHHandler; reports when auth succeeded or the link died.
final class AuthWatcher: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = Any
    let promise: EventLoopPromise<Void>
    var done = false
    init(_ p: EventLoopPromise<Void>) { promise = p }
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if event is UserAuthSuccessEvent, !done { done = true; promise.succeed(()) }
        context.fireUserInboundEventTriggered(event)
    }
    func errorCaught(context: ChannelHandlerContext, error: Error) {
        if !done { done = true; promise.fail(error) }
        context.close(promise: nil)
    }
    func channelInactive(context: ChannelHandlerContext) {
        if !done { done = true; promise.fail(SSHError.closed) }
        context.fireChannelInactive()
    }
}

/// Bridges an SSH session channel to callbacks.
final class SessionHandler: ChannelDuplexHandler, @unchecked Sendable {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = Never
    typealias OutboundIn = SSHChannelData
    typealias OutboundOut = SSHChannelData

    var onData: (([UInt8]) -> Void)?
    var onExit: ((Int?) -> Void)?
    var onReply: ((Bool) -> Void)?
    var exitStatus: Int?

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let d = unwrapInboundIn(data)
        guard case .byteBuffer(var buf) = d.data, let bytes = buf.readBytes(length: buf.readableBytes) else { return }
        onData?(bytes)
    }
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case let s as SSHChannelRequestEvent.ExitStatus: exitStatus = s.exitStatus
        case is ChannelSuccessEvent: onReply?(true)
        case is ChannelFailureEvent: onReply?(false)
        case let e as ChannelEvent where e == .inputClosed: break
        default: context.fireUserInboundEventTriggered(event)
        }
    }
    func channelInactive(context: ChannelHandlerContext) {
        onExit?(exitStatus); onExit = nil
        context.fireChannelInactive()
    }
    func errorCaught(context: ChannelHandlerContext, error: Error) { context.close(promise: nil) }
}

// MARK: - Public API

public final class ShellChannel: @unchecked Sendable {
    let channel: Channel
    init(channel: Channel) { self.channel = channel }

    public func write(_ bytes: [UInt8]) {
        guard !bytes.isEmpty else { return }
        let buf = channel.allocator.buffer(bytes: bytes)
        channel.writeAndFlush(SSHChannelData(type: .channel, data: .byteBuffer(buf)), promise: nil)
    }
    public func resize(cols: Int, rows: Int) {
        guard cols > 0, rows > 0 else { return }
        channel.triggerUserOutboundEvent(SSHChannelRequestEvent.WindowChangeRequest(
            terminalCharacterWidth: cols, terminalRowHeight: rows, terminalPixelWidth: 0, terminalPixelHeight: 0), promise: nil)
    }
    public func close() { channel.close(promise: nil) }
    public var isActive: Bool { channel.isActive }
}

public final class SSHConnection: @unchecked Sendable {
    public let host: String
    public let port: Int
    public let user: String
    private let auth: [SSHAuth]
    private let hostKeyValidator: HostKeyValidator
    private var channel: Channel?
    private var sshHandler: NIOSSHHandler?
    private var authDelegate: AuthDelegate?
    private let group: EventLoopGroup = MultiThreadedEventLoopGroup.singleton

    public var onDisconnect: (() -> Void)?

    public init(host: String, port: Int = 22, user: String, auth: [SSHAuth], hostKeyValidator: @escaping HostKeyValidator) {
        self.host = host; self.port = port; self.user = user; self.auth = auth; self.hostKeyValidator = hostKeyValidator
    }

    public var isConnected: Bool { channel?.isActive ?? false }

    /// TCP connect + key exchange + user auth. Throws an SSHError with user-facing text.
    /// Same as connect(timeout:), for callers that don't import NIO.
    public func connect(seconds: Int64) async throws { try await connect(timeout: .seconds(seconds)) }

    public func connect(timeout: TimeAmount = .seconds(12)) async throws {
        let authDelegate = AuthDelegate(user: user, auth: auth)
        let hostDelegate = HostKeyDelegate(hostKeyValidator)
        self.authDelegate = authDelegate
        let el = group.next()
        let what = "\(SupportReport.label(forAddress: host)):\(port)"
        SupportLog.shared.add("connect \(what) auth=\(auth.map(\.logName).joined(separator: ","))")
        let authPromise = el.makePromise(of: Void.self)
        let bootstrap = ClientBootstrap(group: el)
            .connectTimeout(timeout)
            .channelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_KEEPALIVE), value: 1)
            .channelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_NODELAY), value: 1)
            // Notice a dead link (phone changed network, NAT dropped us) in ~1 min, not 2 h.
            .channelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_KEEPALIVE), value: 30)
            .channelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_KEEPINTVL), value: 10)
            .channelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_KEEPCNT), value: 3)
            .channelInitializer { ch in
                ch.eventLoop.makeCompletedFuture {
                    let ssh = NIOSSHHandler(role: .client(.init(userAuthDelegate: authDelegate, serverAuthDelegate: hostDelegate)),
                                            allocator: ch.allocator, inboundChildChannelInitializer: { child, _ in
                                                // Never accept channels the server opens (forwarding, X11, agent).
                                                child.eventLoop.makeFailedFuture(SSHError.channelFailed("refused"))
                                            })
                    try ch.pipeline.syncOperations.addHandler(ssh)
                    try ch.pipeline.syncOperations.addHandler(AuthWatcher(authPromise))
                }
            }

        let ch: Channel
        do { ch = try await bootstrap.connect(host: host, port: port).get() }
        catch {
            authPromise.fail(SSHError.closed)
            SupportLog.shared.add("tcp failed \(what): " + "\(error)".replacingOccurrences(of: host, with: "<host>"))
            throw SSHError.unreachable(advice: NetworkHint.unreachableAdvice(for: host))
        }

        do {
            try await withTimeout(timeout, on: el, authPromise.futureResult)
        } catch {
            ch.close(promise: nil)
            SupportLog.shared.add("login failed \(what): " + "\(error)".replacingOccurrences(of: host, with: "<host>"))
            if let hk = hostDelegate.failure { throw hk }
            if let e = error as? SSHError, case .authFailed = e { throw e }
            if error is NIOSSHError || error is SSHError {
                throw SSHError.authFailed(triedPassword: authDelegate.triedPassword)
            }
            throw SSHError.unreachable(advice: NetworkHint.unreachableAdvice(for: host))
        }
        SupportLog.shared.add("logged in \(what)")
        self.channel = ch
        self.sshHandler = try await ch.pipeline.handler(type: NIOSSHHandler.self).get()
        ch.closeFuture.whenComplete { [weak self] _ in self?.onDisconnect?() }
    }

    private func withTimeout(_ t: TimeAmount, on el: EventLoop, _ f: EventLoopFuture<Void>) async throws {
        let p = el.makePromise(of: Void.self)
        let task = el.scheduleTask(in: t) { p.fail(SSHError.unreachable(advice: "The server took too long to answer.")) }
        f.whenComplete { r in task.cancel(); p.completeWith(r) }
        try await p.futureResult.get()
    }

    private func openSession(handler: SessionHandler) async throws -> Channel {
        guard let channel, let sshHandler else { throw SSHError.closed }
        let promise = channel.eventLoop.makePromise(of: Channel.self)
        channel.eventLoop.execute {
            sshHandler.createChannel(promise) { child, type in
                guard type == .session else { return child.eventLoop.makeFailedFuture(SSHError.channelFailed("bad type")) }
                return child.eventLoop.makeCompletedFuture {
                    try child.pipeline.syncOperations.addHandler(handler)
                }.flatMap { child.setOption(ChannelOptions.allowRemoteHalfClosure, value: true) }
            }
        }
        return try await promise.futureResult.get()
    }

    /// Send a request and wait for success/failure.
    private func request(_ child: Channel, _ handler: SessionHandler, _ event: Any) async throws {
        let p = child.eventLoop.makePromise(of: Bool.self)
        child.eventLoop.execute {
            handler.onReply = { ok in handler.onReply = nil; p.succeed(ok) }
            child.triggerUserOutboundEvent(event).whenFailure { p.fail($0) }
        }
        let ok = try await p.futureResult.get()
        if !ok { throw SSHError.channelFailed("request refused") }
    }

    /// Runs a command without a PTY and collects stdout. Used for key install.
    public func exec(_ command: String) async throws -> (status: Int?, output: String) {
        let handler = SessionHandler()
        guard let channel else { throw SSHError.closed }
        // onData and onExit both run on the channel's event loop, so `out` needs no lock.
        let done = channel.eventLoop.makePromise(of: (Int?, [UInt8]).self)
        var out = [UInt8]()
        // A hostile server can answer with endless output: keep the first 256 KB, drop the rest.
        handler.onData = { d in if out.count < 262_144 { out += d.prefix(262_144 - out.count) } }
        handler.onExit = { done.succeed(($0, out)) }
        let child = try await openSession(handler: handler)
        try await request(child, handler, SSHChannelRequestEvent.ExecRequest(command: command, wantReply: true))
        let (status, bytes) = try await done.futureResult.get()
        return (status, String(decoding: bytes, as: UTF8.self))
    }

    /// Opens an interactive PTY. `command` nil = login shell, else exec it with the PTY (tmux attach).
    public func openShell(cols: Int, rows: Int, term: String = "xterm-256color", command: String?,
                          onData: @escaping ([UInt8]) -> Void, onExit: @escaping (Int?) -> Void) async throws -> ShellChannel {
        let handler = SessionHandler()
        handler.onData = onData
        handler.onExit = onExit
        let child = try await openSession(handler: handler)
        try await request(child, handler, SSHChannelRequestEvent.PseudoTerminalRequest(
            wantReply: true, term: term, terminalCharacterWidth: max(cols, 20), terminalRowHeight: max(rows, 5),
            terminalPixelWidth: 0, terminalPixelHeight: 0, terminalModes: SSHTerminalModes([:])))
        child.triggerUserOutboundEvent(SSHChannelRequestEvent.EnvironmentRequest(wantReply: false, name: "LANG", value: "en_US.UTF-8"), promise: nil)
        if let command {
            try await request(child, handler, SSHChannelRequestEvent.ExecRequest(command: command, wantReply: true))
        } else {
            try await request(child, handler, SSHChannelRequestEvent.ShellRequest(wantReply: true))
        }
        return ShellChannel(channel: child)
    }

    /// True if the server still answers (runs `true` on a fresh exec channel).
    /// Used after the app comes back from the background, when the socket may look open but be dead.
    public func ping(timeout: TimeAmount = .seconds(4)) async -> Bool {
        guard let channel, channel.isActive else { return false }
        let el = channel.eventLoop
        let p = el.makePromise(of: Bool.self)
        let timer = el.scheduleTask(in: timeout) { p.succeed(false) }
        Task {
            let ok = (try? await self.exec("true"))?.status == 0
            timer.cancel(); p.succeed(ok)
        }
        return (try? await p.futureResult.get()) ?? false
    }

    public func close() { channel?.close(promise: nil); channel = nil }
}

public extension SSHConnection {
    /// Reads a server's host key fingerprint without logging in or sending anything secret:
    /// the handshake is refused right after the key arrives.
    static func fetchFingerprint(host: String, port: Int, seconds: Int64 = 8) async throws -> String {
        let box = FingerprintBox()
        let c = SSHConnection(host: host, port: port, user: "vshell-probe", auth: []) { _, fp in
            box.value = fp; return .hostKeyRejected
        }
        do { try await c.connect(seconds: seconds) } catch let e as SSHError {
            if let fp = box.value { return fp }
            throw e
        }
        c.close()
        if let fp = box.value { return fp }
        throw SSHError.hostKeyRejected
    }
}

final class FingerprintBox: @unchecked Sendable {
    private let lock = NSLock(); private var v: String?
    var value: String? {
        get { lock.lock(); defer { lock.unlock() }; return v }
        set { lock.lock(); v = newValue; lock.unlock() }
    }
}

/// The one-tap setup: log in with a password, install the device key, prove the key works.
public enum KeySetup {
    public enum Step: Sendable { case installing, verifying }

    public static func installKey(host: String, port: Int, user: String, password: String,
                                  key: Curve25519.Signing.PrivateKey, comment: String,
                                  hostKeyValidator: @escaping HostKeyValidator,
                                  progress: @escaping @Sendable (Step) -> Void = { _ in }) async throws {
        let line = KeyManager.openSSHPublicKey(key.publicKey, comment: comment)
        let pwConn = SSHConnection(host: host, port: port, user: user, auth: [.password(password)], hostKeyValidator: hostKeyValidator)
        try await pwConn.connect()
        defer { pwConn.close() }
        progress(.installing)
        let (_, out) = try await pwConn.exec(RemoteCommands.installAuthorizedKey(line))
        guard out.contains("VSHELL_KEY_OK") else {
            throw SSHError.channelFailed("could not write ~/.ssh/authorized_keys: \(out.prefix(200))")
        }
        progress(.verifying)
        // Prove it: a key-only login must now work.
        let keyConn = SSHConnection(host: host, port: port, user: user, auth: [.key(key)], hostKeyValidator: hostKeyValidator)
        do { try await keyConn.connect() }
        catch SSHError.authFailed { throw SSHError.keyRefused }
        keyConn.close()
    }
}
