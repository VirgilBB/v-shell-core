import Foundation
import CryptoKit

/// Any private key v-Shell can sign with: its own ed25519 device key, or a key file the user
/// imported from their provider (Ed25519 or ECDSA). RSA is not supported (swift-nio-ssh has no RSA).
public enum SigningKey {
    case ed25519(Curve25519.Signing.PrivateKey)
    case p256(P256.Signing.PrivateKey)
    case p384(P384.Signing.PrivateKey)
    case p521(P521.Signing.PrivateKey)

    public var typeName: String {
        switch self {
        case .ed25519: return "ssh-ed25519"
        case .p256: return "ecdsa-sha2-nistp256"
        case .p384: return "ecdsa-sha2-nistp384"
        case .p521: return "ecdsa-sha2-nistp521"
        }
    }

    /// `type base64 comment`, ready for authorized_keys.
    public func publicKeyLine(comment: String) -> String {
        let blob: Data
        switch self {
        case .ed25519(let k): return KeyManager.openSSHPublicKey(k.publicKey, comment: comment)
        case .p256(let k): blob = Self.ecdsaBlob("nistp256", k.publicKey.x963Representation)
        case .p384(let k): blob = Self.ecdsaBlob("nistp384", k.publicKey.x963Representation)
        case .p521(let k): blob = Self.ecdsaBlob("nistp521", k.publicKey.x963Representation)
        }
        return "\(typeName) \(blob.base64EncodedString()) \(comment)"
    }

    static func ecdsaBlob(_ curve: String, _ q: Data) -> Data {
        SSHWire.string("ecdsa-sha2-" + curve) + SSHWire.string(curve) + SSHWire.string(q)
    }

    // MARK: Keychain storage. Legacy device keys are the bare 32-byte ed25519 seed.

    private static let tag = Data("vsk1:".utf8)

    var stored: Data {
        switch self {
        case .ed25519(let k): return Self.tag + Data("e:".utf8) + k.rawRepresentation
        case .p256(let k): return Self.tag + Data("2:".utf8) + k.rawRepresentation
        case .p384(let k): return Self.tag + Data("3:".utf8) + k.rawRepresentation
        case .p521(let k): return Self.tag + Data("5:".utf8) + k.rawRepresentation
        }
    }

    static func fromStored(_ d: Data) -> SigningKey? {
        guard d.starts(with: tag), d.count > tag.count + 2 else {
            return (try? Curve25519.Signing.PrivateKey(rawRepresentation: d)).map { .ed25519($0) }
        }
        let kind = d[d.startIndex + tag.count]
        let raw = d.dropFirst(tag.count + 2)
        switch kind {
        case UInt8(ascii: "e"): return (try? Curve25519.Signing.PrivateKey(rawRepresentation: raw)).map { .ed25519($0) }
        case UInt8(ascii: "2"): return (try? P256.Signing.PrivateKey(rawRepresentation: raw)).map { .p256($0) }
        case UInt8(ascii: "3"): return (try? P384.Signing.PrivateKey(rawRepresentation: raw)).map { .p384($0) }
        case UInt8(ascii: "5"): return (try? P521.Signing.PrivateKey(rawRepresentation: raw)).map { .p521($0) }
        default: return nil
        }
    }
}

public enum KeyImportError: Error, Equatable, LocalizedError {
    case rsa
    case encrypted
    case unsupported(String)
    case notAKey

    public var errorDescription: String? {
        switch self {
        case .rsa: return "It's an RSA key. v-Shell supports Ed25519 and ECDSA keys today."
        case .encrypted: return "This key is protected with a passphrase. v-Shell can't open passphrase-protected key files yet."
        case .unsupported(let t): return "This key type (\(t)) isn't supported. v-Shell supports Ed25519 and ECDSA keys."
        case .notAKey: return "That isn't a private key file. It should start with -----BEGIN … PRIVATE KEY-----."
        }
    }

    /// Title for the "not supported" screen.
    public var title: String {
        switch self {
        case .notAKey: return "That isn't a key file"
        default: return "This key type isn't supported yet"
        }
    }
}

/// Parses private key files from cloud providers and ~/.ssh. Nothing touches the network.
public enum KeyImport {
    public static func parse(_ text: String) throws -> SigningKey {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.contains("BEGIN RSA PRIVATE KEY") { throw KeyImportError.rsa }
        if t.contains("BEGIN ENCRYPTED PRIVATE KEY") || t.contains("Proc-Type: 4,ENCRYPTED") { throw KeyImportError.encrypted }
        if t.contains("BEGIN OPENSSH PRIVATE KEY") { return try openSSH(t) }
        if t.contains("BEGIN EC PRIVATE KEY") || t.contains("BEGIN PRIVATE KEY") {
            if let k = try? P256.Signing.PrivateKey(pemRepresentation: t) { return .p256(k) }
            if let k = try? P384.Signing.PrivateKey(pemRepresentation: t) { return .p384(k) }
            if let k = try? P521.Signing.PrivateKey(pemRepresentation: t) { return .p521(k) }
            if let der = body(t), der.range(of: Data([0x2B, 0x65, 0x70])) != nil,   // OID 1.3.101.112 Ed25519
               der.count >= 32, let k = try? Curve25519.Signing.PrivateKey(rawRepresentation: der.suffix(32)) {
                return .ed25519(k)
            }
            if let der = body(t), der.range(of: Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])) != nil {
                throw KeyImportError.rsa   // PKCS#8 rsaEncryption
            }
            throw KeyImportError.unsupported("PEM")
        }
        if t.hasPrefix("ssh-") || t.hasPrefix("ecdsa-") { throw KeyImportError.notAKey }   // a public key line
        throw KeyImportError.notAKey
    }

    static func body(_ pem: String) -> Data? {
        let b64 = pem.split(whereSeparator: \.isNewline).filter { !$0.hasPrefix("-----") && !$0.contains(":") }.joined()
        return Data(base64Encoded: b64)
    }

    // openssh-key-v1: magic, cipher, kdf, kdfopts, nkeys, pubkey, private section.
    static func openSSH(_ pem: String) throws -> SigningKey {
        guard let d = body(pem) else { throw KeyImportError.notAKey }
        var r = Reader(d)
        guard r.bytes(15) == Data("openssh-key-v1\0".utf8) else { throw KeyImportError.notAKey }
        let cipher = try r.string()
        _ = try r.string(); _ = try r.string()
        if String(decoding: cipher, as: UTF8.self) != "none" { throw KeyImportError.encrypted }
        guard try r.uint32() == 1 else { throw KeyImportError.unsupported("multiple keys") }
        _ = try r.string()
        var p = Reader(try r.string())
        guard try p.uint32() == p.uint32() else { throw KeyImportError.notAKey }
        let type = String(decoding: try p.string(), as: UTF8.self)
        switch type {
        case "ssh-ed25519":
            _ = try p.string()
            let priv = try p.string()
            guard priv.count == 64, let k = try? Curve25519.Signing.PrivateKey(rawRepresentation: priv.prefix(32)) else { throw KeyImportError.notAKey }
            return .ed25519(k)
        case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
            _ = try p.string(); _ = try p.string()
            let scalar = Data(try p.string().drop(while: { $0 == 0 }))
            func padded(_ n: Int) -> Data { Data(repeating: 0, count: max(0, n - scalar.count)) + scalar }
            switch type {
            case "ecdsa-sha2-nistp256": if let k = try? P256.Signing.PrivateKey(rawRepresentation: padded(32)) { return .p256(k) }
            case "ecdsa-sha2-nistp384": if let k = try? P384.Signing.PrivateKey(rawRepresentation: padded(48)) { return .p384(k) }
            default: if let k = try? P521.Signing.PrivateKey(rawRepresentation: padded(66)) { return .p521(k) }
            }
            throw KeyImportError.notAKey
        case "ssh-rsa": throw KeyImportError.rsa
        default: throw KeyImportError.unsupported(type)
        }
    }

    struct Reader {
        let d: Data; var i: Int
        init(_ d: Data) { self.d = Data(d); i = 0 }
        mutating func bytes(_ n: Int) -> Data? {
            guard n >= 0, i + n <= d.count else { return nil }
            defer { i += n }
            return d.subdata(in: i..<i + n)
        }
        mutating func uint32() throws -> UInt32 {
            guard let b = bytes(4) else { throw KeyImportError.notAKey }
            return b.reduce(0) { $0 << 8 | UInt32($1) }
        }
        mutating func string() throws -> Data {
            let n = Int(try uint32())
            guard let b = bytes(n) else { throw KeyImportError.notAKey }
            return b
        }
    }
}

public extension KeyManager {
    /// The device key or an imported key, by id.
    func signingKey(_ id: String = KeyManager.defaultKeyID) -> SigningKey? {
        store.get(id).flatMap(SigningKey.fromStored)
    }

    /// Stores an imported key on this device only (Keychain, never synced). Returns its id.
    func importKey(_ key: SigningKey) throws -> String {
        let id = "imported-" + UUID().uuidString
        try store.set(key.stored, for: id)
        return id
    }

    /// authorized_keys line for any stored key.
    func publicKeyLine(for id: String, comment: String) -> String? {
        signingKey(id)?.publicKeyLine(comment: comment)
    }
}
