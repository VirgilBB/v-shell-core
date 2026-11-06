import Foundation
import CryptoKit
import Security

/// Where private key bytes live. Keychain in the app, memory in tests.
public protocol SecretStore: AnyObject {
    func get(_ id: String) -> Data?
    func set(_ data: Data, for id: String) throws
    func delete(_ id: String)
}

public final class MemorySecretStore: SecretStore {
    private var items: [String: Data] = [:]
    public init() {}
    public func get(_ id: String) -> Data? { items[id] }
    public func set(_ data: Data, for id: String) throws { items[id] = data }
    public func delete(_ id: String) { items[id] = nil }
}

/// Generic-password Keychain items, this device only, after first unlock
/// (so reconnects work while the phone is locked in a pocket).
public final class KeychainSecretStore: SecretStore {
    let service: String
    public init(service: String = "app.vshell.keys") { self.service = service }
    private func base(_ id: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: id]
    }
    public func get(_ id: String) -> Data? {
        var q = base(id); q[kSecReturnData as String] = true; q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: AnyObject?
        return SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess ? out as? Data : nil
    }
    public func set(_ data: Data, for id: String) throws {
        SecItemDelete(base(id) as CFDictionary)
        var q = base(id)
        q[kSecValueData as String] = data
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let st = SecItemAdd(q as CFDictionary, nil)
        guard st == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(st)) }
    }
    public func delete(_ id: String) { SecItemDelete(base(id) as CFDictionary) }
}

public enum SSHWire {
    public static func string(_ d: Data) -> Data {
        var len = UInt32(d.count).bigEndian
        return Data(bytes: &len, count: 4) + d
    }
    public static func string(_ s: String) -> Data { string(Data(s.utf8)) }
}

/// ed25519 device keys. One default key per device; hosts reference it by id.
public final class KeyManager {
    public static let defaultKeyID = "device"
    let store: SecretStore
    public init(store: SecretStore) { self.store = store }

    public func hasKey(_ id: String = defaultKeyID) -> Bool { store.get(id) != nil }

    /// Returns the existing key or makes one.
    @discardableResult
    public func ensureKey(_ id: String = defaultKeyID) throws -> Curve25519.Signing.PrivateKey {
        if let k = privateKey(id) { return k }
        let k = Curve25519.Signing.PrivateKey()
        try store.set(k.rawRepresentation, for: id)
        return k
    }

    public func privateKey(_ id: String = defaultKeyID) -> Curve25519.Signing.PrivateKey? {
        store.get(id).flatMap { try? Curve25519.Signing.PrivateKey(rawRepresentation: $0) }
    }

    public func deleteKey(_ id: String) { store.delete(id) }

    /// `ssh-ed25519 AAAA... comment`, ready for authorized_keys.
    public func publicKeyLine(_ id: String = defaultKeyID, comment: String = "v-shell") -> String? {
        guard let k = privateKey(id) else { return nil }
        return Self.openSSHPublicKey(k.publicKey, comment: comment)
    }

    public static func openSSHPublicKey(_ pub: Curve25519.Signing.PublicKey, comment: String) -> String {
        let blob = SSHWire.string("ssh-ed25519") + SSHWire.string(pub.rawRepresentation)
        return "ssh-ed25519 \(blob.base64EncodedString()) \(comment)"
    }

    /// OpenSSH-style SHA256 fingerprint of any `type base64 [comment]` line.
    public static func fingerprint(ofOpenSSHLine line: String) -> String? {
        let parts = line.split(separator: " ")
        guard parts.count >= 2, let blob = Data(base64Encoded: String(parts[1])) else { return nil }
        let digest = SHA256.hash(data: blob)
        return "SHA256:" + Data(digest).base64EncodedString().replacingOccurrences(of: "=", with: "")
    }
}
