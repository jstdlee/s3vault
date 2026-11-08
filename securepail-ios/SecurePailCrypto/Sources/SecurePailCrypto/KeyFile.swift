import CryptoKit
import Foundation
#if canImport(CommonCrypto)
import CommonCrypto
#endif

/// The password-protected backup of a master key (`securepail-key` JSON). The
/// shape matches Quick Diary's key file; `Data` fields are base64 and
/// `created` is ISO 8601, so the desktop app and iOS read each other's files.
public struct KeyFile: Codable, Equatable {
    public var format = "securepail-key"
    public var version = 1
    public var kdf = "PBKDF2-HMAC-SHA256"
    public var iterations: Int
    public var salt: Data
    /// AES-256-GCM `nonce(12) | ciphertext | tag(16)` of the 32-byte master key.
    public var wrappedKey: Data
    /// First 16 bytes of HMAC-SHA256(master key, "securepail-check").
    public var check: Data
    public var created: Date
}

public enum KeyBackup {
    public static let defaultIterations = 600_000
    static let minIterations = 100_000
    static let maxIterations = 10_000_000
    static let aad = Data("securepail-key-v1".utf8)
    static let checkLabel = Data("securepail-check".utf8)

    static func decoder() -> JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }

    static func encoder() -> JSONEncoder {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.outputFormatting = [.prettyPrinted, .sortedKeys]
        return e
    }

    /// PBKDF2-HMAC-SHA256 → 32 bytes. The password is NFC-normalised, so the
    /// same password typed on different keyboards gives the same key.
    static func deriveKey(password: String, salt: Data, iterations: Int) throws -> SymmetricKey {
        let normalized = password.precomposedStringWithCanonicalMapping
        var out = [UInt8](repeating: 0, count: 32)
        #if canImport(CommonCrypto)
        let length = normalized.utf8.count
        let status = normalized.withCString { pwPtr in
            salt.withUnsafeBytes { saltBuf in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    pwPtr, length,
                    saltBuf.bindMemory(to: UInt8.self).baseAddress, salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    UInt32(iterations),
                    &out, out.count)
            }
        }
        guard status == Int32(kCCSuccess) else { throw SecurePailError.badKeyFile }
        #else
        out = pbkdf2(password: Array(normalized.utf8), salt: Array(salt), iterations: iterations)
        #endif
        return SymmetricKey(data: out)
    }

    #if !canImport(CommonCrypto)
    /// Slow reference PBKDF2 for platforms without CommonCrypto (tests on Linux).
    static func pbkdf2(password: [UInt8], salt: [UInt8], iterations: Int) -> [UInt8] {
        let key = SymmetricKey(data: password)
        var u = Array(HMAC<SHA256>.authenticationCode(for: salt + [0, 0, 0, 1], using: key))
        var t = u
        for _ in 1..<iterations {
            u = Array(HMAC<SHA256>.authenticationCode(for: u, using: key))
            for i in 0..<t.count { t[i] ^= u[i] }
        }
        return t
    }
    #endif

    static func checkValue(_ master: SymmetricKey) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: checkLabel, using: master)).prefix(16)
    }

    /// Wraps the stored key with `password` and returns the JSON file.
    public static func make(key stored: String, password: String,
                            iterations: Int = defaultIterations) throws -> Data {
        let salt = SPE.randomBytes(16)
        return try encoder().encode(try wrap(key: stored, password: password, iterations: iterations,
                                             salt: salt, nonce: nil,
                                             created: Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down))))
    }

    /// Deterministic when `nonce` is given (tests).
    static func wrap(key stored: String, password: String, iterations: Int, salt: Data,
                     nonce: Data?, created: Date) throws -> KeyFile {
        guard iterations >= minIterations, iterations <= maxIterations else { throw SecurePailError.badKeyFile }
        let master = try SPE.masterKey(stored)
        let kek = try deriveKey(password: password, salt: salt, iterations: iterations)
        let masterBytes = master.withUnsafeBytes { Data($0) }
        let sealed: AES.GCM.SealedBox
        if let nonce {
            sealed = try AES.GCM.seal(masterBytes, using: kek, nonce: AES.GCM.Nonce(data: nonce), authenticating: aad)
        } else {
            sealed = try AES.GCM.seal(masterBytes, using: kek, authenticating: aad)
        }
        return KeyFile(iterations: iterations, salt: salt, wrappedKey: sealed.combined!,
                       check: checkValue(master), created: created)
    }

    public static func isKeyFile(_ data: Data) -> Bool {
        (try? decoder().decode(KeyFile.self, from: data))?.format == "securepail-key"
    }

    /// Opens a key file and returns the stored key.
    public static func open(_ data: Data, password: String) throws -> String {
        guard let file = try? decoder().decode(KeyFile.self, from: data),
              file.format == "securepail-key", file.version == 1, file.kdf == "PBKDF2-HMAC-SHA256",
              file.wrappedKey.count >= 12 + 16,
              file.iterations >= minIterations, file.iterations <= maxIterations
        else { throw SecurePailError.badKeyFile }
        let kek = try deriveKey(password: password, salt: file.salt, iterations: file.iterations)
        let master: Data
        do {
            let box = try AES.GCM.SealedBox(combined: file.wrappedKey)
            master = try AES.GCM.open(box, using: kek, authenticating: aad)
        } catch {
            throw SecurePailError.wrongPassword
        }
        let key = SymmetricKey(data: master)
        guard master.count == 32, checkValue(key) == file.check else { throw SecurePailError.badKeyFile }
        return SPE.storedKey(key)
    }

    // MARK: Recovery key — 16 groups of 4 hex digits

    public static func recoveryString(key stored: String) throws -> String {
        let master = try SPE.masterKey(stored).withUnsafeBytes { Data($0) }
        let hex = master.map { String(format: "%02X", $0) }.joined()
        return stride(from: 0, to: hex.count, by: 4).map { i -> String in
            let start = hex.index(hex.startIndex, offsetBy: i)
            return String(hex[start..<hex.index(start, offsetBy: 4)])
        }.joined(separator: "-")
    }

    public static func parseRecovery(_ text: String) throws -> String {
        let hex = text.uppercased().filter { $0.isHexDigit }
        let rest = text.uppercased().filter { !$0.isHexDigit && $0 != "-" && !$0.isWhitespace }
        guard rest.isEmpty, hex.count == 64 else { throw SecurePailError.badRecoveryKey }
        var bytes = [UInt8]()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { throw SecurePailError.badRecoveryKey }
            bytes.append(byte)
            index = next
        }
        return SPE.storedKey(SymmetricKey(data: bytes))
    }
}
