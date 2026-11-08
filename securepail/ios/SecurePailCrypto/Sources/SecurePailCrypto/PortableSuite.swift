import CryptoKit
import Foundation

/// Errors of the portable suite. Messages say what happened and what to do.
public enum SecurePailError: Error, Equatable, LocalizedError {
    /// The data is not a securePail "SPE1" object.
    case notPortableFormat
    /// Wrong key, or the data was damaged, modified or cut short.
    case authenticationFailed
    /// The key is not a generated securePail key ("spk1-…").
    case badKey
    case badKeyFile
    case wrongPassword
    case badRecoveryKey
    case fileTooLarge

    public var errorDescription: String? {
        switch self {
        case .notPortableFormat: "This is not a securePail encrypted file."
        case .authenticationFailed: "Wrong key, or the file is damaged or was changed."
        case .badKey: "A securePail key starts with spk1-. Create one with pail secure keygen, or restore it from a key file."
        case .badKeyFile: "This is not a securePail key file."
        case .wrongPassword: "Wrong password."
        case .badRecoveryKey: "A recovery key has 64 characters (0–9, A–F). Check it and try again."
        case .fileTooLarge: "The file is too large."
        }
    }
}

/// The portable securePail suite ("SPE1"): chunked AES-256-GCM with a per-file
/// key derived by HKDF-SHA256. It uses only CryptoKit and produces exactly the
/// bytes the desktop app does (see docs/secure-layer.md and the shared test
/// vectors).
///
/// Object = header | chunk 0 | chunk 1 | …
///   header  = "SPE1" | chunkSize (UInt32 big endian) | salt (16 bytes)
///   fileKey = HKDF-SHA256(master, salt, info "securepail-file-v1", 32 bytes)
///   chunk i = AES-256-GCM(fileKey, nonce = UInt32BE(i) | 7 zero bytes | last,
///                         aad = header), stored as ciphertext | 16-byte tag
public enum SPE {
    public static let magic = Data("SPE1".utf8)
    public static let headerLength = 24
    public static let defaultChunkSize = 1 << 20
    static let minChunkSize = 1 << 10
    static let maxChunkSize = 16 << 20
    static let tagLength = 16
    static let fileKeyInfo = Data("securepail-file-v1".utf8)

    // MARK: Keys

    /// Stored keys look like "spk1-" + base64url(32 random bytes), without padding.
    public static let keyPrefix = "spk1-"

    /// A new random key in its stored form.
    public static func generateKey() -> String {
        storedKey(SymmetricKey(size: .bits256))
    }

    public static func storedKey(_ key: SymmetricKey) -> String {
        keyPrefix + key.withUnsafeBytes { Data($0) }.base64URLNoPadding
    }

    /// The 32-byte master key of a stored key.
    public static func masterKey(_ stored: String) throws -> SymmetricKey {
        guard stored.hasPrefix(keyPrefix),
              let raw = Data(base64URLNoPadding: String(stored.dropFirst(keyPrefix.count))),
              raw.count == 32 else { throw SecurePailError.badKey }
        return SymmetricKey(data: raw)
    }

    /// Cryptographically secure random bytes (CryptoKit's generator, so it works on every platform).
    static func randomBytes(_ count: Int) -> Data {
        SymmetricKey(size: SymmetricKeySize(bitCount: count * 8)).withUnsafeBytes { Data($0) }
    }

    // MARK: Objects

    /// Encrypts `data` in memory.
    public static func encrypt(_ data: Data, key stored: String) throws -> Data {
        let salt = randomBytes(16)
        var input = data[...]
        var out = Data()
        try encryptChunks(
            read: { count in
                let part = Data(input.prefix(count))
                input = input.dropFirst(part.count)
                return part
            },
            write: { out.append($0) },
            key: try masterKey(stored), salt: salt, chunkSize: defaultChunkSize)
        return out
    }

    /// Decrypts an object in memory. Throws if any byte was changed or the end was cut off.
    public static func decrypt(_ object: Data, key stored: String) throws -> Data {
        var input = object[...]
        var out = Data()
        try decryptChunks(
            read: { count in
                let part = Data(input.prefix(count))
                input = input.dropFirst(part.count)
                return part
            },
            write: { out.append($0) },
            key: try masterKey(stored))
        return out
    }

    /// Encrypts a file, reading and writing one chunk at a time. `destination`
    /// is replaced only when everything succeeded.
    public static func encryptFile(at source: URL, to destination: URL, key stored: String) throws {
        let master = try masterKey(stored)
        let salt = randomBytes(16)
        try streamFile(from: source, to: destination) { input, output in
            try encryptChunks(
                read: { try input.read(upToCount: $0) ?? Data() },
                write: { try output.write(contentsOf: $0) },
                key: master, salt: salt, chunkSize: defaultChunkSize)
        }
    }

    /// Decrypts a file chunk by chunk. `destination` is written to a temporary
    /// file first and only moved into place when the whole file authenticated.
    public static func decryptFile(at source: URL, to destination: URL, key stored: String) throws {
        let master = try masterKey(stored)
        try streamFile(from: source, to: destination) { input, output in
            try decryptChunks(
                read: { try input.read(upToCount: $0) ?? Data() },
                write: { try output.write(contentsOf: $0) },
                key: master)
        }
    }

    // MARK: Core

    static func nonce(index: UInt32, last: Bool) throws -> AES.GCM.Nonce {
        var n = Data(count: 12)
        n[0] = UInt8(index >> 24 & 0xff)
        n[1] = UInt8(index >> 16 & 0xff)
        n[2] = UInt8(index >> 8 & 0xff)
        n[3] = UInt8(index & 0xff)
        n[11] = last ? 1 : 0
        return try AES.GCM.Nonce(data: n)
    }

    static func fileKey(master: SymmetricKey, salt: Data) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: master, salt: salt, info: fileKeyInfo, outputByteCount: 32)
    }

    static func makeHeader(chunkSize: Int, salt: Data) -> Data {
        var h = magic
        let c = UInt32(chunkSize)
        h.append(contentsOf: [UInt8(c >> 24 & 0xff), UInt8(c >> 16 & 0xff), UInt8(c >> 8 & 0xff), UInt8(c & 0xff)])
        h.append(salt)
        return h
    }

    /// `read(n)` returns up to n bytes and an empty Data at the end.
    static func encryptChunks(read: (Int) throws -> Data, write: (Data) throws -> Void,
                              key master: SymmetricKey, salt: Data, chunkSize: Int) throws {
        let header = makeHeader(chunkSize: chunkSize, salt: salt)
        let key = fileKey(master: master, salt: salt)
        try write(header)
        var current = try read(chunkSize)
        var index: UInt32 = 0
        while true {
            let next = try read(chunkSize)
            let last = next.isEmpty
            let box = try AES.GCM.seal(current, using: key, nonce: nonce(index: index, last: last),
                                       authenticating: header)
            try write(box.ciphertext + box.tag)
            if last { return }
            guard index < UInt32.max else { throw SecurePailError.fileTooLarge }
            current = next
            index += 1
        }
    }

    static func decryptChunks(read: (Int) throws -> Data, write: (Data) throws -> Void,
                              key master: SymmetricKey) throws {
        let header = try readExactly(read, headerLength)
        guard header.count == headerLength, header.prefix(4) == magic else { throw SecurePailError.notPortableFormat }
        let chunkSize = Int(header[4]) << 24 | Int(header[5]) << 16 | Int(header[6]) << 8 | Int(header[7])
        guard chunkSize >= minChunkSize, chunkSize <= maxChunkSize else { throw SecurePailError.notPortableFormat }
        let key = fileKey(master: master, salt: Data(header[8..<24]))
        let block = chunkSize + tagLength
        var current = try readExactly(read, block)
        var index: UInt32 = 0
        while true {
            let next = try readExactly(read, block)
            let last = next.isEmpty
            guard current.count >= tagLength else { throw SecurePailError.authenticationFailed }
            let split = current.count - tagLength
            do {
                let box = try AES.GCM.SealedBox(
                    nonce: nonce(index: index, last: last),
                    ciphertext: current.prefix(split),
                    tag: current.suffix(tagLength))
                try write(try AES.GCM.open(box, using: key, authenticating: header))
            } catch let error as SecurePailError {
                throw error
            } catch is CryptoKitError {
                throw SecurePailError.authenticationFailed
            }
            if last { return }
            current = next
            index += 1
        }
    }

    /// Reads until `count` bytes arrived or the input ended.
    private static func readExactly(_ read: (Int) throws -> Data, _ count: Int) throws -> Data {
        var out = Data()
        while out.count < count {
            let part = try read(count - out.count)
            if part.isEmpty { break }
            out.append(part)
        }
        return out
    }

    private static func streamFile(from source: URL, to destination: URL,
                                   _ body: (FileHandle, FileHandle) throws -> Void) throws {
        let fm = FileManager.default
        let tmp = destination.deletingLastPathComponent()
            .appendingPathComponent(".securepail-tmp-\(UUID().uuidString)")
        guard fm.createFile(atPath: tmp.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown)
        }
        var done = false
        defer { if !done { try? fm.removeItem(at: tmp) } }
        let input = try FileHandle(forReadingFrom: source)
        let output = try FileHandle(forWritingTo: tmp)
        defer { try? input.close(); try? output.close() }
        try body(input, output)
        try output.synchronize()
        try output.close()
        if fm.fileExists(atPath: destination.path) {
            _ = try fm.replaceItemAt(destination, withItemAt: tmp)
        } else {
            try fm.moveItem(at: tmp, to: destination)
        }
        done = true
    }
}

extension Data {
    var base64URLNoPadding: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    init?(base64URLNoPadding s: String) {
        var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b.count % 4 != 0 { b.append("=") }
        self.init(base64Encoded: b)
    }
}
