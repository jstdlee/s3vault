import CryptoKit
import XCTest
@testable import SecurePailCrypto

/// Known-answer vectors written by the desktop app (Go). They are the contract
/// between the platforms: if these pass, files and key files are interchangeable.
private struct Vectors: Decodable {
    struct Object: Decodable {
        let saltHex: String
        let chunkSize: Int
        let plaintextHex: String
        let objectBase64: String
    }
    struct KeyFileVector: Decodable {
        let password: String
        let nonceHex: String
        let saltHex: String
        let json: String
    }
    let keyHex: String
    let object: Object
    let keyFile: KeyFileVector
}

private func data(hex: String) -> Data {
    var out = Data()
    var i = hex.startIndex
    while i < hex.endIndex {
        let n = hex.index(i, offsetBy: 2)
        out.append(UInt8(hex[i..<n], radix: 16)!)
        i = n
    }
    return out
}

final class PortableSuiteTests: XCTestCase {
    private func vectors() throws -> Vectors {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "portable-vectors", withExtension: "json"))
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url))
    }

    private func storedKey(_ v: Vectors) -> String {
        SPE.storedKey(SymmetricKey(data: data(hex: v.keyHex)))
    }

    func testDecryptsObjectWrittenByDesktop() throws {
        let v = try vectors()
        let object = try XCTUnwrap(Data(base64Encoded: v.object.objectBase64))
        let plain = try SPE.decrypt(object, key: storedKey(v))
        XCTAssertEqual(plain, data(hex: v.object.plaintextHex))
    }

    func testProducesTheSameBytesAsDesktop() throws {
        let v = try vectors()
        let salt = data(hex: v.object.saltHex)
        var input = data(hex: v.object.plaintextHex)[...]
        var out = Data()
        try SPE.encryptChunks(
            read: { count in
                let part = Data(input.prefix(count))
                input = input.dropFirst(part.count)
                return part
            },
            write: { out.append($0) },
            key: SymmetricKey(data: data(hex: v.keyHex)), salt: salt, chunkSize: v.object.chunkSize)
        XCTAssertEqual(out.base64EncodedString(), v.object.objectBase64)
    }

    func testOpensKeyFileWrittenByDesktop() throws {
        let v = try vectors()
        let key = try KeyBackup.open(Data(v.keyFile.json.utf8), password: v.keyFile.password)
        XCTAssertEqual(key, storedKey(v))
        XCTAssertThrowsError(try KeyBackup.open(Data(v.keyFile.json.utf8), password: "wrong")) {
            XCTAssertEqual($0 as? SecurePailError, .wrongPassword)
        }
    }

    func testWrapsKeyLikeDesktop() throws {
        let v = try vectors()
        let desktop = try KeyBackup.decoder().decode(KeyFile.self, from: Data(v.keyFile.json.utf8))
        let mine = try KeyBackup.wrap(key: storedKey(v), password: v.keyFile.password, iterations: desktop.iterations,
                                      salt: data(hex: v.keyFile.saltHex), nonce: data(hex: v.keyFile.nonceHex),
                                      created: desktop.created)
        XCTAssertEqual(mine.wrappedKey, desktop.wrappedKey)
        XCTAssertEqual(mine.check, desktop.check)
    }

    func testRoundTripSizes() throws {
        let key = SPE.generateKey()
        for n in [0, 1, 100, SPE.defaultChunkSize - 1, SPE.defaultChunkSize, SPE.defaultChunkSize + 1, 3 * SPE.defaultChunkSize + 7] {
            let plain = Data((0..<n).map { UInt8(truncatingIfNeeded: $0 &* 31) })
            let object = try SPE.encrypt(plain, key: key)
            let chunks = max(1, (n + SPE.defaultChunkSize - 1) / SPE.defaultChunkSize)
            XCTAssertEqual(object.count, SPE.headerLength + n + chunks * 16, "size for \(n)")
            XCTAssertEqual(try SPE.decrypt(object, key: key), plain, "round trip for \(n)")
        }
    }

    func testDetectsTamperingTruncationAndWrongKey() throws {
        let key = SPE.generateKey()
        let plain = Data(repeating: 7, count: 2 * SPE.defaultChunkSize + 10)
        let object = try SPE.encrypt(plain, key: key)
        func fails(_ bad: Data, _ k: String? = nil, file: StaticString = #filePath, line: UInt = #line) {
            XCTAssertThrowsError(try SPE.decrypt(bad, key: k ?? key), file: file, line: line)
        }
        fails(object, SPE.generateKey())
        var flipped = object; flipped[flipped.count / 2] ^= 1; fails(flipped)
        var header = object; header[9] ^= 1; fails(header)
        fails(Data(object.prefix(SPE.headerLength + SPE.defaultChunkSize + 16))) // cut at a chunk boundary
        fails(Data(object.dropLast()))
        fails(object + Data([0]))
        XCTAssertThrowsError(try SPE.decrypt(Data("hello".utf8), key: key)) {
            XCTAssertEqual($0 as? SecurePailError, .notPortableFormat)
        }
    }

    func testFileRoundTripAndNoPartialOutput() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let key = SPE.generateKey()
        let plain = Data((0..<(2 * SPE.defaultChunkSize + 5)).map { UInt8(truncatingIfNeeded: $0) })
        let src = dir.appendingPathComponent("a.bin"), enc = dir.appendingPathComponent("a.spe")
        let back = dir.appendingPathComponent("b.bin")
        try plain.write(to: src)
        try SPE.encryptFile(at: src, to: enc, key: key)
        try SPE.decryptFile(at: enc, to: back, key: key)
        XCTAssertEqual(try Data(contentsOf: back), plain)
        // The Data path reads what the file path wrote.
        XCTAssertEqual(try SPE.decrypt(Data(contentsOf: enc), key: key), plain)

        var damaged = try Data(contentsOf: enc); damaged[damaged.count - 1] ^= 1
        let bad = dir.appendingPathComponent("bad.spe"), out = dir.appendingPathComponent("out.bin")
        try damaged.write(to: bad)
        XCTAssertThrowsError(try SPE.decryptFile(at: bad, to: out, key: key))
        XCTAssertFalse(FileManager.default.fileExists(atPath: out.path), "a failed decrypt must leave no file")
        let leftovers = try FileManager.default.contentsOfDirectory(atPath: dir.path).filter { $0.hasPrefix(".securepail-tmp") }
        XCTAssertTrue(leftovers.isEmpty, "temporary files left: \(leftovers)")
    }

    func testKeyFileAndRecoveryRoundTrip() throws {
        let key = SPE.generateKey()
        let file = try KeyBackup.make(key: key, password: "Pässword-Ünïcode 123", iterations: 100_000)
        XCTAssertTrue(KeyBackup.isKeyFile(file))
        XCTAssertEqual(try KeyBackup.open(file, password: "Pässword-Ünïcode 123"), key)
        // The same password typed with decomposed characters opens it too (NFC).
        XCTAssertEqual(try KeyBackup.open(file, password: "Pa\u{308}ssword-U\u{308}ni\u{308}code 123"), key)
        let recovery = try KeyBackup.recoveryString(key: key)
        XCTAssertEqual(recovery.count, 16 * 4 + 15)
        XCTAssertEqual(try KeyBackup.parseRecovery(recovery.lowercased().replacingOccurrences(of: "-", with: " ")), key)
        XCTAssertThrowsError(try KeyBackup.parseRecovery("12-34"))
        XCTAssertThrowsError(try SPE.masterKey("a typed passphrase"))
    }
}
