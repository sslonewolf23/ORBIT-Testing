import Foundation
import CryptoKit
import DeviceCheck
import Security
import Darwin

enum ORBITEnvelopeStoreError: Error {
    case invalidConfiguration
    case keychain(OSStatus)
    case identityMissing
    case identityAlreadyExists
    case invalidIdentity
    case unsafeDirectory
    case unsafeFile
    case malformedEnvelope
    case authenticationFailed
    case witnessUnavailable
    case witnessConflict
    case revisionOverflow
    case concurrentAccess
    case ioFailure
    case httpFailure(Int)
}

private struct ORBITIdentity {
    let keyID: String
    let recoveryCredential: Data
    let macKey: SymmetricKey
}

private struct ORBITWitnessHead: Equatable {
    let revision: UInt64
    let tombstone: Bool
    let digest: Data
}

private final class ORBITNoRedirectDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

/*
 * Research iOS persistence adapter for the combined ORBE envelope.
 *
 * The caller MUST hold ORBIT's cross-process package transaction lock across
 * every load/commit/recovery operation. This actor serializes only this
 * process. App Attest enrollment and recovery are separate, explicit flows;
 * installIdentity accepts credentials only after those flows have succeeded.
 *
 * Each candidate is first written as a durable pending file, then anchored by
 * App Attest CAS, then atomically promoted. Recovery can finish either side of
 * that sequence without guessing. The witness digest covers payload || HMAC.
 */
actor ORBITTransactionEnvelopeStore {
    private let directoryURL: URL
    private let witnessOrigin: URL
    private let identity: ORBITIdentity
    private let session: URLSession
    private var busy = false

    private let currentName = "orbit-transaction-envelope.bin"
    private let pendingName = "orbit-transaction-envelope.pending"
    private let maxFileBytes = 48 * 1024 * 1024 + 32

    init(directoryURL: URL, witnessOrigin: URL) throws {
        guard witnessOrigin.scheme?.lowercased() == "https",
              witnessOrigin.host != nil,
              witnessOrigin.user == nil,
              witnessOrigin.password == nil,
              witnessOrigin.path.isEmpty || witnessOrigin.path == "/",
              witnessOrigin.query == nil,
              witnessOrigin.fragment == nil else {
            throw ORBITEnvelopeStoreError.invalidConfiguration
        }
        self.directoryURL = directoryURL
        self.witnessOrigin = witnessOrigin
        self.identity = try Self.loadIdentity()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        self.session = URLSession(configuration: configuration,
                                   delegate: ORBITNoRedirectDelegate(),
                                   delegateQueue: nil)
    }

    /*
     * Call only after App Attest registration has bound keyID and the
     * uniformly random 32-byte recovery credential to this installation.
     * The returned MAC key is never exported. A missing Keychain identity
     * during normal operation is an error; this method never silently
     * replaces an existing identity.
     */
    static func installIdentity(keyID: String,
                                recoveryCredential: Data,
                                directoryURL: URL) throws {
        let keyBytes = Data(keyID.utf8)
        guard !keyID.isEmpty, keyBytes.count <= 128,
              recoveryCredential.count == 32 else {
            throw ORBITEnvelopeStoreError.invalidIdentity
        }
        let directoryFD = try openPrivateDirectory(directoryURL)
        defer { close(directoryFD) }
        if Self.fileExists(directoryFD, "orbit-transaction-envelope.bin") ||
           Self.fileExists(directoryFD, "orbit-transaction-envelope.pending") {
            throw ORBITEnvelopeStoreError.identityAlreadyExists
        }

        var macBytes = Data(count: 32)
        let randomStatus = macBytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
        }
        guard randomStatus == errSecSuccess else {
            throw ORBITEnvelopeStoreError.keychain(randomStatus)
        }

        var record = Data([1])
        Self.appendUInt16(UInt16(keyBytes.count), to: &record)
        record.append(keyBytes)
        record.append(recoveryCredential)
        record.append(macBytes)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.orbit.transaction-envelope",
            kSecAttrAccount as String: "device-identity-v1",
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: record
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw ORBITEnvelopeStoreError.keychain(status)
        }
    }

    func loadAndRecover() async throws -> Data? {
        guard !busy else { throw ORBITEnvelopeStoreError.concurrentAccess }
        busy = true
        defer { busy = false }
        return try await recoverUnlocked()
    }

    /*
     * payload must be a validated canonical ORBE byte string. The caller
     * validates the C state transition before calling this method. The store
     * enforces consecutive revisions and independently anchors the digest.
     */
    func commit(payload: Data) async throws {
        guard !busy else { throw ORBITEnvelopeStoreError.concurrentAccess }
        busy = true
        defer { busy = false }

        _ = try await recoverUnlocked()
        let directoryFD = try Self.openPrivateDirectory(directoryURL)
        defer { close(directoryFD) }

        let currentFile = try readAuthenticatedFile(directoryFD, name: currentName)
        let oldHead: ORBITWitnessHead
        if let currentFile {
            oldHead = try makeHead(file: currentFile)
        } else {
            oldHead = ORBITWitnessHead(revision: 0, tombstone: true,
                                       digest: Data(repeating: 0, count: 32))
        }

        let nextRevision = oldHead.revision.addingReportingOverflow(1)
        guard !nextRevision.overflow else {
            throw ORBITEnvelopeStoreError.revisionOverflow
        }
        guard try envelopeRevision(payload) == nextRevision.partialValue else {
            throw ORBITEnvelopeStoreError.malformedEnvelope
        }

        let pendingFile = seal(payload)
        try writeAtomically(pendingFile, name: pendingName, directoryFD: directoryFD)
        let nextHead = try makeHead(file: pendingFile)

        do {
            try await witnessCompareAndSwap(old: oldHead, next: nextHead)
        } catch {
            // A lost response is resolved by reading the independent head.
            // If it already equals next, promotion is safe; otherwise pending
            // remains durable and the caller must block package operations.
            let observed = try await witnessHead()
            guard observed == nextHead else { throw error }
        }
        try promotePending(directoryFD)
    }

    private func recoverUnlocked() async throws -> Data? {
        let directoryFD = try Self.openPrivateDirectory(directoryURL)
        defer { close(directoryFD) }

        let currentFile = try readAuthenticatedFile(directoryFD, name: currentName)
        let pendingFile = try readAuthenticatedFile(directoryFD, name: pendingName)
        let observed = try await witnessHead()

        let currentHead: ORBITWitnessHead
        if let currentFile {
            currentHead = try makeHead(file: currentFile)
        } else {
            currentHead = ORBITWitnessHead(revision: 0, tombstone: true,
                                           digest: Data(repeating: 0, count: 32))
        }

        if let pendingFile {
            let pendingHead = try makeHead(file: pendingFile)
            if observed == pendingHead {
                try promotePending(directoryFD)
                return try openEnvelopePayload(pendingFile)
            }
            let expectedRevision = currentHead.revision.addingReportingOverflow(1)
            guard observed == currentHead, !expectedRevision.overflow,
                  pendingHead.revision == expectedRevision.partialValue else {
                throw ORBITEnvelopeStoreError.witnessConflict
            }
            do {
                try await witnessCompareAndSwap(old: currentHead, next: pendingHead)
            } catch {
                let afterRetry = try await witnessHead()
                guard afterRetry == pendingHead else { throw error }
            }
            try promotePending(directoryFD)
            return try openEnvelopePayload(pendingFile)
        }

        guard observed == currentHead else {
            throw ORBITEnvelopeStoreError.witnessConflict
        }
        guard let currentFile else { return nil }
        return try openEnvelopePayload(currentFile)
    }

    private func witnessHead() async throws -> ORBITWitnessHead {
        let requestBytes = Data("ORBIT-JOURNAL-HEAD-V1\0".utf8) + Data(identity.keyID.utf8)
        let assertion = try await makeAssertion(for: requestBytes)
        let response = try await sendJSON(
            path: "/v1/orbit/journal/head",
            body: [
                "keyID": identity.keyID,
                "request": requestBytes.base64EncodedString(),
                "assertion": assertion.base64EncodedString(),
                "recoveryCredential": identity.recoveryCredential.base64EncodedString()
            ],
            expectedStatus: 200)
        guard let object = try JSONSerialization.jsonObject(with: response) as? [String: Any],
              let revision = object["revision"] as? NSNumber,
              let digestText = object["digest"] as? String,
              let digest = Data(base64Encoded: digestText),
              digest.count == 32,
              let tombstone = object["tombstone"] as? Bool else {
            throw ORBITEnvelopeStoreError.witnessUnavailable
        }
        return ORBITWitnessHead(revision: revision.uint64Value,
                                tombstone: tombstone, digest: digest)
    }

    private func witnessCompareAndSwap(old: ORBITWitnessHead,
                                       next: ORBITWitnessHead) async throws {
        let requestBytes = Data("ORBIT-JOURNAL-CAS-V1\0".utf8) +
            Data(identity.keyID.utf8) + encodeHead(old) + encodeHead(next)
        let assertion = try await makeAssertion(for: requestBytes)
        _ = try await sendJSON(
            path: "/v1/orbit/journal/compare-and-swap",
            body: [
                "keyID": identity.keyID,
                "request": requestBytes.base64EncodedString(),
                "assertion": assertion.base64EncodedString(),
                "recoveryCredential": identity.recoveryCredential.base64EncodedString()
            ],
            expectedStatus: 204)
    }

    private func makeAssertion(for requestBytes: Data) async throws -> Data {
        guard DCAppAttestService.shared.isSupported else {
            throw ORBITEnvelopeStoreError.witnessUnavailable
        }
        let clientHash = Data(SHA256.hash(data: requestBytes))
        return try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Data, Error>) in
            DCAppAttestService.shared.generateAssertion(
                identity.keyID, clientDataHash: clientHash) { assertion, error in
                    if let error {
                        continuation.resume(throwing: error)
                    } else if let assertion {
                        continuation.resume(returning: assertion)
                    } else {
                        continuation.resume(throwing: ORBITEnvelopeStoreError.witnessUnavailable)
                    }
                }
        }
    }

    private func sendJSON(path: String, body: [String: String],
                          expectedStatus: Int) async throws -> Data {
        let url = path.split(separator: "/").reduce(witnessOrigin) { $0.appendingPathComponent(String($1)) }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 10
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.httpBody = try JSONSerialization.data(withJSONObject: body,
                                                      options: [.sortedKeys])
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse,
              http.url?.scheme == "https",
              http.url?.host == witnessOrigin.host,
              http.url?.port == witnessOrigin.port else {
            throw ORBITEnvelopeStoreError.witnessUnavailable
        }
        guard http.statusCode == expectedStatus else {
            if http.statusCode == 409 { throw ORBITEnvelopeStoreError.witnessConflict }
            throw ORBITEnvelopeStoreError.httpFailure(http.statusCode)
        }
        return data
    }

    private func seal(_ payload: Data) -> Data {
        let key = identity.macKey
        let tag = HMAC<SHA256>.authenticationCode(for: payload, using: key)
        return payload + Data(tag)
    }

    private func readAuthenticatedFile(_ directoryFD: Int32,
                                       name: String) throws -> Data? {
        let descriptor = openat(directoryFD, name,
                                O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        if descriptor < 0 {
            if errno == ENOENT { return nil }
            throw ORBITEnvelopeStoreError.ioFailure
        }
        defer { close(descriptor) }

        var status = stat()
        guard fstat(descriptor, &status) == 0,
              (status.st_mode & S_IFMT) == S_IFREG,
              status.st_uid == geteuid(),
              (status.st_mode & 0o077) == 0,
              status.st_size >= 32,
              status.st_size <= Int64(maxFileBytes) else {
            throw ORBITEnvelopeStoreError.unsafeFile
        }

        var file = Data()
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: 64 * 1024)
        defer { buffer.deallocate() }
        while true {
            let count = read(descriptor, buffer, 64 * 1024)
            if count < 0 {
                if errno == EINTR { continue }
                throw ORBITEnvelopeStoreError.ioFailure
            }
            if count == 0 { break }
            file.append(buffer, count: count)
            if file.count > maxFileBytes { throw ORBITEnvelopeStoreError.unsafeFile }
        }
        guard file.count >= 32 else { throw ORBITEnvelopeStoreError.unsafeFile }
        let payload = Data(file.dropLast(32))
        let tag = Data(file.suffix(32))
        guard HMAC<SHA256>.isValidAuthenticationCode(
            tag, authenticating: payload, using: identity.macKey) else {
            throw ORBITEnvelopeStoreError.authenticationFailed
        }
        _ = try envelopeRevision(payload)
        return file
    }

    private func openEnvelopePayload(_ file: Data) throws -> Data {
        guard file.count >= 32 else { throw ORBITEnvelopeStoreError.unsafeFile }
        return Data(file.dropLast(32))
    }

    private func makeHead(file: Data) throws -> ORBITWitnessHead {
        let payload = try openEnvelopePayload(file)
        return ORBITWitnessHead(
            revision: try envelopeRevision(payload),
            tombstone: false,
            digest: Data(SHA256.hash(data: file)))
    }

    private func envelopeRevision(_ payload: Data) throws -> UInt64 {
        guard payload.count >= 44,
              payload.prefix(4) == Data("ORBE".utf8),
              payload[4] == 1 else {
            throw ORBITEnvelopeStoreError.malformedEnvelope
        }
        var revision: UInt64 = 0
        for byte in payload[8..<16] { revision = (revision << 8) | UInt64(byte) }
        guard revision > 0 else { throw ORBITEnvelopeStoreError.malformedEnvelope }
        return revision
    }

    private func writeAtomically(_ data: Data, name: String,
                                 directoryFD: Int32) throws {
        guard data.count <= maxFileBytes,
              !Self.fileExists(directoryFD, name) else {
            throw ORBITEnvelopeStoreError.ioFailure
        }
        let temporary = ".orbit-envelope-\(UUID().uuidString).tmp"
        let descriptor = openat(directoryFD, temporary,
                                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                                mode_t(0o600))
        guard descriptor >= 0 else { throw ORBITEnvelopeStoreError.ioFailure }
        var keepTemporary = true
        defer {
            close(descriptor)
            if keepTemporary { _ = unlinkat(directoryFD, temporary, 0) }
        }

        let writeStatus = data.withUnsafeBytes { raw -> Bool in
            guard let base = raw.baseAddress else { return false }
            var offset = 0
            while offset < raw.count {
                let written = write(descriptor, base.advanced(by: offset),
                                    raw.count - offset)
                if written < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                if written == 0 { return false }
                offset += written
            }
            return true
        }
        guard writeStatus, fsync(descriptor) == 0,
              renameat(directoryFD, temporary, directoryFD, name) == 0,
              fsync(directoryFD) == 0 else {
            throw ORBITEnvelopeStoreError.ioFailure
        }
        keepTemporary = false
    }

    private func promotePending(_ directoryFD: Int32) throws {
        guard renameat(directoryFD, pendingName, directoryFD, currentName) == 0,
              fsync(directoryFD) == 0 else {
            throw ORBITEnvelopeStoreError.ioFailure
        }
    }

    private static func openPrivateDirectory(_ url: URL) throws -> Int32 {
        let descriptor = open(url.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw ORBITEnvelopeStoreError.unsafeDirectory }
        var status = stat()
        guard fstat(descriptor, &status) == 0,
              (status.st_mode & S_IFMT) == S_IFDIR,
              status.st_uid == geteuid(),
              (status.st_mode & 0o077) == 0 else {
            close(descriptor)
            throw ORBITEnvelopeStoreError.unsafeDirectory
        }
        return descriptor
    }

    private static func loadIdentity() throws -> ORBITIdentity {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.orbit.transaction-envelope",
            kSecAttrAccount as String: "device-identity-v1",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            throw status == errSecItemNotFound ?
                ORBITEnvelopeStoreError.identityMissing :
                ORBITEnvelopeStoreError.keychain(status)
        }
        guard data.count >= 1 + 2 + 1 + 64, data[0] == 1 else {
            throw ORBITEnvelopeStoreError.invalidIdentity
        }
        let keyLength = Int(data[1]) << 8 | Int(data[2])
        let expectedLength = 3 + keyLength + 64
        guard keyLength > 0, keyLength <= 128, data.count == expectedLength,
              let keyID = String(data: data[3..<(3 + keyLength)], encoding: .utf8) else {
            throw ORBITEnvelopeStoreError.invalidIdentity
        }
        let credentialStart = 3 + keyLength
        let credential = Data(data[credentialStart..<(credentialStart + 32)])
        let macKey = Data(data[(credentialStart + 32)..<(credentialStart + 64)])
        return ORBITIdentity(keyID: keyID, recoveryCredential: credential,
                             macKey: SymmetricKey(data: macKey))
    }

    private static func fileExists(_ directoryFD: Int32, _ name: String) -> Bool {
        var status = stat()
        return fstatat(directoryFD, name, &status, AT_SYMLINK_NOFOLLOW) == 0
    }

    private func encodeHead(_ head: ORBITWitnessHead) -> Data {
        var data = Data()
        appendUInt64(head.revision, to: &data)
        data.append(head.tombstone ? 1 : 0)
        data.append(head.digest)
        return data
    }

    private static func appendUInt16(_ value: UInt16, to data: inout Data) {
        data.append(UInt8(value >> 8))
        data.append(UInt8(value))
    }

    private func appendUInt64(_ value: UInt64, to data: inout Data) {
        for shift in stride(from: 56, through: 0, by: -8) {
            data.append(UInt8((value >> UInt64(shift)) & 0xff))
        }
    }
}
