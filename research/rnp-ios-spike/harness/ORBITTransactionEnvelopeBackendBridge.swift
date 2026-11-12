import Foundation
import Darwin

private final class ORBITSyncResultBox<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Result<Value, Error>?

    func set(_ result: Result<Value, Error>) {
        lock.lock()
        stored = result
        lock.unlock()
    }

    func get() -> Result<Value, Error>? {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }
}

/*
 * Retain this bridge for the entire C transaction. C callbacks are synchronous,
 * so they hop to the Swift actor and wait on a background worker thread. Never
 * invoke the C transaction API from the main thread. The surrounding caller
 * must already hold ORBIT's cross-process transaction lock.
 */
final class ORBITTransactionEnvelopeBackendBridge: @unchecked Sendable {
    let store: ORBITTransactionEnvelopeStore

    init(store: ORBITTransactionEnvelopeStore) {
        self.store = store
    }

    func makeBackend() -> orbit_package_filesystem_envelope_backend {
        orbit_package_filesystem_envelope_backend(
            context: Unmanaged.passUnretained(self).toOpaque(),
            load: orbit_envelope_backend_load,
            release: orbit_envelope_backend_release,
            store_atomic: orbit_envelope_backend_store_atomic
        )
    }
}

@_cdecl("orbit_envelope_backend_load")
func orbit_envelope_backend_load(
    _ context: UnsafeMutableRawPointer?,
    _ payloadOut: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ lengthOut: UnsafeMutablePointer<Int>?,
    _ digestOut: UnsafeMutablePointer<UInt8>?
) -> Bool {
    guard !Thread.isMainThread,
          let context, let payloadOut, let lengthOut, let digestOut else {
        return false
    }
    let bridge = Unmanaged<ORBITTransactionEnvelopeBackendBridge>
        .fromOpaque(context).takeUnretainedValue()
    let semaphore = DispatchSemaphore(value: 0)
    let box = ORBITSyncResultBox<(Data, Data)>()

    Task {
        do {
            box.set(.success(try await bridge.store.loadForBackend()))
        } catch {
            box.set(.failure(error))
        }
        semaphore.signal()
    }
    semaphore.wait()

    guard let result = box.get(),
          let (payload, digest) = try? result.get(),
          !payload.isEmpty, digest.count == 32,
          let allocation = malloc(payload.count) else {
        return false
    }
    let output = allocation.assumingMemoryBound(to: UInt8.self)
    payload.copyBytes(to: output, count: payload.count)
    payloadOut.pointee = output
    lengthOut.pointee = payload.count
    digest.withUnsafeBytes { raw in
        memcpy(digestOut, raw.baseAddress!, 32)
    }
    return true
}

@_cdecl("orbit_envelope_backend_release")
func orbit_envelope_backend_release(
    _ context: UnsafeMutableRawPointer?,
    _ payload: UnsafeMutablePointer<UInt8>?
) {
    _ = context
    if let payload { free(payload) }
}

@_cdecl("orbit_envelope_backend_store_atomic")
func orbit_envelope_backend_store_atomic(
    _ context: UnsafeMutableRawPointer?,
    _ expectedRevision: UInt64,
    _ expectedDigest: UnsafePointer<UInt8>?,
    _ nextPayload: UnsafePointer<UInt8>?,
    _ nextPayloadLength: Int,
    _ nextDigestOut: UnsafeMutablePointer<UInt8>?
) -> Bool {
    guard !Thread.isMainThread,
          let context, let expectedDigest, let nextPayload,
          let nextDigestOut,
          nextPayloadLength >= 44,
          nextPayloadLength <= 48 * 1024 * 1024 else {
        return false
    }
    let bridge = Unmanaged<ORBITTransactionEnvelopeBackendBridge>
        .fromOpaque(context).takeUnretainedValue()
    let payload = Data(bytes: nextPayload, count: nextPayloadLength)
    let expected = Data(bytes: expectedDigest, count: 32)
    let semaphore = DispatchSemaphore(value: 0)
    let box = ORBITSyncResultBox<Data>()

    Task {
        do {
            box.set(.success(try await bridge.store.commit(
                payload: payload,
                expectedRevision: expectedRevision,
                expectedDigest: expected)))
        } catch {
            box.set(.failure(error))
        }
        semaphore.signal()
    }
    semaphore.wait()

    guard let result = box.get(),
          let digest = try? result.get(),
          digest.count == 32 else {
        return false
    }
    digest.withUnsafeBytes { raw in
        memcpy(nextDigestOut, raw.baseAddress!, 32)
    }
    return true
}
