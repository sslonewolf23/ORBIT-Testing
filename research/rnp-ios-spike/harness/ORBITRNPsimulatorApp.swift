import Foundation
import UIKit
import Darwin

@UIApplicationMain
final class ORBITRNPTestAppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        runVerifierSuite()
        return true
    }

    private func runVerifierSuite() {
        let bundle = Bundle.main.bundleURL
        let cases: [(String, String, String, String, Bool)] = [
            ("trusted-primary", "trusted-keyring.gpg", "valid-trusted.InRelease", "trusted-primary.fingerprint", true),
            ("trusted-signing-subkey", "trusted-keyring.gpg", "valid-subkey.InRelease", "trusted-primary.fingerprint", true),
            ("wrong-primary-fingerprint", "trusted-keyring.gpg", "valid-trusted.InRelease", "other-primary.fingerprint", false),
            ("tampered-payload", "trusted-keyring.gpg", "tampered-payload.InRelease", "trusted-primary.fingerprint", false),
            ("tampered-signature", "trusted-keyring.gpg", "tampered-signature.InRelease", "trusted-primary.fingerprint", false),
            ("expired-key", "expired-keyring.gpg", "expired-key.InRelease", "expired-primary.fingerprint", false),
            ("revoked-key", "revoked-keyring.gpg", "revoked-key.InRelease", "revoked-primary.fingerprint", false),
            ("weak-hash", "trusted-keyring.gpg", "weak-hash.InRelease", "trusted-primary.fingerprint", false),
            ("future-signature", "trusted-keyring.gpg", "future-signature.InRelease", "trusted-primary.fingerprint", false),
            ("expired-signature", "old-signer-keyring.gpg", "expired-signature.InRelease", "old-signer-primary.fingerprint", false),
            ("multiple-signatures", "combined-keyring.gpg", "multiple-signatures.InRelease", "trusted-primary.fingerprint", false),
            ("malformed-framing", "trusted-keyring.gpg", "malformed-framing.InRelease", "trusted-primary.fingerprint", false),
            ("truncated-document", "trusted-keyring.gpg", "truncated.InRelease", "trusted-primary.fingerprint", false),
            ("malformed-keyring", "malformed-keyring.gpg", "valid-trusted.InRelease", "trusted-primary.fingerprint", false),
            ("empty-keyring", "empty-keyring.gpg", "valid-trusted.InRelease", "trusted-primary.fingerprint", false),
            ("bad-packet-header", "bad-packet-header.gpg", "valid-trusted.InRelease", "trusted-primary.fingerprint", false),
            ("truncated-packet-header", "truncated-packet-header.gpg", "valid-trusted.InRelease", "trusted-primary.fingerprint", false),
            ("invalid-packet-length", "invalid-packet-length.gpg", "valid-trusted.InRelease", "trusted-primary.fingerprint", false),
            ("unsupported-key-algorithm", "unsupported-key-algorithm.gpg", "valid-trusted.InRelease", "trusted-primary.fingerprint", false),
            ("wrong-signer-keyring", "other-keyring.gpg", "valid-trusted.InRelease", "trusted-primary.fingerprint", false)
        ]

        var lines = ["ORBIT RNP iOS Simulator Runtime Tests", "platform=\(UIDevice.current.systemName) \(UIDevice.current.systemVersion)", "architecture=arm64", "cases=\(cases.count)"]
        var failures = 0

        for test in cases {
            let keyURL = bundle.appendingPathComponent(test.1)
            let messageURL = bundle.appendingPathComponent(test.2)
            let fingerprintURL = bundle.appendingPathComponent(test.3)
            do {
                let key = try Data(contentsOf: keyURL)
                let message = try Data(contentsOf: messageURL)
                let fingerprint = try String(contentsOf: fingerprintURL, encoding: .utf8)
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                var result = orbit_rnp_verify_result()
                let code = key.withUnsafeBytes { keyBytes in
                    message.withUnsafeBytes { messageBytes in
                        fingerprint.withCString { fingerprintCString in
                            orbit_rnp_verify_inrelease(
                                messageBytes.bindMemory(to: UInt8.self).baseAddress,
                                message.count,
                                keyBytes.bindMemory(to: UInt8.self).baseAddress,
                                key.count,
                                fingerprintCString,
                                &result
                            )
                        }
                    }
                }
                let accepted = code == ORBIT_RNP_VERIFY_VALID
                let passed = accepted == test.4
                if !passed { failures += 1 }
                lines.append("\(passed ? "PASS" : "FAIL") \(test.0) expected=\(test.4 ? "ACCEPT" : "BLOCK") actual=\(accepted ? "ACCEPT" : "BLOCK") code=\(code.rawValue)")
            } catch {
                failures += 1
                lines.append("FAIL \(test.0) fixture_error=\(error.localizedDescription)")
            }
        }

        lines.append("result=\(failures == 0 ? "PASS" : "FAIL")")
        lines.append("failures=\(failures)")
        let report = lines.joined(separator: "\n") + "\n"
        print(report)
        do {
            let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            try report.write(to: documents.appendingPathComponent("simulator-results.txt"),
                             atomically: true, encoding: .utf8)
        } catch {
            print("Unable to persist simulator report: \(error)")
            exit(2)
        }
    }
}
