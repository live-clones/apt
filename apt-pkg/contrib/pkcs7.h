// -*- mode: cpp; mode: fold -*-
// Description							/*{{{*/
/* pkcs7.h - X.509 trust store and detached CMS signature verifier.
 *
 * Loads a PEM certificate bundle into an X.509 trust store and verifies
 * a detached CMS/PKCS#7 signature against it.  X509Store is policy
 * agnostic: it performs the raw CMS_verify and accepts any signer that
 * passes the OpenSSL chain validation.  X509_PURPOSE_ANY is set on the
 * store's verify param (see pkcs7.cc for the full rationale); it is a
 * no-op purpose check because APT's repo-signing EKU is not a standard
 * X509_PURPOSE, so any signing-purpose constraints must be enforced
 * per-signer by the policy layer (VerifyCert() hook).
 *
 * Subclasses can override the protected VerifyCert()/VerifySignature()
 * virtual hooks to impose constraints on accepted signers or trust
 * anchors.
 *
 * VerifyDetach enforces two baseline constraints on every call, both
 * mirroring the policy knobs the gpgv method also honors (parity, no
 * policy beyond it):
 *  - A trusted-digest floor: MD2, MD4, MD5, SHA‑1 and RIPEMD‑160 are
 *    untrusted by default; the shared APT::Hashes::<name>::{Untrusted,Weak}
 *    options (also consumed by the gpgv method) can tighten or relax
 *    this per digest.
 *  - A signing-capability check: a signer whose KeyUsage extension is
 *    present but lacks digitalSignature is rejected (gpg accepts data
 *    signatures only from keys flagged for signing).  An absent
 *    KeyUsage extension means unrestricted use (RFC 5280).
 * Both run before any policy hook, so they apply uniformly to every
 * call site (acquire method and ReVerifyTrust).
 *
 * The unconstrained verifier trusts exactly what the admin pins in
 * Signed-By: any signing-capable certificate chaining to that anchor
 * is accepted, regardless of EKU or SAN.  EKU/SAN-based scoping is
 * deliberately not enforced here (it exceeds gpgv parity); operators
 * wanting scoping should pin a dedicated CA.  Hooks remain for
 * subclasses that need stronger policy.
 *
 * Known limitations:
 *  - No CRL or OCSP revocation checks (no distribution story yet).
 *  - Certificate validity (notBefore/notAfter) is enforced by
 *    CMS_verify at verification time; an expired signer or CA cert is
 *    rejected and there is no grace period or override knob.
 *  - CMS / ASN.1 is parsed in‑process, unlike gpgv's separate
 *    subprocess; seccomp filtering is opt‑in.
 *
 * The class uses the pImpl idiom (std::unique_ptr<Impl>) so that the
 * header does not expose OpenSSL types in the class layout; the ABI is
 * therefore stable across changes to the internal representation.
 *
 * This header is internal (APT_COMPILING_APT-guarded) and has no stable
 * ABI; the API may evolve over time.
 */
									/*}}}*/
#ifndef APT_PKCS7_H
#define APT_PKCS7_H

#include <apt-pkg/macros.h>

#ifdef APT_COMPILING_APT

#include <apt-pkg/fileutl.h>

#include <memory>
#include <string>

#include <openssl/x509.h>

namespace APT
{
namespace Internal
{

// Result of a VerifyDetach call.
struct APT_PUBLIC VerificationResult
{
   bool success = false;
   std::string signerSubject;     // X509_NAME_oneline of accepted signer
   std::string signerFingerprint; // SHA-256 hex
};

// Generic X.509 trust store + detached CMS verifier.  Policy-agnostic:
// accepts any signer that passes OpenSSL chain validation and the
// gpgv-parity baseline constraints (see above).  Subclasses can
// override VerifyCert()/VerifySignature() to impose constraints.
class APT_PUBLIC X509Store
{
   class Impl;                             // defined in pkcs7.cc
   std::unique_ptr<Impl> const d;

public:
   X509Store();
   virtual ~X509Store();

   // Load all PEM X.509 certificates from fd into the trust store.
   bool LoadCert(FileFd &fd);
   // Load from a file path directly.
   bool LoadCert(std::string const &path);

   // Verify a detached PEM CMS signature.  Orchestrates CMS_verify,
   // then invokes the protected virtual hooks so subclasses can apply
   // policy.  Returns false (via _error) on failure.
   bool VerifyDetach(FileFd &signature, FileFd &data,
		     VerificationResult &result);

protected:
   // Called once after CMS_verify succeeds, before walking signers.
   // Default: accept (no constraints).
   virtual bool VerifySignature() { return true; }
   // Called for each candidate signer cert.  Default: accept any.
   // PendingSigner() returns the cert currently being evaluated.
   virtual bool VerifyCert() { return true; }

   // The candidate signer being evaluated in the current VerifyCert()
   // call.  Valid only during VerifyDetach().
   X509 *PendingSigner();
};

} // namespace Internal
} // namespace APT

#endif // APT_COMPILING_APT

#endif
