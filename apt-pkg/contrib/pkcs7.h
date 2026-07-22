// -*- mode: cpp; mode: fold -*-
// Description							/*{{{*/
/* pkcs7.h - X.509 trust store and detached CMS signature verifier.
 *
 * Loads a PEM certificate bundle into an X.509 trust store and verifies
 * a detached CMS/PKCS#7 signature against it.  X509Store is policy
 * agnostic: it performs the raw CMS_verify and accepts any signer that
 * passes the OpenSSL chain validation.
 *
 * Constrained (private X509Store subclass) overlays caller-supplied
 * CertificateConstraints — a signer policy applied to each candidate
 * signer, and an anchor policy applied to every loaded bundle cert —
 * via the protected VerifyCert()/VerifySignature() virtual hooks.
 * Callers build the constraint sets with DefaultRepoSignerPolicy() and
 * DefaultRepoAnchorPolicy() (see pkcs7-constraints.h).
 *
 * Both classes use the pImpl idiom (std::unique_ptr<Impl>) so that the
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

#include <apt-pkg/pkcs7-constraints.h>
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
// accepts any signer that passes OpenSSL chain validation.  Subclasses
// can override VerifyCert()/VerifySignature() to impose constraints.
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

   // Apply a constraint set to every loaded bundle certificate.
   // Returns false on first failure.  Used by Constrained::VerifySignature().
   bool ApplyToAllCerts(CertificateConstraints &policy);
};

// Constrained store: overlays caller-supplied certificate constraints
// on top of X509Store's raw verification.  Inherits X509Store privately
// so the base interface is an implementation detail, not part of the
// public API.
class APT_PUBLIC Constrained final : private X509Store
{
   CertificateConstraints signerPolicy;
   CertificateConstraints anchorPolicy;

public:
   Constrained(CertificateConstraints signer, CertificateConstraints anchor);
   ~Constrained() override;

   using X509Store::LoadCert;
   bool VerifyDetach(FileFd &signature, FileFd &data,
		     VerificationResult &result)
   { return X509Store::VerifyDetach(signature, data, result); }

protected:
   bool VerifyCert() override;
   bool VerifySignature() override;
};

} // namespace Internal
} // namespace APT

#endif // APT_COMPILING_APT

#endif
