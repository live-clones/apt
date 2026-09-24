// -*- mode: cpp; mode: fold -*-
// Description							/*{{{*/
/* pkcs7-constraints.h - Certificate and signature constraint datatypes.
 *
 * Pure policy datatypes for PKCS#7/CMS verification.  This module knows
 * nothing about FileFd, X509_STORE, CMS_ContentInfo, or BIO — it only
 * holds collections of std::function callbacks that check an X509 cert.
 * The actual store-building and signature-verification logic lives in
 * pkcs7.h/.cc.
 *
 * DefaultRepoSignerPolicy() and DefaultRepoAnchorPolicy() assemble the
 * standard APT repository-signing policy (BasicConstraints, KeyUsage,
 * EKU, validity, SAN origin+suite matching, trust-anchor constraints)
 * from the built-in check factories, so callers do not need to assemble
 * the constraint objects themselves.
 *
 * New constraint kinds can be added by passing a new std::function to
 * CertificateConstraints::Add() — no subclass hierarchy or ABI change
 * needed.  Built-in check factories are internal to the .cc.
 *
 * This header is internal (APT_COMPILING_APT-guarded) and has no stable
 * ABI; the API may evolve over time.
 */
									/*}}}*/
#ifndef APT_PKCS7_CONSTRAINTS_H
#define APT_PKCS7_CONSTRAINTS_H

#include <apt-pkg/macros.h>

#ifdef APT_COMPILING_APT

#include <functional>
#include <string>

#include <openssl/x509.h>

namespace APT
{
namespace Internal
{

// Placeholder APT repository signing Extended Key Usage OID.
APT_PUBLIC extern char const *const REPO_SIGNING_EKU;

// Aggregate of certificate-level checks.  Each check is a
// std::function<bool(X509*)>; Apply() runs them in insertion order and
// short-circuits on the first failure, pushing a diagnostic via
// _error->Error().
class APT_PUBLIC CertificateConstraints
{
   void *d;

public:
   CertificateConstraints();
   ~CertificateConstraints();
   CertificateConstraints(CertificateConstraints &&) noexcept;
   CertificateConstraints &operator=(CertificateConstraints &&) noexcept;

   CertificateConstraints &Add(std::function<bool(X509 *)> check);
   bool Apply(X509 *cert);
};

// Assemble the default repo-signing leaf-certificate policy:
// BasicConstraints CA:FALSE critical, KeyUsage digitalSignature critical,
// EKU REPO_SIGNING_EKU, Validity, SubjectAltName(suite, origin).
APT_PUBLIC CertificateConstraints DefaultRepoSignerPolicy(std::string origin, std::string suite);

// Assemble the default trust-anchor policy: BasicConstraints CA:TRUE
// critical, KeyUsage keyCertSign.
APT_PUBLIC CertificateConstraints DefaultRepoAnchorPolicy();

} // namespace Internal
} // namespace APT

#endif // APT_COMPILING_APT

#endif
