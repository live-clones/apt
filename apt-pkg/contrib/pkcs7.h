/*
 * pkcs7.h - Base class of the X.509 trust store and CMS signature verifier
 *
 * Copyright (c) 2026 Canonical Ltd
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * Contains the BaseX509Store class, which provides basic behavior for loading
 * a trust store and verifying detached CMS signatures.
 */

#ifndef APT_PKCS7_H
#define APT_PKCS7_H

#include <apt-pkg/fileutl.h>
#include <apt-pkg/header-is-private.h>
#include <apt-pkg/macros.h>

#include <memory>
#include <string>
#include <vector>

#include <openssl/types.h>

// CMS_SignerInfo is needed as an opaque handle for the VerifySignature() hook
// and nothing else. Including <openssl/cms.h> for that one typedef would drag
// some 12k lines of X.509v3 and PKCS #7 declarations into every consumer, and
// no other apt-pkg header exposes OpenSSL at all, so mirror the declaration
// from cms.h (where it is an implementation detail of the same ABI) instead.
// Redeclaring an identical typedef is valid, so a translation unit that
// includes <openssl/cms.h> as well still compiles.
typedef struct CMS_SignerInfo_st CMS_SignerInfo;

namespace APT::Internal
{

/**
 * @brief Identification of a signer that passed verification
 */
struct APT_PUBLIC SignerIdentity
{
   // The signer's subject as rendered by X509_NAME_print_ex() with
   // XN_FLAG_ONELINE, which escapes control and non-ASCII characters. The
   // value is attacker controlled but cannot break out of a single line, so it
   // is safe to embed in user visible messages.
   std::string subject;
   // SHA-256 over the DER encoding of the signer's certificate, hex encoded.
   std::string fingerprint;
};

/**
 * @brief Result of a CMS/PKCS #7 signature verification
 */
struct APT_PUBLIC VerificationResult
{
   // All signers that verified and passed every constraint. Non-empty exactly
   // when VerifyDetach() succeeded.
   std::vector<SignerIdentity> signers;
};

/**
 * @brief Base class for an X.509 trust store.
 *
 * The base class considers only the OpenSSL chain validation by default,
 * where subclasses can impose additional policies and constraints by
 * overriding the VerifyCert()/VerifySignature() methods.
 *
 * Chain validation is deliberately purpose-agnostic: the store pins
 * X509_PURPOSE_ANY, which disables the suitability check OpenSSL would
 * otherwise apply to the signer certificate. Neither its keyUsage nor its
 * extendedKeyUsage therefore restricts what it may sign here, so any leaf
 * issued under a loaded anchor is accepted as a signer. Chain constraints such
 * as basicConstraints are unaffected and remain enforced. A subclass that
 * requires, say, a codeSigning extendedKeyUsage has to enforce it in
 * VerifyCert().
 *
 * No floor is imposed on signature or key strength either (i.e. a SHA-1 based 
 * chain verifies). A subclass wanting to rule those out can raise the
 * X509_VERIFY_PARAM auth level of the certificates it accepts in VerifyCert().
 *
 * TODO: Revocation is not checked.
 */
class APT_PUBLIC BaseX509Store
{
   // APT_HIDDEN, as the surrounding class' default visibility would otherwise
   // propagate into the nested one and export the whole implementation.
   class APT_HIDDEN Impl;
   const std::unique_ptr<Impl> d;

   public:
   BaseX509Store();
   virtual ~BaseX509Store();

   /**
    * @brief Load the PEM X.509 certificate(s) from fd into the trust store
    *
    * Read a FileFd as a PEM bundle and load all the contained X.509
    * certificates into the trust store. Every certificate in the bundle
    * becomes a trust anchor, so a bundle should hold nothing a caller is not
    * willing to treat as one.
    *
    * Each call replaces the trust store built by the previous one rather than
    * adding to it. A caller with several bundles has to concatenate them.
    * A failed call leaves the previously loaded store untouched.
    *
    * The fd is rewound before reading and must refer to uncompressed data, as
    * it is read directly rather than through the FileFd decompression layer.
    *
    * Caller is responsible for closing the given fd.
    *
    * @param fd is the PEM bundle's fd
    * @return true if loading the certificate(s) was successful, false
    * otherwise
    */
   bool LoadCert(FileFd &fd);

   /**
    * @brief Verify a detached CMS/PKCS#7 signature (.p7s) against its data.
    *
    * Read signature as a p7s file, verify it against the trust store and its
    * data, thereafter write the verification results to result.
    *
    * A signature file may hold more than one PEM block. A block that cannot
    * be parsed is fatal, as a signature file that is not fully understood is
    * never partially trusted. A block that parses but fails verification is
    * tolerated as long as at least one other block yields an accepted signer.
    * Bytes outside of a PEM block are ignored.
    *
    * Both fds are rewound before reading and must refer to uncompressed data,
    * as they are read directly rather than through the FileFd decompression
    * layer.
    *
    * Caller is responsible for closing the given fds.
    *
    * @param signature is the p7s file's fd
    * @param data is the signed data's fd
    * @param result contains the written verification results
    * @return true if at least one signer verified and passed every
    * constraint, false otherwise
    */
   [[nodiscard]] bool VerifyDetach(FileFd &signature,
				   FileFd &data,
				   VerificationResult &result);

   protected:
   /**
    * @brief Verify a signer's signature against constraints.
    *
    * Called during VerifyDetach() for every signer whose signature and
    * certificate chain OpenSSL accepted, this method is used to introduce
    * constraints on the signer's signature. It runs before VerifyCert(), which
    * is then skipped for a signer rejected here.
    *
    * By default, all signatures are accepted. Clients are expected to
    * optionally append constraints by overriding the method in a subclass.
    *
    * Use LoadedCerts() to impose a trust anchor policy.
    *
    * Report the outcome through the return value. The hook runs inside its own
    * error frame which is always discarded, so anything pushed with _error is
    * re-emitted as a warning attributed to the signer and can never fail the
    * overall verification on its own.
    *
    * Both handles belong to the CMS structure under verification. Never free
    * them and never retain them beyond the call.
    *
    * @param si is the CMS SignerInfo under evaluation
    * @param cert is the certificate that produced the signature described by si
    * @return true if the verification is successful, false otherwise
    */
   virtual bool VerifySignature(CMS_SignerInfo * /*si*/, X509 * /*cert*/) { return true; }

   /**
    * @brief Verify an X.509 certificate against constraints.
    *
    * Called during VerifyDetach() for every signer whose signature and
    * certificate chain OpenSSL accepted, and which VerifySignature() did not
    * already reject, this method is used to introduce constraints on a
    * certificate.
    *
    * By default, all certificates are accepted. Clients are expected to
    * optionally append constraints by overriding the method in a subclass.
    *
    * Report the outcome through the return value. The hook runs inside its own
    * error frame which is always discarded, so anything pushed with _error is
    * re-emitted as a warning attributed to the signer and can never fail the
    * overall verification on its own.
    *
    * The certificate belongs to the CMS structure under verification. Never
    * free it and never retain it beyond the call.
    *
    * @param cert is the signer certificate under evaluation
    * @return true if the verification is successful, false otherwise
    */
   virtual bool VerifyCert(X509 * /*cert*/) { return true; }

   /**
    * @brief Non-owning view of every certificate loaded by LoadCert().
    *
    * Lets a subclass impose a trust-anchor policy from VerifySignature().
    * The certificates are owned by the trust store and must not be freed.
    * The pointers stay valid until the next LoadCert() call.
    *
    * @return the trust store's certificates
    */
   std::vector<X509 *> LoadedCerts() const;
};

} // namespace APT::Internal

#endif
