/*
 * p7s-store.cc - Trust store policy for a repository's Release.p7s
 *
 * Copyright (c) 2026 Canonical Ltd
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <config.h>

#include "p7s-store.h"

#include <apt-pkg/error.h>

#include <openssl/cms.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>

#include <apti18n.h>

/* Constraints live here, one function each. A constraint returns false to
   reject and describes why with _error->Error(); BaseX509Store folds that into
   the diagnostic it attributes to the signer.

   Keep them side-effect free: a single signature may carry several signers, the
   hooks are called once per signer, and rejecting one signer is not a failure
   of the verification as a whole. Never free or retain the arguments either --
   both belong to the CMS structure under verification.

   The two constraints below are EXAMPLES. They are deliberately the least
   controversial floors available. They exist to demonstrate the shape of a
   constraint and to keep both hooks exercised. They are not the repository
   signing policy APT will ship, which is why PolicyIsConstrained is still
   false; see p7s-store.h. */

// The digest the signer committed to. Allow-list rather than deny-list, so 
// that a digest nobody considered is rejected instead of accepted by default.
static bool RequireStrongDigest(CMS_SignerInfo *si)
{
   X509_ALGOR *digest = nullptr;
   CMS_SignerInfo_get0_algs(si, nullptr, nullptr, &digest, nullptr);
   ASN1_OBJECT const *algorithm = nullptr;
   if (digest != nullptr)
      X509_ALGOR_get0(&algorithm, nullptr, nullptr, digest);
   int const nid = algorithm == nullptr ? NID_undef : OBJ_obj2nid(algorithm);

   static constexpr std::array Accepted{NID_sha256, NID_sha384, NID_sha512,
					NID_sha3_256, NID_sha3_384, NID_sha3_512};
   if (std::find(Accepted.begin(), Accepted.end(), nid) != Accepted.end())
      return true;
   // TRANSLATORS: %s is a digest name such as SHA1, untranslated on purpose.
   return _error->Error(_("the signature uses the digest %s, which is too weak"),
			nid == NID_undef ? "(unrecognised)" : OBJ_nid2sn(nid));
}

// The strength of the key that made the signature. BaseX509Store does not raise
// the OpenSSL auth level, so a 1024 bit RSA chain verifies there. Compare
// security bits rather than key bits so that the floor means the same thing for
// RSA and for elliptic curves: 112 is what RSA-2048 offers, and what OpenSSL
// itself calls auth level 2.
static bool RequireStrongKey(X509 *cert)
{
   static constexpr int MinimumSecurityBits = 112;

   EVP_PKEY *const key = X509_get0_pubkey(cert);
   if (key == nullptr)
      return _error->Error(_("the signer certificate carries no usable public key"));
   if (int const bits = EVP_PKEY_get_security_bits(key); bits < MinimumSecurityBits)
      return _error->Error(_("the signer key offers %d bits of security, but %d are required"),
			   bits, MinimumSecurityBits);
   return true;
}

bool P7SStore::VerifySignature(CMS_SignerInfo *si, X509 * /*cert*/)
{
   return RequireStrongDigest(si);
}

bool P7SStore::VerifyCert(X509 *cert)
{
   return RequireStrongKey(cert);
}
