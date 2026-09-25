/*
 * p7s-store.h - Trust store policy for a repository's Release.p7s
 *
 * Copyright (c) 2026 Canonical Ltd
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * Contains P7SStore, the constrained BaseX509Store subclass the p7s acquire
 * method verifies a detached CMS/PKCS#7 repository signature against.
 */

#ifndef APT_P7S_STORE_H
#define APT_P7S_STORE_H

#include <apt-pkg/pkcs7.h>

/**
 * @brief The trust store a repository's Release.p7s is verified against.
 *
 * This subclass is where APT's policy for repository signatures lives. It is
 * intentionally the only thing standing between "OpenSSL accepted a chain" and
 * "APT trusts this repository", so that the whole of that decision is
 * reviewable in one file.
 *
 * @warning The constraint set is currently EMPTY, which makes this class
 * behaviourally identical to its base
 *
 * To add a constraint:
 *  - write a `static bool Require...()` in p7s-store.cc which returns false on
 *    rejection and describes the reason with _error->Error(),
 *  - call it from VerifySignature() or VerifyCert(),
 *
 * Both hooks run inside an error frame that BaseX509Store always discards, so
 * anything a constraint pushes with _error is re-emitted as a warning
 * attributed to the signer, and can never fail an unrelated signer or the
 * verification as a whole.
 *
 */
class P7SStore : public APT::Internal::BaseX509Store
{
   public:
   static constexpr bool PolicyIsConstrained = false;
   protected:
   bool VerifySignature(CMS_SignerInfo *si, X509 *cert) override;
   bool VerifyCert(X509 *cert) override;
};

#endif
