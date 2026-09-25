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

#include <apti18n.h>

/* Constraints live here, one function each. A constraint returns false to
   reject and describes why with _error->Error(); BaseX509Store folds that into
   the diagnostic it attributes to the signer.

   Keep them side-effect free: a single signature may carry several signers, the
   hooks are called once per signer, and rejecting one signer is not a failure
   of the verification as a whole. Never free or retain the arguments either --
   both belong to the CMS structure under verification. */

bool P7SStore::VerifySignature(CMS_SignerInfo * /*si*/, X509 * /*cert*/)
{
   // No constraints on the signature itself yet, see p7s-store.h.
   return true;
}

bool P7SStore::VerifyCert(X509 * /*cert*/)
{
   // No constraints on the signer certificate yet, see p7s-store.h.
   return true;
}
