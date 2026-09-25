/*
 * p7s.cc - APT acquire method verifying detached CMS/PKCS#7 signatures
 *
 * Copyright (c) 2026 Canonical Ltd
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * Verifies a repository's Release.p7s against its Release file and the PEM
 * bundle of trust anchors named by the source's Signed-By option.
 */

#include <config.h>

#include "aptmethod.h"
#include "p7s-store.h"

#include <apt-pkg/error.h>
#include <apt-pkg/fileutl.h>
#include <apt-pkg/strutl.h>

#include <string>
#include <unordered_map>
#include <vector>

#include <apti18n.h>

using APT::Internal::VerificationResult;

class P7SMethod : public aptMethod
{
   bool OpenBundle(std::string const &SignedBy, FileFd &Bundle);

   protected:
   bool URIAcquire(std::string const &Message, FetchItem *Itm) override;

   public:
   P7SMethod();
};

P7SMethod::P7SMethod() : aptMethod("p7s", "1.1", SingleInstance | SendConfig | SendURIEncoded)
{
   // Verification happens in-process with OpenSSL, so unlike gpgv and sqv we
   // never fork a helper and the base syscall set is enough.
   SeccompFlags = aptMethod::BASE;
}

/* Signed-By names the PEM bundle of trust anchors to verify against. The
   sources.list parser already restricts a CMS/PKCS#7 source to a single
   absolute .pem path, but re-check it here: this method has to be correct on
   its own terms, and the check is what turns a misconfigured source into a
   comprehensible message instead of an OpenSSL parse failure. */
bool P7SMethod::OpenBundle(std::string const &SignedBy, FileFd &Bundle)
{
   auto const Entries = VectorizeString(SignedBy, ',');
   if (Entries.empty())
      return _error->Error(_("Signed-By names no PEM bundle to verify the "
			     "CMS/PKCS#7 signature against"));
   if (Entries.size() != 1)
      return _error->Error(_("Signed-By must name a single PEM bundle to verify a "
			     "CMS/PKCS#7 signature, and nothing besides, but names: %s"),
			   APT::String::Join(Entries, ", ").c_str());

   std::string const &Path = Entries[0];
   if (Path.empty() || Path[0] != '/')
      return _error->Error(_("The PEM bundle %s named by Signed-By is not an absolute path"),
			   Path.c_str());
   if (not APT::String::Endswith(Path, ".pem"))
      return _error->Error(_("The PEM bundle %s named by Signed-By does not end in .pem"),
			   Path.c_str());

   /* Open read-only and *raw*: BaseX509Store reads the fd directly rather than
      through FileFd's decompression layer, so asking for a compressor here
      would hand it bytes it cannot parse. Scope FileFd's own diagnostic away so
      the message names Signed-By, which is what the user has to fix. */
   _error->PushToStack();
   bool const Opened = Bundle.Open(Path, FileFd::ReadOnly);
   _error->RevertToStack();
   if (not Opened)
      return _error->Error(_("Could not read the PEM bundle %s named by Signed-By"),
			   Path.c_str());
   return true;
}

bool P7SMethod::URIAcquire(std::string const &Message, FetchItem *Itm)
{
   // Quick safety check: do we have left-over errors from a previous URL?
   if (unlikely(_error->PendingError()))
      return _error->Error("Internal error: Error set at start of verification");

   if (not P7SStore::PolicyIsConstrained &&
       not ConfigFindB("Allow-Unconstrained-Policy", false))
      return _error->Error(_("Refusing to verify a CMS/PKCS#7 signature: this APT's "
			     "certificate policy is unconstrained"));

   URI const Get(Itm->Uri);
   std::string const Signature = DecodeSendURI(Get.Host + Get.Path); // for relative paths
   std::string const &Data = Itm->DestFile;

   /* gpgv and sqv read "signature path == data path" as a clear-signed file to
      be split into the two. A CMS/PKCS#7 repository signature is always
      detached, as there is no clear-signed form of it, and hence no InRelease
      equivalent. Equality here is a caller bug */
   if (Signature == Data)
      return _error->Error("Internal error: %s is both the signature and the signed data",
			   Data.c_str());

   FileFd Bundle;
   if (not OpenBundle(DeQuoteString(LookupTag(Message, "Signed-By")), Bundle))
      return false;

   FileFd SignatureFd;
   if (not SignatureFd.Open(Signature, FileFd::ReadOnly))
      return false;
   FileFd DataFd;
   if (not DataFd.Open(Data, FileFd::ReadOnly))
      return false;

   // Nothing should have failed in the setup; if it did, don't bother verifying
   if (_error->PendingError())
      return false;

   P7SStore Store;
   if (not Store.LoadCert(Bundle))
      return false;

   VerificationResult Result;
   if (not Store.VerifyDetach(SignatureFd, DataFd, Result))
      return _error->PendingError() ? false : _error->Error(_("No good signature"));

   std::vector<std::string> Signers;
   Signers.reserve(Result.signers.size());
   for (auto const &Signer : Result.signers)
   {
      if (DebugEnabled())
	 std::clog << "Good signature from " << Signer.fingerprint
		   << " (" << Signer.subject << ")\n";
      Signers.push_back(Signer.fingerprint);
   }

   /* VerifyDetach() warns about every signature block and every signer it
      rejected, even when another one verified. Those warnings are not a
      PendingError, so returning here would drop them on the floor. They
      are exactly what one wants to see when a constraint rejects a
      signer. Hand them to the acquire process instead, before the
      201 so they stay attributed to this item. */
   while (not _error->empty())
   {
      std::string Msg;
      _error->PopMessage(Msg);
      Warning(std::move(Msg));
   }

   std::unordered_map<std::string, std::string> Fields;
   Fields.emplace("URI", Itm->Uri);
   Fields.emplace("Filename", Itm->DestFile);
   /* The SHA-256 fingerprints of the accepted signer certificates.
      pkgAcqMetaBase::CheckAuthDone() hard-errors on an empty Signed-By for any
      method not claiming version 1.0, so this must never be empty -- which
      VerifyDetach() having returned true guarantees. */
   Fields.emplace("Signed-By", APT::String::Join(Signers, "\n"));
   SendMessage("201 URI Done", std::move(Fields));
   Dequeue();

   // If we have a pending error somehow, we should still fail here...
   return not _error->PendingError();
}

int main()
{
   return P7SMethod().Run();
}
