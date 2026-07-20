// -*- mode: cpp; mode: fold -*-
// Description							/*{{{*/
/* ######################################################################

   cms - APT acquire method for verifying detached PEM CMS signatures

   Implements the "cms:" URI scheme.  The signature file is a detached
   PEM-encoded CMS / PKCS#7 structure carrying the signing leaf certificate
   and any intermediate certificates.  The data file is the plain Release
   file.  The trusted X.509 certificate bundle is supplied via the
   "Signed-By" acquire header — either a filesystem path or an inline
   PEM certificate blob.

   Verification is delegated to APT::Internal::X509Store (see
   apt-pkg/contrib/pkcs7.h), which builds the trust store and runs
   CMS_verify() against the supplied certificate bundle.  The Suite
   and Origin headers are read from the acquire message and forwarded
   for use by future policy-aware verification, but are not used by
   the unconstrained verifier.

   ##################################################################### */
									/*}}}*/
// Include Files						/*{{{*/
#include <config.h>

#include "aptmethod.h"
#include <apt-pkg/strutl.h>
#include <apt-pkg/fileutl.h>
#include <apt-pkg/pkcs7.h>

#include <string>
#include <unordered_map>

using namespace APT::Internal;
									/*}}}*/

class CMSMethod : public aptMethod
{
   protected:
   bool URIAcquire(std::string const &Message, FetchItem *Itm) override;

   public:
   CMSMethod() : aptMethod("cms", "1.1", SingleInstance | SendConfig | SendURIEncoded) {}
};
// CMSMethod::URIAcquire - Verify a detached PEM CMS signature		/*{{{*/
bool CMSMethod::URIAcquire(std::string const &Message, FetchItem *Itm)
{
   if (unlikely(_error->PendingError()))
      return _error->Error("Internal error: pending error at start of cms verification");

   // The URI scheme encodes the path to the signature file.
   // "cms:<url-encoded-path>" -> local filesystem path of the .p7s file.
   URI const Get(Itm->Uri);
   std::string const SigPath = DecodeSendURI(Get.Host + Get.Path);
   std::string const DataPath = Itm->DestFile;
   std::string const SignedBy = DeQuoteString(LookupTag(Message, "Signed-By"));
   std::string const Suite = DeQuoteString(LookupTag(Message, "Suite"));
   std::string const Origin = DeQuoteString(LookupTag(Message, "Origin"));
   (void)Origin; // used by the constrained verifier in a later commit

   if (SignedBy.empty())
      return _error->Error("cms verification requires a Signed-By certificate");
   if (Suite.empty())
      return _error->Error("cms verification requires a Suite header");

   // Open the signature file.
   FileFd sigFd;
   if (not sigFd.Open(SigPath, FileFd::ReadOnly))
      return _error->Error("cms: cannot open signature file %s", SigPath.c_str());

   // Open the data (Release) file.
   FileFd dataFd;
   if (not dataFd.Open(DataPath, FileFd::ReadOnly))
      return _error->Error("cms: cannot open data file %s", DataPath.c_str());

   // Load the certificate bundle - either from a file path or an inline
   // PEM blob in the Signed-By header.
   X509Store store;
   if (SignedBy[0] == '/')
   {
      // Filesystem path.
      if (not FileExists(SignedBy))
	 return _error->Error("cms: Signed-By certificate bundle not found: %s", SignedBy.c_str());
      if (not store.LoadCert(SignedBy))
	 return false;
   }
   else
   {
      // Inline PEM certificate blob — write to a temp file, then load.
      // Alternatively, FileFd could wrap a memfd, but the simplest
      // approach is a temporary file.
      FileFd certFd;
      std::string const tmpCert = _config->FindDir("Dir::State::lists") + "aptcms-XXXXXX";
      if (not certFd.Open(tmpCert, FileFd::WriteAtomic, FileFd::Extension))
	 return _error->Error("cms: cannot create temp file for inline certificate");
      if (not certFd.Write(SignedBy.data(), SignedBy.size()))
	 return _error->Error("cms: cannot write inline certificate to temp file");
      certFd.Close();
      if (not certFd.Open(tmpCert, FileFd::ReadOnly))
	 return _error->Error("cms: cannot reopen temp certificate file");
      bool const ok = store.LoadCert(certFd);
      certFd.Close();
      RemoveFile("cms", tmpCert);
      if (not ok)
	 return false;
   }

   VerificationResult result;
   if (not store.VerifyDetach(sigFd, dataFd, result))
      return _error->Error("cms: verification failed for %s", DataPath.c_str());

   if (DebugEnabled())
      std::clog << "cms verification succeeded for " << DataPath
	 << ", signer: " << result.signerSubject << "\n";

   std::unordered_map<std::string, std::string> fields;
   fields.emplace("URI", Itm->Uri);
   fields.emplace("Filename", Itm->DestFile);
   fields.emplace("Signed-By", result.signerSubject);
   fields.emplace("Signer-Fingerprint", result.signerFingerprint);
   SendMessage("201 URI Done", std::move(fields));
   Dequeue();

   return not _error->PendingError();
}
									/*}}}*/

int main()
{
   return CMSMethod().Run();
}
