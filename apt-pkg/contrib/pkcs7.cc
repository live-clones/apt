/*
 * pkcs7.cc - Implementation of the X.509 trust store
 *
 * Copyright (c) 2026 Canonical Ltd
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <config.h>

#include <apt-pkg/error.h>
#include <apt-pkg/macros.h>
#include <apt-pkg/pkcs7.h>
#include <apt-pkg/strutl.h>

#include <algorithm>
#include <array>
#include <cstdarg>
#include <iterator>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pemerr.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <apti18n.h>

namespace APT::Internal
{

// Deleter types for unique_ptr aliases
struct X509Deleter
{
   void operator()(X509 *p) const { X509_free(p); }
};
struct X509StoreDeleter
{
   void operator()(X509_STORE *p) const { X509_STORE_free(p); }
};
struct CMSDeleter
{
   void operator()(CMS_ContentInfo *p) const { CMS_ContentInfo_free(p); }
};
struct BIODeleter
{
   void operator()(BIO *p) const { BIO_free(p); }
};
// CMS_get0_signers() returns a new stack of internal pointers, so only free
// the stack
struct X509StackNoFreeDeleter
{
   void operator()(STACK_OF(X509) * p) const { sk_X509_free(p); }
};

// unique_ptr type aliases
using X509UP = std::unique_ptr<X509, X509Deleter>;
using X509StoreUP = std::unique_ptr<X509_STORE, X509StoreDeleter>;
using CMSUP = std::unique_ptr<CMS_ContentInfo, CMSDeleter>;
using BIOUP = std::unique_ptr<BIO, BIODeleter>;
using X509StackNoFreeUP = std::unique_ptr<STACK_OF(X509), X509StackNoFreeDeleter>;

class BaseX509Store::Impl
{
   public:
   explicit Impl(BaseX509Store &o) : owner(o) {}

   BaseX509Store &owner; // for virtual hooks
   X509StoreUP store;
   std::vector<X509UP> certs;

   bool LoadCert(FileFd &fd);
   bool VerifyDetach(FileFd &signature, FileFd &data, VerificationResult &result);

   private:
   bool ReadSignatureBlocks(FileFd &signature, std::vector<CMSUP> &blocks);
   bool VerifyOneBlock(CMS_ContentInfo *cms, FileFd &data,
		       std::vector<std::string> &failures,
		       std::vector<std::string> &warnings,
		       std::vector<X509 *> &signers);
};

// Scope OpenSSL's thread-local error queue for the duration of an operation.
//
// Ensures that errors from before the scope are left untouched and that
// errors generated within the scope are cleaned up when it ends.
class ErrorScope
{
   // The queue was empty and we are free to drain it.
   const bool owns_errors;

   public:
   ErrorScope() : owns_errors(ERR_peek_error() == 0) { ERR_set_mark(); }
   ~ErrorScope()
   {
      // ERR_set_mark() cannot record a mark on an empty queue, so do not send
      // ERR_pop_to_mark() looking for one. Everything queued is ours to drop
      // here, and clearing cannot lose anything that is not.
      if (owns_errors)
	 ERR_clear_error();
      else
	 ERR_pop_to_mark();
   }
   ErrorScope(const ErrorScope &) = delete;
   ErrorScope &operator=(const ErrorScope &) = delete;

   // Report a failure to the APT error stack.
   //
   // The formatted message is always added as an APT error in its own right.
   // If this scope owns the OpenSSL error queue, every entry on it is then
   // drained and added as a further APT error. Otherwise the queue belongs to
   // the caller and is left untouched.
   //
   // Always returns false, for use directly from failure paths.
   bool Error(const char *fmt, ...) APT_PRINTF(2);

   // Return the OpenSSL errors associated with this scope.
   //
   // If this scope owns the error queue, drain all errors into the result.
   // Otherwise, leave the queue untouched and return its most recent error.
   std::vector<std::string> Errors();

   // Conclude an otherwise successful operation.
   //
   // If this scope owns the error queue, drain whatever OpenSSL left on it
   // onto the APT error stack and report whether it was clean.
   //
   // A queue that was already dirty when the scope opened is a failure too:
   // its entries cannot be attributed, so neither we nor the caller can tell
   // an error of ours from one some earlier invocation left behind.
   //
   // Returns true if there were no errors, false otherwise.
   bool MaybeErrors();

   // Whether the newest error reports the absence of a further PEM block, which
   // is how a complete bundle ends rather than a failure. Only meaningful
   // directly after a failed PEM read made inside this scope.
   bool AtEndOfPEMBundle() const
   {
      const unsigned long err = ERR_peek_last_error();
      return ERR_GET_LIB(err) == ERR_LIB_PEM &&
	     ERR_GET_REASON(err) == PEM_R_NO_START_LINE;
   }
};

bool ErrorScope::Error(const char *fmt, ...)
{
   // GlobalError::Insert() reports back that its buffer was too small rather
   // than growing it itself, so keep handing it the grown msgSize until it
   // takes the message. This is the same loop GlobalError's own varargs
   // members run.
   va_list args;
   size_t msgSize = 400;
   bool retry;
   do
   {
      va_start(args, fmt);
      retry = _error->Insert(GlobalError::ERROR, fmt, args, msgSize);
      va_end(args);
   } while (retry);

   if (owns_errors)
   {
      while (const unsigned long err = ERR_get_error())
      {
	 char buf[256];
	 ERR_error_string_n(err, buf, sizeof(buf));
	 _error->Error("%s", buf);
      }
   }
   return false;
}

std::vector<std::string> ErrorScope::Errors()
{
   std::vector<std::string> errors;

   if (owns_errors)
   {
      while (const unsigned long err = ERR_get_error())
      {
	 char buf[256];
	 ERR_error_string_n(err, buf, sizeof(buf));
	 errors.emplace_back(buf);
      }
   }
   else
   {
      const unsigned long err = ERR_peek_last_error();
      if (err != 0)
      {
	 char buf[256];
	 ERR_error_string_n(err, buf, sizeof(buf));
	 errors.emplace_back(buf);
      }
   }

   return errors;
}

bool ErrorScope::MaybeErrors()
{
   // Pre-existing entries are not attributable: neither we nor the caller can
   // tell an error of ours from one an earlier invocation left behind, so do
   // not touch them and do not claim success either.
   if (not owns_errors)
      return false;

   const bool hasErr = ERR_peek_error() != 0;
   while (const unsigned long err = ERR_get_error())
   {
      char buf[256];
      ERR_error_string_n(err, buf, sizeof(buf));
      _error->Error("%s", buf);
   }

   return not hasErr;
}

static std::string HexEncode(const unsigned char *data, size_t len)
{
   static const char hex[] = "0123456789abcdef";
   std::string out;
   out.reserve(len * 2);
   for (size_t i = 0; i < len; ++i)
   {
      out += hex[(data[i] >> 4) & 0xf];
      out += hex[data[i] & 0xf];
   }
   return out;
}

// SHA-256 over the DER encoding of the certificate, hex encoded.
//
// Return std::nullopt on failure.
static std::optional<std::string> CertFingerprint(X509 *cert)
{
   unsigned char md[EVP_MAX_MD_SIZE];
   unsigned int len = 0;
   if (X509_digest(cert, EVP_sha256(), md, &len) != 1)
      return std::nullopt;
   return HexEncode(md, len);
}

// Render a certificate's subject name as a single line, with control and
// non-ASCII characters escaped so the result is safe to print.
//
// Return an empty string on failure.
static std::string SubjectOneline(X509 *cert)
{
   BIOUP bio(BIO_new(BIO_s_mem()));
   if (bio == nullptr)
      return "";
   if (X509_NAME_print_ex(bio.get(), X509_get_subject_name(cert), 0,
			  XN_FLAG_ONELINE) < 0)
      return "";
   char *data = nullptr;
   const long len = BIO_get_mem_data(bio.get(), &data);
   if (len <= 0 || data == nullptr)
      return "";
   return std::string(data, static_cast<size_t>(len));
}

// Describe a certificate for a diagnostic, even if rendering its subject fails.
static std::string DescribeCert(X509 *cert)
{
   std::string subject = SubjectOneline(cert);
   if (subject.empty())
      subject = _("unprintable subject");
   return subject;
}

// Drain all messages from the current error frame and return the non-empty
// messages in order. The frame is discarded afterward; this must be paired
// with a preceding _error->PushToStack().
//
// PopMessage() returns whether the popped message is an error or warning,
// not whether another message remains. Use empty(DEBUG) to detect exhaustion:
// every message type is >= DEBUG, so empty(DEBUG) remains false while the
// frame contains any messages.
static std::vector<std::string> DrainErrorFrame()
{
   std::vector<std::string> errors;
   while (not _error->empty(GlobalError::DEBUG))
   {
      std::string message;
      _error->PopMessage(message);
      if (not message.empty())
	 errors.emplace_back(std::move(message));
   }

   _error->RevertToStack();
   return errors;
}

// Move every message of more onto the end of out.
static void AppendErrors(std::vector<std::string> &out,
			 std::vector<std::string> &&more)
{
   out.insert(out.end(), std::make_move_iterator(more.begin()),
	      std::make_move_iterator(more.end()));
}

bool BaseX509Store::Impl::LoadCert(FileFd &fd)
{
   ErrorScope errScope;

   if (not fd.Seek(0))
      return errScope.Error(_("LoadCert: cannot rewind the certificate bundle"));

   // Lazily initialize the store.
   // Build the new store separately to avoid leaving a partially populated
   // trust store behind.
   X509StoreUP newStore(X509_STORE_new());
   if (newStore == nullptr)
      return errScope.Error(_("LoadCert: X509_STORE_new failed"));

   // CMS_verify applies the "smime_sign" defaults (purpose SMIME_SIGN, trust EMAIL)
   // to every field the store's param leaves unset, which rejects a signer whose
   // extendedKeyUsage lacks emailProtection. X509_PURPOSE_ANY drops that
   // suitability check on the signer certificate entirely - its keyUsage is no
   // longer consulted either - while leaving chain constraints such as
   // basicConstraints enforced. Purpose-like policy is the VerifyCert() hook's
   // business; see the class documentation.
   X509_VERIFY_PARAM *const param = X509_STORE_get0_param(newStore.get());
   if (param == nullptr ||
       X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_ANY) != 1)
      return errScope.Error(_("LoadCert: cannot set the trust store purpose"));
   // Use the fd to prevent a TOCTOU race based on pathname
   BIOUP bio(BIO_new(BIO_s_fd()));
   if (bio == nullptr)
      return errScope.Error(_("LoadCert: BIO_new failed"));
   if (BIO_set_fd(bio.get(), fd.Fd(), BIO_NOCLOSE) != 1)
      return errScope.Error(_("LoadCert: BIO_set fd failed"));

   std::vector<X509UP> newCerts;
   while (true)
   {
      // Scope every read, so that AtEndOfPEMBundle() reports on this read and
      // nothing else, and so that a tolerated one leaves the queue as it was.
      ErrorScope readErrScope;
      X509UP cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
      if (cert == nullptr)
      {
	 // Running out of PEM blocks is how a complete bundle ends.
	 if (readErrScope.AtEndOfPEMBundle())
	    break;

	 return readErrScope.Error(_("LoadCert: failed to read certificate"));
      }
      if (X509_STORE_add_cert(newStore.get(), cert.get()) != 1)
	 return readErrScope.Error(_("LoadCert: failed to add certificate"));

      // Keep an owning handle so LoadedCerts() can hand the bundle to a
      // subclass' trust anchor policy, as X509_STORE_add_cert only up-refs.
      newCerts.push_back(std::move(cert));
   }

   if (newCerts.empty())
      return errScope.Error(_("LoadCert: no certificates found"));

   store = std::move(newStore);
   certs = std::move(newCerts);
   return errScope.MaybeErrors();
}

// Accepted detached signature labels
static constexpr std::array<const char *, 3> SignatureLabels = {
   PEM_STRING_CMS, PEM_STRING_PKCS7, PEM_STRING_PKCS7_SIGNED};

// Set a limit to the number of signature bytes and blocks to guard against
// DoS attacks based on oversized signatures
static constexpr size_t MaxSignatureBlocks = 32;
static constexpr unsigned long long MaxSignatureBytes = 1024 * 1024;

// Read every PEM block of the signature file and parse it as a CMS structure.
//
// PEM_read_bio_CMS only accepts the "CMS" label, so go through the generic
// PEM_read_bio and hand the DER body to d2i_CMS_ContentInfo.
//
// Anything unexpected is fatal. Note that PEM_read_bio skips whatever sits
// between blocks, so surrounding junk is ignored rather than rejected.
bool BaseX509Store::Impl::ReadSignatureBlocks(FileFd &signature,
					      std::vector<CMSUP> &blocks)
{
   ErrorScope errScope;

   if (not signature.Seek(0))
      return errScope.Error(_("VerifyDetach: cannot rewind the signature file"));

   const unsigned long long fileSize = signature.FileSize();
   if (signature.Failed())
      return errScope.Error(_("VerifyDetach: cannot determine the signature file size"));
   if (fileSize > MaxSignatureBytes)
      return errScope.Error(_("VerifyDetach: signature file exceeds %llu bytes"),
			    MaxSignatureBytes);

   // Use the fd to prevent a TOCTOU race based on pathname
   BIOUP bio(BIO_new(BIO_s_fd()));
   if (bio == nullptr)
      return errScope.Error(_("VerifyDetach: BIO_new failed"));
   if (BIO_set_fd(bio.get(), signature.Fd(), BIO_NOCLOSE) != 1)
      return errScope.Error(_("VerifyDetach: BIO_set fd failed"));

   unsigned long long total = 0;
   while (true)
   {
      char *name = nullptr;
      char *header = nullptr;
      unsigned char *der = nullptr;
      long derLen = 0;

      // Scope every block, so that AtEndOfPEMBundle() reports on this read and
      // nothing else, and so that a tolerated one leaves the queue as it was.
      ErrorScope blockErrScope;
      if (PEM_read_bio(bio.get(), &name, &header, &der, &derLen) != 1)
      {
	 // Running out of PEM blocks is how a complete file ends.
	 if (blockErrScope.AtEndOfPEMBundle())
	    break;

	 return blockErrScope.Error(_("VerifyDetach: failed to read signature block"));
      }
      // On success PEM_read_bio hands out three OPENSSL_malloc'd buffers.
      DEFER([&]
	    { OPENSSL_free(name); OPENSSL_free(header); OPENSSL_free(der); });

      const std::string label = (name != nullptr) ? name : "";
      if (std::none_of(SignatureLabels.begin(), SignatureLabels.end(),
		       [&label](const char *const known)
		       { return label == known; }))
	 return blockErrScope.Error(
	    _("VerifyDetach: unexpected PEM label \"%s\" in the signature file"),
	    label.c_str());

      if (derLen < 0)
	 return blockErrScope.Error(_("VerifyDetach: signature block has a negative length"));
      total += static_cast<unsigned long long>(derLen);
      if (total > MaxSignatureBytes)
	 return blockErrScope.Error(_("VerifyDetach: signature file exceeds %llu bytes"),
				    MaxSignatureBytes);

      const unsigned char *p = der;
      CMSUP cms(d2i_CMS_ContentInfo(nullptr, &p, derLen));
      if (cms == nullptr)
	 return blockErrScope.Error(_("VerifyDetach: failed to parse the %s block"),
				    label.c_str());

      // Refuse rather than truncate: silently ignoring trailing blocks would
      // hide signatures the caller believes were taken into account.
      if (blocks.size() >= MaxSignatureBlocks)
	 return blockErrScope.Error(_("VerifyDetach: more than %zu signature blocks"),
				    MaxSignatureBlocks);

      blocks.push_back(std::move(cms));
   }

   if (blocks.empty())
      return errScope.Error(_("VerifyDetach: no signature blocks found"));

   return errScope.MaybeErrors();
}

// Verify one CMS block against the trust store and data, appending every
// accepted signer to signers.
//
// A hard failure of the block itself is appended to failures, whereas the
// rejection of an individual signer is appended to warnings. The caller
// decides which of the two ends up being fatal.
bool BaseX509Store::Impl::VerifyOneBlock(CMS_ContentInfo *cms, FileFd &data,
					 std::vector<std::string> &failures,
					 std::vector<std::string> &warnings,
					 std::vector<X509 *> &signers)
{
   // A block that fails while another one verifies is only a warning, so scope
   // this block's errors to keep them out of the diagnostics of the blocks that
   // follow, and off the caller's queue entirely.
   ErrorScope errScope;

   // signers is accumulated across blocks, so remember where this one starts.
   const size_t before = signers.size();

   // The caller has rewound data for us. Use the fd to prevent a TOCTOU race
   // based on pathname.
   BIOUP dataBio(BIO_new(BIO_s_fd()));
   if (dataBio == nullptr)
   {
      AppendErrors(failures, errScope.Errors());
      return false;
   }
   if (BIO_set_fd(dataBio.get(), data.Fd(), BIO_NOCLOSE) != 1)
   {
      AppendErrors(failures, errScope.Errors());
      return false;
   }

   if (CMS_verify(cms, nullptr, store.get(), dataBio.get(), nullptr,
		  CMS_DETACHED | CMS_BINARY) != 1)
   {
      AppendErrors(failures, errScope.Errors());
      return false;
   }

   X509StackNoFreeUP certStack(CMS_get0_signers(cms));
   if (certStack == nullptr)
   {
      failures.push_back(_("CMS_get0_signers returned null"));
      return false;
   }
   // CMS_get0_SignerInfos returns an internal pointer — no free.
   const STACK_OF(CMS_SignerInfo) *infos = CMS_get0_SignerInfos(cms);
   if (infos == nullptr)
   {
      failures.push_back(_("CMS_get0_SignerInfos returned null"));
      return false;
   }

   for (int i = 0; i < sk_CMS_SignerInfo_num(infos); ++i)
   {
      CMS_SignerInfo *const si = sk_CMS_SignerInfo_value(infos, i);
      if (si == nullptr)
	 continue;

      // The signer stack and the SignerInfo stack are not documented to share
      // an order, so pair a SignerInfo with its certificate explicitly instead
      // of trusting the index.
      X509 *cert = nullptr;
      for (int j = 0; j < sk_X509_num(certStack.get()); ++j)
      {
	 X509 *const candidate = sk_X509_value(certStack.get(), j);
	 if (candidate != nullptr && CMS_SignerInfo_cert_cmp(si, candidate) == 0)
	 {
	    cert = candidate;
	    break;
	 }
      }
      if (cert == nullptr)
      {
	 warnings.push_back(_("a verified signer has no matching certificate"));
	 continue;
      }

      // Run the hooks in their own error frame. A rejection is only a warning
      // when another signer or block verifies, so a subclass that reports via
      // _error->Error() must not leave a hard error on the global list.
      // Fold into the signer's diagnostic instead.
      _error->PushToStack();
      const char *rejection = nullptr;
      {
	 // The hooks are handed raw OpenSSL handles, so they may well queue
	 // errors of their own. Those are neither ours to report nor ours to
	 // leave lying around.
	 ErrorScope hookErrors;
	 if (not owner.VerifySignature(si, cert))
	    rejection = _("signature rejected by policy");
	 else if (not owner.VerifyCert(cert))
	    rejection = _("certificate rejected by policy");
      }
      auto details = DrainErrorFrame();

      if (rejection == nullptr)
      {
	 // A hook may annotate a signer it accepts - keep that visible.
	 for (auto &detail : details)
	    warnings.push_back(std::move(detail));

	 signers.push_back(cert);
	 continue;
      }

      std::string warning;
      if (details.empty())
	 strprintf(warning, "%s: %s", DescribeCert(cert).c_str(), rejection);
      else
	 strprintf(warning, "%s: %s: %s", DescribeCert(cert).c_str(), rejection,
		   APT::String::Join(details, "; ").c_str());
      warnings.push_back(std::move(warning));
   }

   if (signers.size() == before)
   {
      failures.push_back(_("no signer passed the certificate policy"));
      return false;
   }

   return errScope.MaybeErrors();
}

bool BaseX509Store::Impl::VerifyDetach(FileFd &signature, FileFd &data,
				       VerificationResult &result)
{
   // Nothing here talks to OpenSSL directly, but scope the queue anyway so that
   // whatever the steps below leave behind cannot escape to the caller.
   ErrorScope errScope;

   result.signers.clear();

   if (store == nullptr)
      return errScope.Error(_("VerifyDetach: no trust store loaded"));

   std::vector<CMSUP> blocks;
   if (not ReadSignatureBlocks(signature, blocks))
      return false;

   // Non-owning: the certificates belong to the CMS structures held in blocks,
   // which outlive the loop below.
   std::vector<X509 *> accepted;
   std::vector<std::string> blockFailures;
   std::vector<std::string> signerWarnings;
   for (size_t i = 0; i < blocks.size(); ++i)
   {
      // An unrewindable data file affects every block equally, so this is fatal
      // rather than a per-block failure. Keeping it out here also keeps the
      // Errno that FileFd pushes off the soft-failure path.
      if (not data.Seek(0))
	 return errScope.Error(_("VerifyDetach: cannot rewind the data file"));

      std::vector<std::string> failures;
      if (VerifyOneBlock(blocks[i].get(), data, failures, signerWarnings, accepted))
	 continue;

      for (const auto &message : failures)
      {
	 std::string detail;
	 strprintf(detail, _("signature block %zu: %s"), i + 1, message.c_str());
	 blockFailures.push_back(std::move(detail));
      }
   }

   // We didn't accept any signers.
   // We've already handled all ssl errors by creating the warnings and
   // failures, so explicitly create APT errors and warnings.
   if (accepted.empty())
   {
      for (const auto &warning : signerWarnings)
	 _error->Warning("VerifyDetach: %s", warning.c_str());
      for (const auto &failure : blockFailures)
	 _error->Error("VerifyDetach: %s", failure.c_str());
      return errScope.Error(_("VerifyDetach: no acceptable signature found"));
   }

   // At least one block yielded an accepted signer, so everything that did not
   // work out is informational only.
   for (const auto &failure : blockFailures)
      _error->Warning("VerifyDetach: %s", failure.c_str());
   for (const auto &warning : signerWarnings)
      _error->Warning("VerifyDetach: %s", warning.c_str());

   for (X509 *const cert : accepted)
   {
      const auto fingerprint = CertFingerprint(cert);
      // Failure to calculate the fingerprint is fatal.
      if (not fingerprint)
	 return errScope.Error(
	    _("VerifyDetach: cannot calculate certificate fingerprint for %s"),
	    DescribeCert(cert).c_str());

      SignerIdentity identity{SubjectOneline(cert), *fingerprint};
      // One certificate may well have signed more than one block.
      if (std::any_of(result.signers.begin(), result.signers.end(),
		      [&identity](const SignerIdentity &signer)
		      { return signer.fingerprint == identity.fingerprint; }))
	 continue;
      result.signers.push_back(std::move(identity));
   }

   return errScope.MaybeErrors();
}

BaseX509Store::BaseX509Store() : d(std::make_unique<Impl>(*this)) {}
BaseX509Store::~BaseX509Store() = default; // Impl is complete in this TU

bool BaseX509Store::LoadCert(FileFd &fd)
{
   return d->LoadCert(fd);
}

bool BaseX509Store::VerifyDetach(FileFd &signature, FileFd &data,
				 VerificationResult &result)
{
   return d->VerifyDetach(signature, data, result);
}

std::vector<X509 *> BaseX509Store::LoadedCerts() const
{
   std::vector<X509 *> loaded;
   loaded.reserve(d->certs.size());
   for (const auto &cert : d->certs)
      loaded.push_back(cert.get());
   return loaded;
}

} // namespace APT::Internal
