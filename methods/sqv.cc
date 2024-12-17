#include <config.h>

#include "aptmethod.h"
#include <apt-pkg/gpgv.h>
#include <apt-pkg/strutl.h>
#include <iterator>
#include <ostream>
#include <sstream>

using std::string;
using std::vector;

class SQVMethod : public aptMethod
{
   private:
   bool VerifyGetSigners(const char *file, const char *outfile,
			 vector<string> keyFiles,
			 vector<string> &signers);

   protected:
   virtual bool URIAcquire(std::string const &Message, FetchItem *Itm) APT_OVERRIDE;

   public:
   SQVMethod() : aptMethod("sqv", "1.1", SingleInstance | SendConfig | SendURIEncoded) {};
};

bool SQVMethod::VerifyGetSigners(const char *file, const char *outfile,
				 vector<string> keyFiles,
				 vector<string> &signers)
{
   bool const Debug = DebugEnabled();

   std::vector<std::string> args;

   args.push_back(SQV_EXECUTABLE);
   if (keyFiles.empty())
   {
      auto Parts = GetListOfFilesInDir(_config->FindDir("Dir::Etc::TrustedParts"), std::vector<std::string>{"gpg", "asc"}, true);
      for (auto &Part : Parts)
      {
	 if (Debug)
	    std::clog << "Trying TrustedPart: " << Part << std::endl;
	 keyFiles.push_back(Part);
      }
   }

   if (keyFiles.empty())
      return _error->Error("The signatures couldn't be verified because no keyring is specified");

   for (auto const &keyring : keyFiles)
   {
      args.push_back("--keyring");
      args.push_back(keyring);
   }

   FileFd signatureFd;
   FileFd messageFd;
   DEFER([&]
	 {
	 if (signatureFd.IsOpen()) RemoveFile("RemoveSignature", signatureFd.Name());
	 if (messageFd.IsOpen()) RemoveFile("RemoveMessage", messageFd.Name()); });

   if (strcmp(file, outfile) == 0)
   {
      if (GetTempFile("apt.sig", false, &signatureFd) == nullptr)
	 return false;
      if (GetTempFile("apt.data", false, &messageFd) == nullptr)
	 return false;

      // FIXME: The test suite only expects the final message.
      _error->PushToStack();
      if (signatureFd.Failed() || messageFd.Failed() ||
	  not SplitClearSignedFile(file, &messageFd, nullptr, &signatureFd))
	 return _error->RevertToStack(), _error->Error("Splitting up %s into data and signature failed", file);
      _error->RevertToStack();

      args.push_back(signatureFd.Name());
      args.push_back(messageFd.Name());
   }
   else
   {
      if (not VerifyDetachedSignatureFile(file))
	 return false;
      args.push_back(file);
      args.push_back(outfile);
   }

   // FIXME: Use a select() loop
   FileFd sqvout;
   FileFd sqverr;
   if (GetTempFile("apt.sqvout", false, &sqvout) == nullptr)
      return "Internal error: Cannot create temporary file";

   DEFER([&]
	 { RemoveFile("CleanSQVOut", sqvout.Name()); });

   if (GetTempFile("apt.sqverr", false, &sqverr) == nullptr)
      return "Internal error: Cannot create temporary file";

   DEFER([&]
	 { RemoveFile("CleanSQVErr", sqverr.Name()); });

   // Translate the argument list to a C array. This should happen before
   // the fork so we don't allocate money between fork() and execvp().
   if (Debug)
      std::clog << "Executing " << APT::String::Join(args, " ") << std::endl;
   std::vector<const char *> cArgs;
   cArgs.reserve(args.size() + 1);
   for (auto const &arg : args)
      cArgs.push_back(arg.c_str());
   cArgs.push_back(nullptr);
   pid_t pid = ExecFork({sqvout.Fd(), sqverr.Fd()});
   if (pid < 0)
      return _error->Errno("VerifyGetSigners", "Couldn't spawn new process");
   else if (pid == 0)
   {
      dup2(sqvout.Fd(), STDOUT_FILENO);
      dup2(sqverr.Fd(), STDERR_FILENO);
      execvp(cArgs[0], (char **)&cArgs[0]);
      _exit(123);
   }

   int status;
   waitpid(pid, &status, 0);
   sqverr.Seek(0);
   sqvout.Seek(0);

   if (Debug == true)
      ioprintf(std::clog, "sqv exited with status %i\n", WEXITSTATUS(status));
   if (WEXITSTATUS(status) != 0)
   {
      std::string msg;
      for (std::string err; sqverr.ReadLine(err);)
	 msg.append(err).append("\n");
      return _error->Error(_("Sub-process %s returned an error code (%u), error message is:\n%s"), cArgs[0], WEXITSTATUS(status), msg.c_str());
   }

   for (std::string signer; sqvout.ReadLine(signer);)
   {
      if (Debug)
	 std::clog << "Got GOODSIG " << signer << std::endl;
      signers.push_back(signer);
   }

   return true;
}

static std::string GenerateKeyFile(std::string const key)
{
   FileFd fd;
   GetTempFile("apt-key.XXXXXX.asc", false, &fd);
   fd.Write(key.data(), key.size());
   return fd.Name();
}

bool SQVMethod::URIAcquire(std::string const &Message, FetchItem *Itm)
{
   URI const Get(Itm->Uri);
   std::string const Path = DecodeSendURI(Get.Host + Get.Path); // To account for relative paths

   std::vector<std::string> Signers, keyFpts, keyFiles;
   struct TemporaryFile
   {
      std::string name = "";
      ~TemporaryFile() { RemoveFile("~TemporaryFile", name); }
   } tmpKey;

   std::string SignedBy = DeQuoteString(LookupTag(Message, "Signed-By"));

   if (SignedBy.find("-----BEGIN PGP PUBLIC KEY BLOCK-----") != std::string::npos)
   {
      tmpKey.name = GenerateKeyFile(SignedBy);
      keyFiles.emplace_back(tmpKey.name);
   }
   else
   {
      for (auto &&key : VectorizeString(SignedBy, ','))
	 if (key.empty() == false && key[0] == '/')
	    keyFiles.emplace_back(std::move(key));
	 else
	    keyFpts.emplace_back(std::move(key));
   }

   // Run apt-key on file, extract contents and get the key ID of the signer
   VerifyGetSigners(Path.c_str(), Itm->DestFile.c_str(), keyFiles, Signers);
   if (_error->PendingError())
   {
      // Legacy fallback to trusted.gpg
      auto trusted = _config->FindFile("Dir::Etc::Trusted");
      _error->PushToStack();
      VerifyGetSigners(Path.c_str(), Itm->DestFile.c_str(), {trusted}, Signers);
      bool error = _error->PendingError();
      _error->RevertToStack();
      if (error)
	 return false;
      std::string warning;
      strprintf(warning,
		_("Key is stored in legacy trusted.gpg keyring (%s). Use Signed-By instead. See the USER CONFIGURATION section in apt-secure(8) for details."),
		trusted.c_str());
      Warning(std::move(warning));
   }

   if (Signers.empty())
      return _error->Error("No good signature");

   if (not keyFpts.empty())
   {
      Signers.erase(std::remove_if(Signers.begin(), Signers.end(), [&](std::string const &signer) {
	 bool allowedSigner = std::find(keyFpts.begin(), keyFpts.end(), signer) != keyFpts.end();
	 if (not allowedSigner && DebugEnabled())
	       std::cerr << "NoPubKey: GOODSIG " << signer << "\n";
	 return not allowedSigner;
      }), Signers.end());

      if (Signers.empty()) {
	 if (keyFpts.size() > 1)
	    return _error->Error(_("No good signature from required signers: %s"), APT::String::Join(keyFpts, ", ").c_str());
	 return _error->Error(_("No good signature from required signer: %s"), APT::String::Join(keyFpts, ", ").c_str());
      }
   }
   std::unordered_map<std::string, std::string> fields;
   fields.emplace("URI", Itm->Uri);
   fields.emplace("Filename", Itm->DestFile);
   fields.emplace("Signed-By", APT::String::Join(Signers, "\n"));
   SendMessage("201 URI Done", std::move(fields));
   Dequeue();

   if (DebugEnabled())
      std::clog << "sqv succeeded\n";

   return true;
}

int main()
{
   return SQVMethod().Run();
}
