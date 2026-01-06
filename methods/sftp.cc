#include <config.h>

#include "sftp.h"

#include <format>
#include <fstream>

#include <fcntl.h>

#include <apt-pkg/fileutl.h>
#include <apt-pkg/mmap.h>

namespace SSH
{

const char *get_error_msg(LIBSSH2_SESSION *session)
{
   char *msg = nullptr;
   libssh2_session_last_error(session, &msg, nullptr, 0);
   return msg;
}

struct CheckedResult
{
   CheckedResult(LIBSSH2_SESSION *session, int rc = LIBSSH2_ERROR_NONE) : session(session)
   {
      if (!validate(session, rc))
	 throw std::runtime_error("SSH Error");
   }

   CheckedResult &operator=(int rc)
   {
      if (!validate(session, rc))
	 throw std::runtime_error("SSH Error");
      return *this;
   }

   static bool validate(LIBSSH2_SESSION *session, int rc)
   {
      if (rc == LIBSSH2_ERROR_NONE)
	 return true;
      char *msg = nullptr;
      return _error->Error(_("SSH error: %s"), get_error_msg(session));
   }

   private:
   LIBSSH2_SESSION *session;
};

Session::Session() : session(libssh2_session_init())
{
}

Session::~Session()
{
   if (session != nullptr)
      libssh2_session_disconnect(session, "");
   libssh2_session_free(session);
}

void Session::ApplyConfig()
{
   // SSH is finicky about it's newlines, this seems the easiest way to define that private key in
   // APT's settings
   auto privKeyFormat = _config->Find("Acquire::sftp::PrivateKeyFromat", "RSA");
   auto pkHeader = std::format("-----BEGIN {} PRIVATE KEY-----", privKeyFormat);
   auto pkFooter = std::format("-----END {} PRIVATE KEY-----", privKeyFormat);
   auto privKeyCore = _config->Find("Acquire::sftp::PrivateKey");
   privateKey = std::format("{}\n{}\n{}\n", pkHeader, privKeyCore, pkFooter);
   passPhrase = _config->Find("Acquire::sftp::PassPhrase");
}

std::vector<std::string> Session::SupportedAlgorithms()
{
   const char **algs = nullptr;
   int nalg = libssh2_session_supported_algs(session, 0, &algs);
   std::vector<std::string> r;
   for (int n = 0; n < nalg; n++)
      r.push_back(algs[n]);
   return r;
}

bool Session::Connect(const URI &uri, aptMethod *parent)
{
   if (session == nullptr)
      return _error->Error("SSH Session is null");
   libssh2_session_disconnect(session, "");

   int port = (uri.Port != 0) ? uri.Port : 22;
   std::unique_ptr<MethodFd> socket;
   auto rc = ::Connect(uri.Host, port, nullptr, 22, m_socket, 0, parent);
   if (rc != ResultState::SUCCESSFUL)
      return _error->Error(_("SSH Session could not connect to %s"), uri.Host.c_str());

   SetNonBlock(m_socket->Fd(), false);
   int rs = libssh2_session_startup(session, m_socket->Fd());
   if (!CheckedResult::validate(session, rs))
      return false;

   ApplyConfig();

   int rca = LIBSSH2_ERROR_AUTHENTICATION_FAILED;
   if (!uri.Password.empty())
   {
      rca = libssh2_userauth_password(session, nullptr, uri.Password.c_str());
   }
   if ((rca != LIBSSH2_ERROR_NONE) && (!privateKey.empty()))
   {
      const char *pPassStr = passPhrase.empty() ? nullptr : passPhrase.data();
      rca = libssh2_userauth_publickey_frommemory(session,
						  uri.User.c_str(), uri.User.size(),
						  nullptr, 0,
						  privateKey.c_str(), privateKey.size(), pPassStr);
   }
   if (rca != LIBSSH2_ERROR_NONE)
   {
      return _error->Error(_("\nError authenticating to %s%s:%i: error %i %s\n"),
			   uri.User.c_str(), uri.Host.c_str(), port, rca, SSH::get_error_msg(session));
   }
   return true;
}

File::File(LIBSSH2_SFTP *session, std::string_view path, int access)
{
   file = libssh2_sftp_open(session, path.data(), access, 0);
   if (file == NULL)
      _error->Error(_("SFTP Could not open: %s"), path.data());
}

File::~File()
{
   libssh2_sftp_close(file);
}

bool File::IsOpen()
{
   return file != nullptr;
}

SFTP::SFTP(Session &ssh)
{
   reset(ssh);
}

SFTP::~SFTP()
{
   libssh2_sftp_shutdown(session);
}

bool SFTP::reset(Session &ssh)
{
   libssh2_sftp_shutdown(session);
   if (ssh.session == nullptr)
   {
      return _error->Error(_("SFTP received a null SSH session"));
   }
   session = libssh2_sftp_init(ssh.session);
   if (session == nullptr)
   {
      return _error->Error(_("Could not allocate SFTP"));
   }
   return true;
}

std::optional<LIBSSH2_SFTP_ATTRIBUTES> SFTP::stat(std::string_view path)
{
   File f(session, path, 0);
   LIBSSH2_SFTP_ATTRIBUTES attr;
   if (libssh2_sftp_fstat(f.file, &attr) != 0)
      return std::nullopt;
   return attr;
}

File SFTP::open(std::string_view path, int access)
{
   return File(session, path, access);
}

Host::Host(const URI &u) : url(u.Host), port(u.Port)
{
}

} // namespace SSH

SftpMethod::SftpMethod(std::string &&pProg) : aptMethod(std::move(pProg), "1.0", SendConfig | SendURIEncoded)
{
}

SftpMethod::~SftpMethod()
{
}

bool SftpMethod::Fetch(FetchItem *Itm)
{
   // Connect to the host
   auto uri = URI(Itm->Uri);
   SSH::Host host(uri);
   if (m_host != host)
   {
      if (!m_ssh.Connect(uri, this))
	 return _error->Error(_("SSH Connect to %s failed"), host.url.c_str());
      m_host = host;
      if (!m_sftp.reset(m_ssh))
	 return false;
   }

   auto uriPath = DeQuoteString(uri.Path);
   auto st = m_sftp.stat(uriPath);
   if (!st.has_value())
      return _error->Error(_("Could not find: %s"), uriPath.c_str());

   // Prepare download
   FetchResult Res;
   Res.Filename = Itm->DestFile;
   Res.IMSHit = false;
   Res.Size = st->filesize;
   Res.LastModified = st->mtime;

   // Check for and up-to-date file, with the same logic as BaseHttpMethod
   bool mtimeMatch = Itm->LastModified >= st->mtime;
   bool sizeMatch = Itm->ExpectedHashes.usable() ? (Itm->ExpectedHashes.FileSize() == st->filesize) : true;
   if (mtimeMatch && sizeMatch)
   {
      Res.IMSHit = true;
      URIDone(Res);
      return true;
   }

   auto fd_src = m_sftp.open(uriPath, O_RDONLY);
   if (!fd_src.IsOpen())
      return false;
   URIStart(Res);

   // Read the data
   {
      FileFd To(Itm->DestFile, FileFd::WriteOnly | FileFd::Create);
      if (!To.IsOpen())
	 return false;
      std::array<char, 1 << 18> dest_buf;
      int nRead = 0;
      while (nRead < st->filesize)
      {
	 int nr = libssh2_sftp_read(fd_src.file, dest_buf.data(), dest_buf.size());
	 if (nr < 0)
	    return _error->Error(_("Could not read: %s\n%s"), uri.Path.c_str(), SSH::get_error_msg(m_ssh.session));
	 To.Write(dest_buf.data(), nr);
	 nRead += nr;
      }
   }

   // Collect results
   CalculateHashes(Itm, Res);
   URIDone(Res);
   return true;
}

bool SftpMethod::Configuration(std::string Message)
{
   if (aptMethod::Configuration(Message) == false)
      return false;
   return true;
}

int main(int argc, const char *argv[])
try
{
   if (libssh2_init(0) != 0)
      return -1;
   std::string Binary{flNotDir(argv[0])};

   int rc = SftpMethod(std::move(Binary)).Run();
   libssh2_exit();
   return rc;
}
catch (std::exception &e)
{
   _error->Error(_("Exception:\n%s"), e.what());
   return -1;
}
