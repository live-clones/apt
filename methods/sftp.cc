#include <config.h>

#include "sftp.h"

#include <format>
#include <fstream>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <libssh/libssh.h>

#include <apt-pkg/fileutl.h>
#include <apt-pkg/mmap.h>

namespace SSH
{

struct CheckedResult
{
   CheckedResult(ssh_session session, int rc = SSH_OK) : session(session)
   {
      if (!validate(rc))
	 throw std::runtime_error("SSH Error");
   }

   CheckedResult &operator=(int rc)
   {
      if (!validate(rc))
	 throw std::runtime_error("SSH Error");
      return *this;
   }

   private:
   bool validate(int rc)
   {
      if (rc == SSH_OK)
	 return true;
      return _error->Error(_("SSH error: %s"), ssh_get_error(session));
   }

   ssh_session session;
};

Session::Session() : session(ssh_new())
{
}

Session::~Session()
{
   if (session != nullptr)
      ssh_disconnect(session);
   ssh_free(session);
   ssh_key_free(privateKey);
   if (agent != 0)
      close(agent);
}

void Session::ApplyConfig()
{
   CheckedResult rc(session);

   // SSH is finicky about it's newlines, this seems the easiest way to define that private key in
   // APT's settings
   auto privKeyCore = _config->Find("Acquire::sftp::PrivateKey");
   std::string privKey = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + std::string(privKeyCore) + "\n-----END OPENSSH PRIVATE KEY-----\n";
   std::string passPhrase = _config->Find("Acquire::sftp::PassPhrase");
   if (!privKey.empty())
   {
      const char *passphrase = (passPhrase.empty()) ? nullptr : passPhrase.c_str();
      ssh_auth_callback auth_callback = nullptr;
      void *auth_data = nullptr;
      if (privateKey != nullptr)
	 ssh_key_free(privateKey);
      rc = ssh_pki_import_privkey_base64(privKey.c_str(), passphrase, auth_callback, auth_data, &privateKey);
   }
   std::string agent_fn = _config->Find("Acquire::sftp::SSHAuthSock");
   if (!agent_fn.empty())
   {
      struct sockaddr_un namesock;
      namesock.sun_family = AF_UNIX;
      strncpy(namesock.sun_path, (char *)agent_fn.c_str(), sizeof(namesock.sun_path));
      agent = socket(AF_UNIX, SOCK_STREAM, 0);
      bind(agent, (struct sockaddr *)&namesock, sizeof(struct sockaddr_un));
      rc = ssh_set_agent_socket(session, agent);
   }
}

bool Session::Connect(URI uri)
{
   if (ssh_is_connected(session))
      ssh_disconnect(session);

   ssh_options_set(session, SSH_OPTIONS_HOST, uri.Host.c_str());
   int port = (uri.Port != 0) ? uri.Port : 22;
   ssh_options_set(session, SSH_OPTIONS_PORT, &port);
   if (!uri.User.empty())
      ssh_options_set(session, SSH_OPTIONS_USER, uri.User.c_str());

   int rc = ssh_connect(session);
   if (rc != SSH_OK)
   {
      return _error->Error(_("Error connecting to %s:%i\n%s\n"), uri.Host.c_str(), port, ssh_get_error(session));
   }

   ApplyConfig();

   int rca = SSH_AUTH_ERROR;
   if (!uri.Password.empty())
   {
      rca = ssh_userauth_password(session, nullptr, uri.Password.c_str());
   }
   if ((rca != SSH_AUTH_SUCCESS) && (privateKey != nullptr))
   {
      rca = ssh_userauth_publickey(session, nullptr, privateKey);
   }
   if ((rca != SSH_AUTH_SUCCESS) && (agent != 0))
   {
      rca = ssh_userauth_agent(session, nullptr);
   }
   if (rca != SSH_AUTH_SUCCESS)
   {
      return _error->Error(_("\nError authenticating to %s%s:%i: error %i %s\n"), uri.User.c_str(), uri.Host.c_str(), port, rca, ssh_get_error(session));
   }
   return true;
}

File::File(sftp_session session, std::string_view path, int access)
{
   file = sftp_open(session, path.data(), access, 0);
   if (file == NULL)
      _error->Error(_("SFTP Could not open: %s"), path.data());
}

File::~File()
{
   sftp_close(file);
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
   sftp_free(session);
}

bool SFTP::reset(Session &ssh)
{
   sftp_free(session);
   if (ssh.session == nullptr)
   {
      return _error->Error(_("SFTP received a null SSH session"));
   }
   session = sftp_new(ssh.session);
   if (session == nullptr)
   {
      return _error->Error(_("Could not allocate SFTP"));
   }
   int rc = sftp_init(session);
   if (rc < 0)
      return _error->Error(_("Could not initialize SFTP(%i): %s"), rc, ssh_get_error(session));
   return true;
}

sftp_attributes SFTP::stat(std::string_view path)
{
   return sftp_stat(session, path.data());
}

File SFTP::open(std::string_view path, int access)
{
   return File(session, path, access);
}

Host::Host(const URI &u) : url(u.Host), port(u.Port)
{
}

}; // namespace SSH

class MappedOutput
{
   static int AllocateFile(std::string_view name, size_t fileSize)
   {
      unlink(name.data());
      int fd = open(name.data(), O_CREAT | O_RDWR, S_IWUSR | S_IWGRP);
      if (fd < 0)
      {
	 _error->Error(_("Could not create file: %s"), name);
	 return -1;
      }
      int rpa = posix_fallocate(fd, 0, fileSize);
      if (rpa != 0)
      {
	 _error->Error(_("Could not allocate file(%i): %s"), rpa, name);
	 return -2;
      }
      return fd;
   }

   public:
   MappedOutput(std::string_view name, size_t fileSize) : m_file(AllocateFile(name, fileSize), true),
							  m_mmap(m_file, MMap::Public)
   {
   }

   ~MappedOutput()
   {
      m_mmap.Sync();
   }

   bool IsOpen()
   {
      return m_file.IsOpen() && m_mmap.validData();
   }

   std::span<char> span()
   {
      return {reinterpret_cast<char *>(m_mmap.Data()), m_mmap.Size()};
   }

   private:
   FileFd m_file;
   MMap m_mmap;
};

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
      if (!m_ssh.Connect(uri))
	 return _error->Error(_("SSH Connect to %s failed"), host.url.c_str());
      m_host = host;
      if (!m_sftp.reset(m_ssh))
	 return false;
   }

   // A version with a tilde (~) gets converted to %7e, undo the HTML encoding
   auto uriPath = DeQuoteString(uri.Path);
   auto st = m_sftp.stat(uriPath);
   if (st == nullptr)
      return _error->Error(_("Could not find: %s"), uriPath.c_str());

   // Prepare download
   FetchResult Res;
   Res.Filename = Itm->DestFile;
   Res.IMSHit = false;
   Res.Size = st->size;
   Res.LastModified = st->mtime;

   // Check for and up-to-date file, with the same logic as BaseHttpMethod
   bool mtimeMatch = Itm->LastModified >= st->mtime;
   bool sizeMatch = Itm->ExpectedHashes.usable() ? (Itm->ExpectedHashes.FileSize() == st->size) : true;
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
      MappedOutput dest_map(Itm->DestFile.c_str(), st->size);
      if (!dest_map.IsOpen())
	 return false;
      auto dest_span = dest_map.span();
      while (dest_span.size() > 0)
      {
	 int nr = sftp_read(fd_src.file, dest_span.data(), dest_span.size());
	 if (nr < 0)
	    return _error->Error(_("Could not read: %s\n%s"), uri.Path.c_str(), sftp_get_error(m_sftp.session));
	 dest_span = dest_span.subspan(nr);
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
   ssh_init();
   std::string Binary{flNotDir(argv[0])};

   int rc = SftpMethod(std::move(Binary)).Run();
   ssh_finalize();
   return rc;
}
catch (std::exception &e)
{
   _error->Error(_("Exception:\n%s"), e.what());
   return -1;
}
