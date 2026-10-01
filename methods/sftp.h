#pragma once

#include <libssh2.h>
#include <libssh2_sftp.h>

#include <apt-pkg/macros.h>
#include <apt-pkg/strutl.h>

#include "aptmethod.h"
#include "connect.h"

namespace SSH
{

class Session
{
   public:
   Session();
   ~Session();

   Session(const Session &) = delete;
   Session &operator=(const Session &) = delete;

   [[nodiscard]] bool Connect(const URI &uri, aptMethod *parent);

   std::vector<std::string> SupportedAlgorithms();

   LIBSSH2_SESSION *session = nullptr;

   private:
   void ApplyConfig();

   std::unique_ptr<MethodFd> m_socket;
   std::string privateKey, passPhrase;
};

class File
{
   public:
   File(LIBSSH2_SFTP *session, std::string_view path, int access);
   ~File();

   bool IsOpen();

   LIBSSH2_SFTP_HANDLE *file;
};

class SFTP
{
   public:
   SFTP() = default;
   SFTP(Session &ssh);
   ~SFTP();

   SFTP(const SFTP &) = delete;
   SFTP &operator=(const SFTP &) = delete;

   [[nodiscard]] bool reset(Session &ssh);

   std::optional<LIBSSH2_SFTP_ATTRIBUTES> stat(std::string_view path);

   File open(std::string_view path, int access);

   LIBSSH2_SFTP *session = nullptr;
};

class Host
{
   public:
   Host() = default;
   Host(const URI &u);
   auto operator<=>(const Host &) const noexcept = default;

   std::string url;
   int port = 0;
};
} // namespace SSH

class SftpMethod : public aptMethod
{
   public:
   explicit SftpMethod(std::string &&pProg);
   ~SftpMethod() override;

   private:
   bool Fetch(FetchItem *Itm) override;
   bool Configuration(std::string Message) override;

   SSH::Session m_ssh;
   SSH::Host m_host;
   SSH::SFTP m_sftp;
};
