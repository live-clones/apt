#pragma once

#include <libssh/sftp.h>

#include <apt-pkg/macros.h>
#include <apt-pkg/strutl.h>

#include "aptmethod.h"

namespace SSH
{

class Session
{
   public:
   Session();
   ~Session();

   Session(const Session &) = delete;
   Session &operator=(const Session &) = delete;

   [[nodiscard]] bool Connect(URI uri);

   ssh_session session = nullptr;

   private:
   void ApplyConfig();

   ssh_key privateKey = nullptr;
   socket_t agent = 0;
};

class File
{
   public:
   File(sftp_session session, std::string_view path, int access);
   ~File();

   bool IsOpen();

   sftp_file file;
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

   sftp_attributes stat(std::string_view path);

   File open(std::string_view path, int access);

   sftp_session session = nullptr;
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
