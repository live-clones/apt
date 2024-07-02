/*
 * SPDX-License-Identifier: BSD-3-clause
 *
 * Copyright (C) 2024 Canonical Ltd
 */

#include <apt-pkg/string_view.h>

#include <vector>

namespace APT
{
namespace OpenPGP
{

struct PublicKey
{
   // \brief Fingerprint of the key
   std::string fingerprint;
   // \brief Human readable algorithm name
   std::string algorithm;
   /// \brief Flag whether the algorithm listed above is safe.
   ///
   /// Note that the algorithm for this primary key may be safe, but it may have
   /// unsafe subkeys.
   bool safe = false;
   /// \brief Whether the key is revoked (it may not be but all subkeys may be, better check!).
   bool revoked = false;
   /// \brief User identities belonging to the key (not valid for subkeys)
   std::vector<std::string> uids;
   /// \brief Subkeys.
   std::vector<PublicKey> subkeys;
};

class Keyring
{
   std::vector<PublicKey> publicKeys;

   public:
   APT_PUBLIC bool AddKeyFile(const char *path, APT::StringView key);
   std::vector<PublicKey>::const_iterator begin() { return publicKeys.begin(); };
   std::vector<PublicKey>::const_iterator end() { return publicKeys.end(); };
};

} // namespace OpenPGP
} // namespace APT
