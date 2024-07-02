/*
 * SPDX-License-Identifier: BSD-3-clause
 *
 * Copyright (C) 2024 Canonical Ltd
 *
 * Derived from:
 *
 * Copyright (C) 1998 Kazuhiko Yamamoto
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 *  OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 *  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <config.h>

#include <apt-pkg/configuration.h>
#include <apt-pkg/error.h>
#include <apt-pkg/hashes.h>
#include <apt-pkg/macros.h>
#include <apt-pkg/openpgp.h>
#include <apt-pkg/strutl.h>

#include <cassert>
#include <cstdio>
#include <climits>

static int popc(APT::StringView &buffer)
{
   if (buffer.size() == 0)
      return _error->Error("Unexpected EOF"), EOF;

   int c = buffer[0];
   buffer = buffer.substr(1);
   return c & 0xFF;
}

// All the known algorithms
constexpr char algorithms[][8] = {
   "",
   "RSA",
   "RSA",
   "RSA",
   "",
   "",
   "",
   "",
   "",
   "",
   "",
   "",
   "",
   "",
   "",
   "",
   "ElGamal",
   "DSA",
   "ECDH",
   "ECDSA",
   "",
   "",
   "EdDSA",
};

// All the known elliptic curves
constexpr struct
{
   const char *name;
   const unsigned char oidhex[10];
} ellipticCurves[] = {
   {"NIST P-256", {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x3, 0x1, 0x7, 0, 0}},
   {"NIST P-384", {0x2B, 0x81, 0x04, 0x00, 0x22, 0, 0, 0, 0, 0}},
   {"NIST P-521", {0x2B, 0x81, 0x04, 0x00, 0x23, 0, 0, 0, 0, 0}},
   {"Ed25519", {0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01, 0}},
   {"Ed448", {0x2B, 0x65, 0x71, 0, 0, 0, 0, 0, 0, 0}},
   {"Curve25519", {0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01}},
   {"X448", {0x2B, 0x65, 0x6F, 0, 0, 0, 0, 0, 0, 0}},
   {"BrainPoolP256r1", {0x2B, 0x24, 0x3, 0x3, 0x2, 0x8, 0x1, 0x1, 0x7, 0}},
   {"BrainPoolP384r1", {0x2B, 0x24, 0x3, 0x3, 0x2, 0x8, 0x1, 0x1, 0xb, 0}},
   {"BrainPoolP512r1", {0x2B, 0x24, 0x3, 0x3, 0x2, 0x8, 0x1, 0x1, 0xd, 0}},
};

static bool VerifyPublicKeyPacket(const char *path, APT::StringView key, APT::OpenPGP::PublicKey &out)
{
   switch (key[0])
   {
   case 2:
   case 3:
   {
      Hashes md5(Hashes::MD5SUM);
      md5.Add(key.data() + 4, key.size() - 4);
      out.fingerprint = md5.GetHashString(Hashes::MD5SUM).HashValue();

      int algo = key[3];
      if (algo != 1)
	 return _error->Warning("unknown public key algorithm %d in %s", algo, path);
      int bits = key[4] * 256 + key[5];
      strprintf(out.algorithm, "rsa%d", bits);
   }
   break;
   case 4:
   {
      Hashes sha1(Hashes::SHA1SUM);
      unsigned char prefix[] = {0x99, static_cast<unsigned char>((key.size() >> 8) & 0xFF), static_cast<unsigned char>(key.size() & 0xFF)};
      sha1.Add(prefix, sizeof(prefix));
      sha1.Add(key.data(), key.size());
      out.fingerprint = sha1.GetHashString(Hashes::SHA1SUM).HashValue();

      // 1,2,3,4 are creation time.
      int algo = key[5];
      switch (algo)
      {
      case 1:
      case 2:
      case 3:
      case 16:
      case 17:
      {
	 int bits = key[6] * 256 + key[7];
	    std::string safeOption;
	    strprintf(safeOption, "APT::Key::%s::Safe-Size", algorithms[algo]);
	 if (_config->FindI(safeOption.c_str(), INT_MAX) <= bits)
	    out.safe = true;
	 strprintf(out.algorithm, "%s%d", algorithms[algo], bits);
	 break;
      }
      case 18:
      case 19:
      case 22:
      {
	 int oidlen = key[6] & 0xFF;
	 auto oid = key.substr(7, oidlen);
	 for (size_t i = 0; i < APT_ARRAY_SIZE(ellipticCurves); i++)
	 {
	    if (memcmp(ellipticCurves[i].oidhex, oid.data(), oid.size()) != 0)
	       continue;
	    std::string safeOption;
	    strprintf(safeOption, "APT::Key::%s::Safe-Curves", algorithms[algo]);
	    auto rootItem = _config->Tree(safeOption.c_str());
	    if (rootItem)
	    {
	       for (auto item = rootItem->Child; item != nullptr; item = item->Next)
		   if (item->Value ==  ellipticCurves[i].name)
		      out.safe = true;
	    }
	    strprintf(out.algorithm, "%s-%s", algorithms[algo], ellipticCurves[i].name);
	    return true;
	 }
	 std::string oidhex;
	 for (auto c : oid)
	 {
	    std::string s;
	    strprintf(s, "0x%x, ", c);
	    oidhex += s;
	 }
	 return _error->Warning("Unknown elliptic curve %s", oidhex.c_str());
      }
      default:
	 return _error->Warning("unknown public key algorithm %d in %s", algo, path);
      }
   }
   break;
   default:
      return _error->Warning("unknown version (%d).", key[0]);
      break;
   }
   return true;
}
bool APT::OpenPGP::Keyring::AddKeyFile(const char *path, APT::StringView key)
{
   constexpr int NEW_TAG_FLAG = 0x40;
   constexpr int TAG_MASK = 0x3f;
   constexpr int OLD_TAG_SHIFT = 2;
   constexpr int OLD_LEN_MASK = 0x03;

   enum class Tag
   {
      Signature = 2,
      PubKey = 6,
      Compressed = 8,
      UID = 13,
      PubSubKey = 14,
   };

   bool SkippedOne = false;

   while (not key.empty())
   {
      int c = key[0];
      int tag = c & TAG_MASK;

      key = key.substr(1);

      if (c & NEW_TAG_FLAG)
	 return _error->Warning("Unsupported new tag in %s", path), true;

      int tlen = c & OLD_LEN_MASK;
      tag >>= OLD_TAG_SHIFT;

      // std::cerr << "Packet: c=" << c << " tag=" << tag << " tlen=" << tlen << " len=" << (int)(unsigned char)(key[0]) << "\n";

      int len = 0;
      switch (tlen)
      {
      case 0:
	 len = popc(key);
	 break;
      case 1:
	 len = popc(key) << 8;
	 len += popc(key);
	 break;
      case 2:
	 len = popc(key) << 24;
	 len |= popc(key) << 16;
	 len |= popc(key) << 8;
	 len |= popc(key);
	 break;
      case 3:
	 if (tag == int(Tag::Compressed))
	    return _error->Warning("Unsupported compressed key in %s", path);
	 len = EOF;
	 break;
      default:
	 return _error->Error("Unsupported packet length %d in %s", tlen, path);
      }

      if (len == EOF || _error->PendingError())
	 break;
      if (len < 0)
	 return _error->Error("Negative packet length in %s: %d", path, len);
      switch (tag)
      {
      case int(Tag::PubKey):
      {
	 PublicKey pubKey;
	 SkippedOne = false;
	 if (VerifyPublicKeyPacket(path, key.substr(0, len), pubKey))
	    publicKeys.push_back(pubKey);
	 else
	    SkippedOne = true;
	 break;
      }
      case int(Tag::PubSubKey):
      {
	 PublicKey pubKey;
	 if (SkippedOne)
	    break;
	 if (publicKeys.size() == 0)
	    return _error->Error("UID without key in %s: %s", path, key.substr(0, len).to_string().c_str());
	 if (VerifyPublicKeyPacket(path, key.substr(0, len), pubKey))
	    publicKeys.back().subkeys.push_back(pubKey);
	 break;
      }
      case int(Tag::UID):
	 if (SkippedOne)
	    break;
	 if (publicKeys.size() == 0)
	    return _error->Error("UID without key in %s: %s", path, key.substr(0, len).to_string().c_str());
	 publicKeys.back().uids.push_back(key.substr(0, len).to_string());
	 break;
      case int(Tag::Signature):
      {
	 if (SkippedOne)
	    break;
	 if (publicKeys.size() == 0)
	    return _error->Error("Signature without key in %s", path);

	 auto signature = key.substr(0, len);
	 auto version = signature[0];
	 switch (version)
	 {
	 case 3:
	    return _error->Error("Version 3 signatures are not supported");
	 case 4:
	    auto sigType = signature[1];
	    switch (sigType)
	    {
	    case 0x13: // Self certification
	       break;
	    case 0x18: // Subkey binding signature
	       break;
	    case 0x20: // Key revocation
	       publicKeys.back().revoked = true;
	       break;
	    case 0x28: // Subkey revocation
	       publicKeys.back().subkeys.back().revoked = true;
	       break;
	    }
	    break;
	 }
      }
      default:
	 break;
      }
      assert(key.substr(len).size() == key.size() - len);
      key = key.substr(len);
   }

   return true;
}
