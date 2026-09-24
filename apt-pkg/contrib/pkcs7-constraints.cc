// -*- mode: cpp; mode: fold -*-
// Description							/*{{{*/
/* pkcs7-constraints.cc - Certificate constraint datatypes and factories.
 *
 * Implementation of the CertificateConstraints aggregate, the built-in
 * check factory functions, and the default repo-signing policy
 * assemblers (DefaultRepoSignerPolicy / DefaultRepoAnchorPolicy) that
 * build the standard APT constraint set from origin + suite.
 */
									/*}}}*/
// Include Files						/*{{{*/
#include <config.h>

#include <apt-pkg/pkcs7-constraints.h>
#include <apt-pkg/error.h>

#include <functional>
#include <string>
#include <utility>
#include <vector>

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace APT
{
namespace Internal
{
									/*}}}*/

// Placeholder APT repository signing Extended Key Usage OID.
char const *const REPO_SIGNING_EKU = "1.3.6.1.4.1.99999.2";

// Internal helpers							/*{{{*/

// Fetch BasicConstraints: returns false if absent/unparseable.
static bool GetBasicConstraints(X509 *cert, bool &critical, bool &isCA)
{
   int const idx = X509_get_ext_by_NID(cert, NID_basic_constraints, -1);
   if (idx < 0)
      return false;
   X509_EXTENSION *const ext = X509_get_ext(cert, idx);
   BASIC_CONSTRAINTS *const bc = (BASIC_CONSTRAINTS *)X509_get_ext_d2i(cert, NID_basic_constraints, nullptr, nullptr);
   if (bc == nullptr)
      return false;
   critical = (X509_EXTENSION_get_critical(ext) == 1);
   isCA = (bc->ca != 0);
   BASIC_CONSTRAINTS_free(bc);
   return true;
}

									/*}}}*/
// CertificateConstraints implementation					/*{{{*/

class CertConstraintsImpl
{
public:
   std::vector<std::function<bool(X509 *)>> checks;
};

CertificateConstraints::CertificateConstraints()
     : d(new CertConstraintsImpl()) {}
CertificateConstraints::~CertificateConstraints() { delete d; }
CertificateConstraints::CertificateConstraints(CertificateConstraints &&other) noexcept
     : d(other.d) { other.d = nullptr; }
CertificateConstraints &CertificateConstraints::operator=(CertificateConstraints &&other) noexcept
{
   if (this != &other)
   {
      delete d;
      d = other.d;
      other.d = nullptr;
   }
   return *this;
}

CertificateConstraints &CertificateConstraints::Add(std::function<bool(X509 *)> check)
{
   static_cast<CertConstraintsImpl *>(d)->checks.push_back(std::move(check));
   return *this;
}

bool CertificateConstraints::Apply(X509 *cert)
{
   for (auto const &check : static_cast<CertConstraintsImpl *>(d)->checks)
   {
      if (not check(cert))
	 return false;
   }
   return true;
}

									/*}}}*/
// Built-in certificate check factories (internal)			/*{{{*/

// BasicConstraints: present, critical, and CA value must match.
static std::function<bool(X509 *)> BasicConstraintsCheck(bool critical, bool ca)
{
   return [critical, ca](X509 *cert) -> bool {
      bool crit = false, isCA = false;
      if (not GetBasicConstraints(cert, crit, isCA))
      {
	 return _error->Error("BasicConstraints extension missing or unparseable");
      }
      if (crit != critical || isCA != ca)
      {
	 return _error->Error("BasicConstraints must be %s and %s",
			      critical ? "critical" : "non-critical",
			      ca ? "CA:TRUE" : "CA:FALSE");
      }
      return true;
   };
}

// KeyUsage: present, critical, and include all required bits.
static std::function<bool(X509 *)> KeyUsageCheck(unsigned long requiredBits, bool critical)
{
   return [requiredBits, critical](X509 *cert) -> bool {
      int const idx = X509_get_ext_by_NID(cert, NID_key_usage, -1);
      if (idx < 0)
	 return _error->Error("KeyUsage extension missing");
      X509_EXTENSION *const ext = X509_get_ext(cert, idx);
      if (X509_EXTENSION_get_critical(ext) != (critical ? 1 : 0))
	 return _error->Error("KeyUsage extension criticality mismatch");
      unsigned long const flags = X509_get_extension_flags(cert);
      if ((flags & EXFLAG_KUSAGE) == 0)
	 return _error->Error("KeyUsage extension not parsed");
      if ((X509_get_key_usage(cert) & requiredBits) != requiredBits)
	 return _error->Error("KeyUsage does not include all required bits");
      return true;
   };
}

// ExtendedKeyUsage: present and include the specified OID.
static std::function<bool(X509 *)> ExtendedKeyUsageCheck(std::string oid)
{
   return [oid](X509 *cert) -> bool {
      EXTENDED_KEY_USAGE *const eku = (EXTENDED_KEY_USAGE *)X509_get_ext_d2i(cert, NID_ext_key_usage, nullptr, nullptr);
      if (eku == nullptr)
	 return _error->Error("ExtendedKeyUsage extension missing");
      bool found = false;
      for (int i = 0; i < sk_ASN1_OBJECT_num(eku); ++i)
      {
	 ASN1_OBJECT const *const obj = sk_ASN1_OBJECT_value(eku, i);
	 char buf[128];
	 if (OBJ_obj2txt(buf, sizeof(buf), obj, 1) > 0 && strcmp(buf, oid.c_str()) == 0)
	 {
	    found = true;
	    break;
	 }
      }
      EXTENDED_KEY_USAGE_free(eku);
      if (not found)
	 return _error->Error("ExtendedKeyUsage does not include required OID %s", oid.c_str());
      return true;
   };
}

// Validity: certificate must be currently valid.
static std::function<bool(X509 *)> ValidityCheck()
{
   return [](X509 *cert) -> bool {
      time_t now = time(nullptr);
      if (X509_cmp_time(X509_get0_notBefore(cert), &now) > 0)
	 return _error->Error("certificate is not yet valid");
      if (X509_cmp_time(X509_get0_notAfter(cert), &now) < 0)
	 return _error->Error("certificate has expired");
      return true;
   };
}

// SubjectAltName: must contain a dNSName or URI matching the suite,
// AND the subject O= field must match the origin.
static std::function<bool(X509 *)> SubjectAltNameCheck(std::string suite, std::string origin)
{
   return [suite, origin](X509 *cert) -> bool {
      GENERAL_NAMES *const sans = (GENERAL_NAMES *)X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr);
      if (sans == nullptr)
	 return _error->Error("SubjectAltName extension missing");

      bool suiteMatch = false;
      for (int i = 0; i < sk_GENERAL_NAME_num(sans); ++i)
      {
	 GENERAL_NAME const *const gn = sk_GENERAL_NAME_value(sans, i);
	 ASN1_STRING const *str = nullptr;
	 if (gn->type == GEN_DNS)
	    str = gn->d.dNSName;
	 else if (gn->type == GEN_URI)
	    str = gn->d.uniformResourceIdentifier;
	 if (str == nullptr)
	    continue;
	 unsigned char *utf8 = nullptr;
	 int const len = ASN1_STRING_to_UTF8(&utf8, str);
	 if (len < 0)
	    continue;
	 std::string const san(reinterpret_cast<char *>(utf8), static_cast<std::size_t>(len));
	 OPENSSL_free(utf8);
	 if (san == suite)
	 {
	    suiteMatch = true;
	    break;
	 }
      }
      sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);

      if (not suiteMatch)
	 return _error->Error("SubjectAltName does not match suite '%s'", suite.c_str());

      // Check Origin against the subject O= field.
      if (not origin.empty())
      {
	 X509_NAME *const subject = X509_get_subject_name(cert);
	 if (subject == nullptr)
	    return _error->Error("certificate subject missing");
	 char originBuf[256];
	 int const olen = X509_NAME_get_text_by_NID(subject, NID_organizationName, originBuf, sizeof(originBuf));
	 if (olen < 0)
	    return _error->Error("certificate subject O= field missing");
	 std::string const certOrigin(originBuf, static_cast<std::size_t>(olen));
	 if (certOrigin != origin)
	    return _error->Error("certificate origin '%s' does not match expected '%s'",
				 certOrigin.c_str(), origin.c_str());
      }
      return true;
   };
}

// TrustAnchor: BasicConstraints present+critical+CA:TRUE and
// KeyUsage keyCertSign.
static std::function<bool(X509 *)> TrustAnchorCheck()
{
   return [](X509 *cert) -> bool {
      bool critical = false, isCA = false;
      if (not GetBasicConstraints(cert, critical, isCA))
	 return _error->Error("trust anchor BasicConstraints extension missing or unparseable");
      if (not critical || not isCA)
	 return _error->Error("trust anchor must have critical BasicConstraints CA:TRUE");
      unsigned long const flags = X509_get_extension_flags(cert);
      if ((flags & EXFLAG_KUSAGE) == 0 || (X509_get_key_usage(cert) & KU_KEY_CERT_SIGN) == 0)
	 return _error->Error("trust anchor KeyUsage must include keyCertSign");
      return true;
   };
}

									/*}}}*/
// Default policy assemblers						/*{{{*/

CertificateConstraints DefaultRepoSignerPolicy(std::string origin, std::string suite)
{
   CertificateConstraints policy;
   policy
      .Add(BasicConstraintsCheck(true, false))
      .Add(KeyUsageCheck(KU_DIGITAL_SIGNATURE, true))
      .Add(ExtendedKeyUsageCheck(REPO_SIGNING_EKU))
      .Add(ValidityCheck())
      .Add(SubjectAltNameCheck(std::move(suite), std::move(origin)));
   return policy;
}

CertificateConstraints DefaultRepoAnchorPolicy()
{
   CertificateConstraints policy;
   policy.Add(TrustAnchorCheck());
   return policy;
}

									/*}}}*/

} // namespace Internal
} // namespace APT
