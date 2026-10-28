/*
 * debversion_test_hegel.cc - Hegel property tests for Debian version comparison
 *
 * Only built with WITH_HEGEL_TESTS=ON; debian/rules disables them, as
 * configure-time downloads are not allowed during package builds.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <config.h>

#include <apt-pkg/debversion.h>

#include <algorithm>
#include <cctype>
#include <string>

#include "common.h"

#include <hegel/gtest.h>

namespace
{
namespace gs = hegel::generators;

// A small alphabet makes colliding and near-equal versions (leading zeros,
// tilde boundaries, epoch separators) frequent.
static auto const versionGen = []()
{
   gs::TextParams p;
   p.min_size = 1;
   p.max_size = 12;
   p.alphabet = "0129ab~-.+:";
   return gs::text(p);
}();

// Versions are C strings at some API boundaries: NUL bytes cannot occur.
static std::string normalizeVersion(std::string version)
{
   std::replace(version.begin(), version.end(), '\0', '0');
   return version;
}

TEST(DebVersionHegelTest, ComparisonLaws)
{
   hegel::test([](hegel::TestCase &tc)
	       {
      auto less = [](auto const &x, auto const &y) { return debVS.CmpVersion(x, y) < 0; };
      auto equal = [](auto const &x, auto const &y) { return debVS.CmpVersion(x, y) == 0; };

      auto const a = normalizeVersion(tc.draw("a", versionGen));
      auto const b = normalizeVersion(tc.draw("b", versionGen));
      auto const c = normalizeVersion(tc.draw("c", versionGen));

      // A strict weak ordering with a non-trivial equivalence (versions
      // like "01" and "1" differ but compare equal); <= on booleans is
      // implication.
      EXPECT_TRUE(equal(a, a));                                             // reflexivity
      EXPECT_TRUE(less(a, b) <= not less(b, a));                            // antisymmetry
      EXPECT_TRUE(less(a, b) || equal(a, b) || less(b, a));                 // totality
      EXPECT_TRUE((less(a, b) && less(b, c)) <= less(a, c));                // transitivity
      EXPECT_TRUE((equal(a, b) && equal(b, c)) <= equal(a, c));             // equivalence transitivity
      EXPECT_TRUE(equal(a, b) <= (less(a, c) == less(b, c)));               // equivalence consistency

      // Leading zeros of a digit run are insignificant: inserting a zero at
      // the start of a digit run (previous char is not a digit) yields an
      // equivalent version. Prefer an interior run over the leading one.
      if (auto first = a.find_first_of("0123456789"); first != std::string::npos)
      {
	 size_t digit = first;
	 for (auto i = a.find_first_of("0123456789", first + 1); i != std::string::npos; i = a.find_first_of("0123456789", i + 1))
	 {
	    if (not isdigit(static_cast<unsigned char>(a[i - 1])))
	    {
	       digit = i;
	       break;
	    }
	 }
	 std::string aZero = a;
	 aZero.insert(digit, 1, '0');
	 EXPECT_TRUE(equal(a, aZero));
	 EXPECT_EQ(less(a, b), less(aZero, b));
	 EXPECT_EQ(less(b, a), less(b, aZero));
      } });
}
} // namespace
