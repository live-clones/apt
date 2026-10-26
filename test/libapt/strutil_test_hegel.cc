/*
 * strutil_test_hegel.cc - Hegel property tests for the string utilities
 *
 * Only built with WITH_HEGEL_TESTS=ON; debian/rules disables them, as
 * configure-time downloads are not allowed during package builds.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <config.h>

#include <apt-pkg/strutl.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "common.h"

#include <hegel/gtest.h>

namespace
{
namespace gs = hegel::generators;

static std::string asString(std::vector<uint8_t> const &bytes)
{
   return std::string(bytes.begin(), bytes.end());
}

static auto const badGen = []()
{
   gs::TextParams p;
   p.min_size = 0;
   p.max_size = 5;
   p.alphabet = " \"[]<>{}#!$";
   return gs::text(p);
}();

TEST(StrUtilHegelTest, Base64Roundtrip)
{
   hegel::test([](hegel::TestCase &tc)
	       {
      auto const input = asString(tc.draw("input", gs::binary({.min_size = 0, .max_size = 64})));

      auto const encoded = Base64Encode(input);
      EXPECT_EQ(0u, encoded.length() % 4);
      EXPECT_TRUE(encoded.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == std::string::npos);
      // Padding is only ever trailing and determined by the input length.
      auto const padding = std::count(encoded.begin(), encoded.end(), '=');
      EXPECT_EQ((3 - input.length() % 3) % 3, static_cast<size_t>(padding));
      EXPECT_TRUE(encoded.find('=') == std::string::npos || encoded.find('=') >= encoded.length() - padding);

      EXPECT_EQ(input, Base64Decode(encoded)); });
}

TEST(StrUtilHegelTest, RFC1123Roundtrip)
{
   hegel::test([](hegel::TestCase &tc)
	       {
      // Formatting stops at year 9999; both ends are UTC (gmtime_r/timegm),
      // so the roundtrip is timezone-independent.
      auto const t = tc.draw("time", gs::integers<time_t>({.min_value = 0, .max_value = 253402300799}));
      auto const numericTz = tc.draw("numericTz", gs::booleans());

      time_t out = 0;
      EXPECT_TRUE(RFC1123StrToTime(TimeRFC1123(t, numericTz), out));
      EXPECT_EQ(t, out); });
}

TEST(StrUtilHegelTest, QuoteStringRoundtrip)
{
   hegel::test([](hegel::TestCase &tc)
	       {
      auto const input = asString(tc.draw("input", gs::binary({.min_size = 0, .max_size = 32})));
      // QuoteString always escapes '%' (and control and non-printable
      // characters), so the roundtrip holds for any set of Bad characters.
      auto const bad = tc.draw("bad", badGen);

      EXPECT_EQ(input, DeQuoteString(QuoteString(input, bad.c_str()))); });
}
} // namespace
