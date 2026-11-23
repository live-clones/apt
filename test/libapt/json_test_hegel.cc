/*
 * json_test_hegel.cc - Hegel property tests for JSON values
 *
 * Only built with WITH_HEGEL_TESTS=ON; debian/rules disables them, as
 * configure-time downloads are not allowed during package builds.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <config.h>

#include <apt-core/json/json.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "common.h"

#include <hegel/gtest.h>

namespace
{
namespace gs = hegel::generators;

std::string drawString(hegel::TestCase &tc, const char *name)
{
   const auto bytes = tc.draw(name, gs::binary({.min_size = 0, .max_size = 32}));
   static constexpr std::string_view alphabet = "ab01 \"'\\/\n\t";
   std::string result;
   result.reserve(bytes.size());
   for (const auto byte : bytes)
      result += alphabet[byte % alphabet.size()];
   return result;
}

APT::JSON::Value drawJson(hegel::TestCase &tc, std::size_t depth)
{
   const int kind = tc.draw("kind", gs::integers<int>({.min_value = 0, .max_value = depth == 0 ? 5 : 7}));
   switch (kind)
   {
   case 0:
      return {};
   case 1:
      return APT::JSON::Value::boolean(tc.draw("boolean", gs::booleans()));
   case 2:
      return APT::JSON::Value::integer(tc.draw("integer", gs::integers<std::int64_t>()));
   case 3:
      return APT::JSON::Value::unsignedInteger(tc.draw("unsigned", gs::integers<std::uint64_t>()));
   case 4:
      return APT::JSON::Value::real(tc.draw("real", gs::floats<double>({.allow_nan = false, .allow_infinity = false}))).value();
   case 5:
      return APT::JSON::Value::string(drawString(tc, "string")).value();
   case 6:
   {
      auto array = APT::JSON::Value::array();
      const auto size = tc.draw("arraySize", gs::integers<std::size_t>({.min_value = 0, .max_value = 2}));
      for (std::size_t index = 0; index < size; ++index)
	 EXPECT_TRUE(array.append(drawJson(tc, depth - 1)));
      return array;
   }
   case 7:
   {
      auto object = APT::JSON::Value::object();
      const auto size = tc.draw("objectSize", gs::integers<std::size_t>({.min_value = 0, .max_value = 2}));
      for (std::size_t index = 0; index < size; ++index)
      {
	 const auto key = drawString(tc, "key");
	 EXPECT_TRUE(object.set(key.c_str(), drawJson(tc, depth - 1)));
      }
      return object;
   }
   default:
      std::unreachable();
   }
}

void expectRoundTrip(const APT::JSON::Value &value)
{
   const auto serialized = value.stringify();
   auto parsed = APT::JSON::Value::parse(serialized);
   ASSERT_TRUE(parsed.has_value()) << serialized << ": " << parsed.error().message;
   EXPECT_TRUE(value == *parsed) << serialized;
   EXPECT_EQ(serialized, parsed->stringify());

   auto copy = APT::JSON::Value(static_cast<const APT::JSON::View &>(value));
   EXPECT_TRUE(value == copy) << serialized;
   EXPECT_EQ(serialized, copy.stringify());
}
} // namespace

TEST(JSONValueHegelTest, StringRoundTrip)
{
   hegel::test([](hegel::TestCase &tc) {
      const auto input = drawString(tc, "input");
      auto value = APT::JSON::Value::string(input);
      auto parsed = APT::JSON::Value::parse(value->stringify());
      ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
      auto output = parsed->asString();
      ASSERT_TRUE(output.has_value());
      EXPECT_EQ(input, *output);
      expectRoundTrip(*value); });
}

TEST(JSONValueHegelTest, NestedRoundTrip)
{
   hegel::test([](hegel::TestCase &tc) { expectRoundTrip(drawJson(tc, 2)); });
}
