#include <config.h>

#include <apt-core/json/json.h>

#include <json-c/json_tokener.h>

#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include "common.h"

namespace JSON = APT::JSON;

static_assert(not std::is_copy_constructible_v<JSON::Value>);
static_assert(not std::is_copy_assignable_v<JSON::Value>);
static_assert(std::is_nothrow_move_constructible_v<JSON::Value>);
static_assert(std::is_nothrow_move_assignable_v<JSON::Value>);
static_assert(std::is_copy_constructible_v<JSON::View>);

static_assert(noexcept(std::declval<JSON::View>().asBoolean()));
static_assert(noexcept(std::declval<JSON::View>().asInt64()));
static_assert(noexcept(std::declval<JSON::View>().asUInt64()));
static_assert(noexcept(std::declval<JSON::View>().asDouble()));
static_assert(noexcept(std::declval<JSON::View>().asString()));
static_assert(noexcept(std::declval<JSON::View>().find("key")));

TEST(JSONValue, ParseAndInspect)
{
   constexpr std::string_view input = R"({"method":"org.example.Test","parameters":{"answer":42},"more":true})";
   auto value = JSON::Value::parse(input);
   ASSERT_TRUE(value.has_value()) << value.error().message;
   EXPECT_EQ(value->type(), JSON::Type::Object);
   ASSERT_EQ(value->size().value(), 3U);

   auto method = value->find("method");
   ASSERT_TRUE(method.has_value());
   auto methodName = method->asString();
   ASSERT_TRUE(methodName.has_value());
   EXPECT_EQ(*methodName, "org.example.Test");

   auto parameters = value->find("parameters");
   ASSERT_TRUE(parameters.has_value());
   auto answer = parameters->find("answer");
   ASSERT_TRUE(answer.has_value());
   EXPECT_EQ(answer->asInt64().value(), 42);

   auto more = value->find("more");
   ASSERT_TRUE(more.has_value());
   EXPECT_EQ(more->asBoolean().value(), true);
   EXPECT_EQ(value->find("missing").error(), JSON::Error::MissingKey);

   const auto serialized = value->stringify();
   auto reparsed = JSON::Value::parse(serialized);
   ASSERT_TRUE(reparsed.has_value()) << reparsed.error().message;
   EXPECT_TRUE(*value == *reparsed);
}

TEST(JSONValue, KeyedAndMissingKeyAccessors)
{
   auto value = JSON::Value::parse(R"({"nothing":null})");
   ASSERT_TRUE(value.has_value()) << value.error().message;

   auto explicitNull = value->find("nothing");
   ASSERT_TRUE(explicitNull.has_value());
   EXPECT_TRUE(*explicitNull == nullptr);

   auto missingAsNull = value->find("missing", JSON::MissingKeyPolicy::Null);
   ASSERT_TRUE(missingAsNull.has_value());
   EXPECT_TRUE(*missingAsNull == nullptr);
}

TEST(JSONValue, StrictParsing)
{
   for (const auto *const input : {"", "{", "{} trailing", "{} {}", "[1,]", "/* comment */{}", "{\"number\":01}", "{'a':1}", "{\"a\":'b'}"})
   {
      SCOPED_TRACE(input);
      EXPECT_FALSE(JSON::Value::parse(input).has_value());
   }

   std::string deeplyNested(JSON_TOKENER_DEFAULT_DEPTH + 2, '[');
   deeplyNested.append(JSON_TOKENER_DEFAULT_DEPTH + 2, ']');
   auto tooDeep = JSON::Value::parse(deeplyNested);
   ASSERT_FALSE(tooDeep.has_value());
   EXPECT_EQ(tooDeep.error().code, JSON::ParseErrorCode::NestingLimitExceeded);

   constexpr std::string_view invalidUtf8 = "{\"key\":\"\xC3\x28\"}";
   auto badUtf8 = JSON::Value::parse(invalidUtf8);
   ASSERT_FALSE(badUtf8.has_value());
   EXPECT_EQ(badUtf8.error().code, JSON::ParseErrorCode::InvalidSyntax);

   auto whitespace = JSON::Value::parse(" \t\r\n {\"valid\":true} \n");
   ASSERT_TRUE(whitespace.has_value()) << whitespace.error().message;

   auto numberWithWhitespace = JSON::Value::parse(" 42 \n");
   ASSERT_TRUE(numberWithWhitespace.has_value()) << numberWithWhitespace.error().message;
   EXPECT_EQ(numberWithWhitespace->asInt64().value(), 42);

   auto whitespaceOnly = JSON::Value::parse("  \t ");
   ASSERT_FALSE(whitespaceOnly.has_value());
   EXPECT_EQ(whitespaceOnly.error().code, JSON::ParseErrorCode::UnexpectedEnd);

   constexpr char inputWithNul[] = "{}\0ignored";
   auto nulResult = JSON::Value::parse(std::string_view(inputWithNul, sizeof(inputWithNul) - 1));
   ASSERT_FALSE(nulResult.has_value());
   EXPECT_EQ(nulResult.error().code, JSON::ParseErrorCode::EmbeddedNul);
   EXPECT_EQ(nulResult.error().offset, 2U);

   EXPECT_FALSE(JSON::Value::parse(R"({"value":"\u0000"})").has_value());
   EXPECT_FALSE(JSON::Value::parse(R"({"bad\u0000key":true})").has_value());

   auto literalEscape = JSON::Value::parse(R"({"value":"\\u0000"})");
   ASSERT_TRUE(literalEscape.has_value()) << literalEscape.error().message;
   EXPECT_EQ(literalEscape->find("value")->asString().value(), R"(\u0000)");
}

TEST(JSONValue, NullAndFormatting)
{
   JSON::Value null;
   EXPECT_TRUE(null == nullptr);
   EXPECT_EQ(null.type(), JSON::Type::Null);
   EXPECT_EQ(null.stringify(), "null");

   auto parsedNull = JSON::Value::parse("null");
   ASSERT_TRUE(parsedNull.has_value());
   EXPECT_TRUE(*parsedNull == nullptr);

   JSON::Value array = JSON::Value::array();
   auto string = JSON::Value::string("value");
   ASSERT_TRUE(string.has_value());
   ASSERT_TRUE(array.append(std::move(*string)));
   ASSERT_TRUE(array.append(JSON::Value{}));
   EXPECT_EQ(array.stringify(), R"(["value",null])");
   EXPECT_NE(array.stringify(JSON::Format::Pretty).find('\n'), std::string::npos);
}

TEST(JSONValue, IntegerBoundaries)
{
   auto signedMinimum = JSON::Value::integer(std::numeric_limits<std::int64_t>::min());
   EXPECT_EQ(signedMinimum.asInt64().value(), std::numeric_limits<std::int64_t>::min());
   EXPECT_EQ(signedMinimum.asUInt64().error(), JSON::Error::OutOfRange);

   auto signedMaximum = JSON::Value::integer(std::numeric_limits<std::int64_t>::max());
   EXPECT_EQ(signedMaximum.asInt64().value(), std::numeric_limits<std::int64_t>::max());
   EXPECT_EQ(signedMaximum.asUInt64().value(), static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()));

   auto unsignedMaximum = JSON::Value::unsignedInteger(std::numeric_limits<std::uint64_t>::max());
   EXPECT_EQ(unsignedMaximum.asUInt64().value(), std::numeric_limits<std::uint64_t>::max());
   EXPECT_EQ(unsignedMaximum.asInt64().error(), JSON::Error::OutOfRange);
   EXPECT_EQ(unsignedMaximum.asDouble().value(), static_cast<double>(std::numeric_limits<std::uint64_t>::max()));
   EXPECT_EQ(unsignedMaximum.stringify(), "18446744073709551615");

   auto parsed = JSON::Value::parse("18446744073709551615");
   ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
   EXPECT_EQ(parsed->asUInt64().value(), std::numeric_limits<std::uint64_t>::max());
   EXPECT_EQ(parsed->asInt64().error(), JSON::Error::OutOfRange);
}

TEST(JSONValue, StrictAccessors)
{
   auto integer = JSON::Value::integer(12);
   EXPECT_EQ(integer.asDouble().value(), 12.0);
   EXPECT_EQ(integer.asString().error(), JSON::Error::TypeMismatch);
   EXPECT_EQ(integer.asBoolean().error(), JSON::Error::TypeMismatch);
   EXPECT_EQ(integer.size().error(), JSON::Error::TypeMismatch);
   EXPECT_EQ(integer.find("key").error(), JSON::Error::TypeMismatch);
   EXPECT_EQ(integer.at(0).error(), JSON::Error::TypeMismatch);

   auto real = JSON::Value::real(1.25);
   ASSERT_TRUE(real.has_value());
   EXPECT_EQ(real->asDouble().value(), 1.25);
   EXPECT_EQ(real->asInt64().error(), JSON::Error::TypeMismatch);
   EXPECT_EQ(real->asUInt64().error(), JSON::Error::TypeMismatch);

   auto parsedReal = JSON::Value::parse("1.25");
   ASSERT_TRUE(parsedReal.has_value()) << parsedReal.error().message;
   EXPECT_EQ(parsedReal->type(), JSON::Type::Real);
   EXPECT_EQ(parsedReal->asDouble().value(), 1.25);

   auto string = JSON::Value::string("hello");
   ASSERT_TRUE(string.has_value());
   EXPECT_EQ(string->asString().value(), "hello");
   EXPECT_EQ(string->asDouble().error(), JSON::Error::TypeMismatch);

   auto empty = JSON::Value::string({});
   ASSERT_TRUE(empty.has_value());
   EXPECT_EQ(empty->asString().value(), "");
   EXPECT_EQ(empty->stringify(), "\"\"");

   auto escaped = JSON::Value::string("quote=\" backslash=\\ dot=\\.");
   ASSERT_TRUE(escaped.has_value());
   EXPECT_EQ(escaped->stringify(), R"("quote=\" backslash=\\ dot=\\.")");

   auto slashed = JSON::Value::string("https://example.com");
   ASSERT_TRUE(slashed.has_value());
   EXPECT_EQ(slashed->stringify(), R"("https://example.com")");
}

TEST(JSONValue, ObjectAndArrayUpdates)
{
   auto object = JSON::Value::object();
   ASSERT_TRUE(object.set("answer", JSON::Value::integer(42)));
   auto answer = JSON::Value::string("forty-two");
   ASSERT_TRUE(answer.has_value());
   ASSERT_TRUE(object.set("answer", std::move(*answer)));
   ASSERT_TRUE(object.set("nothing", JSON::Value{}));
   EXPECT_EQ(object.size().value(), 2U);
   EXPECT_EQ(object.find("answer")->asString().value(), "forty-two");
   EXPECT_TRUE(*object.find("nothing") == nullptr);

   auto copy = JSON::Value(static_cast<const JSON::View &>(object));
   ASSERT_TRUE(object.set("answer", JSON::Value::integer(7)));
   EXPECT_EQ(object.find("answer")->asInt64().value(), 7);
   EXPECT_EQ(copy.find("answer")->asString().value(), "forty-two");
   EXPECT_EQ(copy.stringify(), R"({"answer":"forty-two","nothing":null})");

   auto array = JSON::Value::array();
   ASSERT_TRUE(array.append(JSON::Value::boolean(true)));
   ASSERT_TRUE(array.append(std::move(object)));
   ASSERT_EQ(array.size().value(), 2U);
   EXPECT_EQ(array.at(0)->asBoolean().value(), true);
   EXPECT_EQ(array.at(1)->find("answer")->asInt64().value(), 7);
   EXPECT_EQ(array.at(2).error(), JSON::Error::OutOfRange);

   EXPECT_EQ(array.set("key", JSON::Value{}).error(), JSON::Error::TypeMismatch);
   EXPECT_EQ(copy.append(JSON::Value{}).error(), JSON::Error::TypeMismatch);

   EXPECT_EQ(copy.find(nullptr).error(), JSON::Error::InvalidArgument);
   EXPECT_EQ(copy.set(nullptr, JSON::Value{}).error(), JSON::Error::InvalidArgument);
}

TEST(JSONValue, RejectsSelfInsertionWithoutFormingCycles)
{
   auto object = JSON::Value::object();
   EXPECT_EQ(object.set("self", std::move(object)).error(), JSON::Error::TypeMismatch);
   EXPECT_EQ(object.type(), JSON::Type::Null);

   auto array = JSON::Value::array();
   EXPECT_EQ(array.append(std::move(array)).error(), JSON::Error::TypeMismatch);
   EXPECT_EQ(array.type(), JSON::Type::Null);
}

TEST(JSONValue, RejectsNonFiniteNumbersOnAccess)
{
   auto nan = JSON::Value::parse("NaN");
   ASSERT_TRUE(nan.has_value()) << nan.error().message;
   EXPECT_EQ(nan->asDouble().error(), JSON::Error::InvalidArgument);

   auto overflow = JSON::Value::parse(R"({"value":1e999})");
   ASSERT_TRUE(overflow.has_value()) << overflow.error().message;
   EXPECT_EQ(overflow->find("value")->asDouble().error(), JSON::Error::InvalidArgument);
}

TEST(JSONValue, RejectsNonPortableValues)
{
   constexpr std::string_view stringWithNul("a\0b", 3);
   EXPECT_EQ(JSON::Value::string(stringWithNul).error(), JSON::Error::InvalidArgument);
   EXPECT_EQ(JSON::Value::real(std::numeric_limits<double>::quiet_NaN()).error(), JSON::Error::InvalidArgument);
   EXPECT_EQ(JSON::Value::real(std::numeric_limits<double>::infinity()).error(), JSON::Error::InvalidArgument);
}
