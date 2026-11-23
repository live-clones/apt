#include <config.h>

#include <apt-core/json/json.h>

#include <json-c/json_tokener.h>

#include <cstdint>
#include <expected>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

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

/* Tests for the Encode/Decode functionality: encode(), get(), into() */

static_assert(noexcept(std::declval<JSON::View>().get<bool>()));
static_assert(noexcept(std::declval<JSON::View>().get<std::int64_t>()));
static_assert(noexcept(std::declval<JSON::View>().get<std::uint64_t>()));
static_assert(noexcept(std::declval<JSON::View>().get<int>()));
static_assert(noexcept(std::declval<JSON::View>().get<double>()));
static_assert(noexcept(std::declval<JSON::View>().get<std::string_view>()));
static_assert(not noexcept(std::declval<JSON::View>().get<std::string>()));

static_assert(not JSON::Encodable<std::nullptr_t>);
static_assert(not JSON::Encodable<JSON::Value>);

struct TestStruct
{
   std::string name;
   std::optional<int> count;
};

template <>
struct JSON::Decode<TestStruct>
{
   static std::expected<TestStruct, JSON::Error> operator()(JSON::View v)
   {
      TestStruct result;
      return v.into("name", result.name)
	 .and_then([&] noexcept { return v.into("count", result.count); })
	 .transform([&] { return result; });
   }
};

static_assert(JSON::Decodable<TestStruct>);

template <>
struct JSON::Encode<TestStruct>
{
   static std::expected<Value, JSON::Error> operator()(const TestStruct &val)
   {
      auto obj = Value::object();
      return obj.set("name", val.name)
	 .and_then([&] { return obj.set("count", val.count); })
	 .transform([&] { return std::move(obj); });
   }
};
static_assert(JSON::Encodable<TestStruct>);
static_assert(JSON::Encodable<std::vector<int>>);
static_assert(JSON::Decodable<std::vector<int>>);
static_assert(JSON::Encodable<std::vector<bool>>);
static_assert(JSON::Decodable<std::vector<bool>>);

TEST(JSONValue, EncodeAndGetDispatch)
{
   EXPECT_EQ(JSON::Value::encode(true)->get<bool>().value(), true);
   EXPECT_EQ(JSON::Value::encode(5.0)->get<double>().value(), 5.0);
   EXPECT_EQ(JSON::Value::encode(-5)->get<int>().value(), -5); // sign bypass
   const auto unsignedMaximum = std::numeric_limits<std::uint64_t>::max();
   EXPECT_EQ(JSON::Value::encode(unsignedMaximum)->get<std::uint64_t>().value(), unsignedMaximum);
   EXPECT_EQ(JSON::Value::encode("hello")->get<std::string>().value(), "hello");
   EXPECT_EQ(JSON::Value::encode(static_cast<char *>(nullptr)).error(), JSON::Error::InvalidArgument);

   auto value = JSON::Value::encode(TestStruct{"banana", 42});
   EXPECT_EQ(value->stringify(), R"({"name":"banana","count":42})");

   auto nullCount = JSON::Value::encode(TestStruct{"banana", std::nullopt});
   EXPECT_EQ(nullCount->stringify(), R"({"name":"banana","count":null})");

   EXPECT_TRUE(JSON::Value::array().get<std::vector<int>>().value().empty());
}

TEST(JSONValue, EncodeContainers)
{
   EXPECT_EQ(JSON::Value::encode(std::vector<int>{})->stringify(), R"([])");
   EXPECT_EQ(JSON::Value::encode(std::vector<int>{1, 2, 3})->stringify(), R"([1,2,3])");
   EXPECT_EQ(JSON::Value::encode(std::vector<bool>{true, false, true})->stringify(), R"([true,false,true])");
   EXPECT_EQ(JSON::Value::encode(std::vector<std::string>{"a", "b"})->stringify(), R"(["a","b"])");
   EXPECT_EQ(JSON::Value::encode(std::vector<std::vector<int>>{{}, {1}, {2, 3}})->stringify(), R"([[],[1],[2,3]])");
}

TEST(JSONValue, DecodeIntoContainers)
{
   auto array = JSON::Value::parse(R"([1,2,3])");
   ASSERT_TRUE(array.has_value()) << array.error().message;

   std::vector<int> out{7};
   ASSERT_TRUE(array->into(out).has_value());
   EXPECT_EQ(out, (std::vector<int>{1, 2, 3}));

   std::vector<int> unchanged{7};
   EXPECT_EQ(array->at(1)->into(unchanged).error(), JSON::Error::TypeMismatch);
   EXPECT_EQ(unchanged, (std::vector<int>{7}));

   auto badElement = JSON::Value::parse(R"([1,"x"])");
   ASSERT_TRUE(badElement.has_value()) << badElement.error().message;
   EXPECT_EQ(badElement->get<std::vector<int>>().error(), JSON::Error::TypeMismatch);
}

TEST(JSONValue, DecodeCustomStructs)
{
   auto withCount = JSON::Value::parse(R"({"name":"banana","count":42})");
   ASSERT_TRUE(withCount.has_value()) << withCount.error().message;
   auto banana = withCount->get<TestStruct>();
   ASSERT_TRUE(banana.has_value());
   EXPECT_EQ(banana->name, "banana");
   EXPECT_EQ(banana->count, 42);

   auto withNull = JSON::Value::parse(R"({"name":"banana","count":null})");
   ASSERT_TRUE(withNull.has_value()) << withNull.error().message;
   auto nullCount = withNull->get<TestStruct>();
   ASSERT_TRUE(nullCount.has_value());
   EXPECT_EQ(nullCount->count, std::nullopt);

   auto missingCount = JSON::Value::parse(R"({"name":"banana"})");
   ASSERT_TRUE(missingCount.has_value()) << missingCount.error().message;
   EXPECT_EQ(missingCount->get<TestStruct>().error(), JSON::Error::MissingKey);

   auto wrongNameType = JSON::Value::parse(R"({"name":42,"count":1})");
   ASSERT_TRUE(wrongNameType.has_value()) << wrongNameType.error().message;
   EXPECT_EQ(wrongNameType->get<TestStruct>().error(), JSON::Error::TypeMismatch);
}

TEST(JSONValue, RejectsOutOfRangeNarrowing)
{
   auto overflow = JSON::Value::parse("3000000000");
   ASSERT_TRUE(overflow.has_value()) << overflow.error().message;
   EXPECT_EQ(overflow->get<int>().error(), JSON::Error::OutOfRange);

   auto tooLarge = JSON::Value::parse("4294967296");
   ASSERT_TRUE(tooLarge.has_value()) << tooLarge.error().message;
   EXPECT_EQ(tooLarge->get<unsigned>().error(), JSON::Error::OutOfRange);
}

struct ReflectableTestStruct
{
   std::string name;
   std::optional<int> count;
};

template <>
struct JSON::Reflect<ReflectableTestStruct>
{
   static constexpr auto operator()(auto &val) noexcept
   {
      return std::tuple{
	 std::pair{"name", std::ref(val.name)},
	 std::pair{"count", std::ref(val.count)},
      };
   }
};

static_assert(JSON::Reflectable<ReflectableTestStruct>);
static_assert(JSON::Decodable<ReflectableTestStruct>);
static_assert(JSON::Encodable<ReflectableTestStruct>);

TEST(JSONValue, ReflectableStructsEncode)
{
   auto obj = JSON::Value::encode(ReflectableTestStruct{"test", 42});
   ASSERT_TRUE(obj.has_value());
   ASSERT_EQ(obj->stringify(), R"({"name":"test","count":42})");
}

TEST(JSONValue, ReflectableStructsDecode)
{
   auto obj = JSON::Value::parse(R"({"name":"test","count":43})");
   EXPECT_TRUE(obj->get<ReflectableTestStruct>().has_value());
   EXPECT_EQ(obj->get<ReflectableTestStruct>()->name, "test");
   EXPECT_EQ(obj->get<ReflectableTestStruct>()->count, 43);
}

TEST(JSONValue, ReflectableStructsNull)
{
   // Missing key is fine
   auto parsedMissing = JSON::Value::parse(R"({"name":"test"})");
   EXPECT_EQ(parsedMissing->get<ReflectableTestStruct>()->name, "test");
   EXPECT_EQ(parsedMissing->get<ReflectableTestStruct>()->count, std::nullopt);
   ASSERT_EQ(parsedMissing->stringify(), R"({"name":"test"})");
   // Parse explicit null; object is fine
   auto parsedNull = JSON::Value::parse(R"({"name":"test","count":null})");
   auto reflectedNull = parsedNull->get<ReflectableTestStruct>();
   EXPECT_EQ(reflectedNull->name, "test");
   EXPECT_EQ(reflectedNull->count, std::nullopt);
   ASSERT_EQ(parsedNull->stringify(), R"({"name":"test","count":null})");
   // Encoding it back we do not render null
   ASSERT_EQ(JSON::Value::encode(*reflectedNull)->stringify(), R"({"name":"test"})");
}
