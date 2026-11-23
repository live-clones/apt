/*
 * json.cc - JSON values implemented with json-c
 *
 * SPDX-License-Identifier: GPL-2.0+
 */
#include <config.h>

#include <apt-core/json/json.h>

#include <json-c/json_object.h>
#include <json-c/json_tokener.h>

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <memory>
#include <new>
#include <stdexcept>
#include <utility>

using namespace std::string_view_literals;

namespace APT::JSON
{
namespace
{
Handle *nonNull(Handle *handle)
{
   if (handle == nullptr)
      throw std::bad_alloc();
   return handle;
}

// Additional strictness checks before json-c parser:
// - \0 bytes in the input (json-c silently truncates if in a string)
// - \u0000 escaped nul bytes in string values (json-c silently truncates)
// - single quoted strings
std::expected<void, ParseError> validateJsonSyntax(std::string_view input)
{
   constexpr std::string_view escapedNul = "\\u0000"sv;
   bool inString = false;
   for (std::size_t index = 0; index < input.size(); ++index)
   {
      const std::string_view remaining = input.substr(index);
      switch (remaining.front())
      {
      case '\0':
	 return std::unexpected(ParseError{.code = ParseErrorCode::EmbeddedNul, .offset = index, .message = "JSON input contains an embedded NUL character"});
      case '\'':
	 if (not inString)
	    return std::unexpected(ParseError{.code = ParseErrorCode::InvalidSyntax, .offset = index, .message = "Single-quoted strings are not valid JSON"});
	 break;
      case '"':
	 inString = not inString;
	 break;
      case '\\':
	 if (inString)
	 {
	    if (remaining.starts_with(escapedNul))
	       return std::unexpected(ParseError{.code = ParseErrorCode::EmbeddedNul, .offset = index, .message = "JSON strings cannot contain embedded NUL characters"});
	    if (remaining.starts_with("\\\""sv) || remaining.starts_with("\\\\"sv))
	       ++index; // ignore those special escaped characters so our quoting and escape logic is consistent
	 }
	 break;
      default:
	 break;
      }
   }
   return {};
}
} // namespace

Type View::type() const noexcept
{
   switch (json_object_get_type(handle))
   {
   case json_type_null:
      return Type::Null;
   case json_type_boolean:
      return Type::Boolean;
   case json_type_int:
      return Type::Integer;
   case json_type_double:
      return Type::Real;
   case json_type_string:
      return Type::String;
   case json_type_array:
      return Type::Array;
   case json_type_object:
      return Type::Object;
   }
   std::unreachable();
}

std::expected<bool, Error> View::asBoolean() const noexcept
{
   if (type() != Type::Boolean)
      return std::unexpected(Error::TypeMismatch);
   return json_object_get_boolean(handle) != 0;
}

std::expected<std::int64_t, Error> View::asInt64() const noexcept
{
   if (type() != Type::Integer)
      return std::unexpected(Error::TypeMismatch);

   errno = 0;
   const auto value = json_object_get_int64(handle);
   if (errno != 0)
      return std::unexpected(Error::OutOfRange);
   return value;
}

std::expected<std::uint64_t, Error> View::asUInt64() const noexcept
{
   if (type() != Type::Integer)
      return std::unexpected(Error::TypeMismatch);

   // json-c before 0.19 returns 0 without errno for negative integers.
   errno = 0;
   const auto signedValue = json_object_get_int64(handle);
   if (errno == 0 && signedValue < 0)
      return std::unexpected(Error::OutOfRange);

   errno = 0;
   const auto value = json_object_get_uint64(handle);
   if (errno != 0)
      return std::unexpected(Error::OutOfRange);
   return value;
}

std::expected<double, Error> View::asDouble() const noexcept
{
   switch (type())
   {
   case Type::Integer:
      if (auto signedVal = asInt64(); signedVal)
	 return static_cast<double>(*signedVal);
      if (auto unsignedVal = asUInt64(); unsignedVal)
	 return static_cast<double>(*unsignedVal);
      return std::unexpected(Error::OutOfRange);
   case Type::Real:
   {
      const auto value = json_object_get_double(handle);
      if (not std::isfinite(value))
	 return std::unexpected(Error::InvalidArgument);
      return value;
   }
   default:
      return std::unexpected(Error::TypeMismatch);
   }
}

std::expected<std::string_view, Error> View::asString() const noexcept
{
   if (type() != Type::String)
      return std::unexpected(Error::TypeMismatch);

   const auto length = json_object_get_string_len(handle);
   const char *const text = json_object_get_string(handle);
   // Cheap assertions. No NUL bytes is enforced in Value::parse() and Value::string()
   if (length < 0 || text == nullptr)
      return std::unexpected(Error::InvalidArgument);

   return std::string_view(text, static_cast<std::size_t>(length));
}

std::expected<std::size_t, Error> View::size() const noexcept
{
   if (type() == Type::Array)
      return json_object_array_length(handle);
   if (type() == Type::Object)
      return static_cast<std::size_t>(json_object_object_length(handle));
   return std::unexpected(Error::TypeMismatch);
}

std::expected<View, Error> View::find(const char *key, MissingKeyPolicy missingKeyPolicy) const noexcept
{
   if (key == nullptr)
      return std::unexpected(Error::InvalidArgument);
   if (type() != Type::Object)
      return std::unexpected(Error::TypeMismatch);

   json_object *value = nullptr;
   if (json_object_object_get_ex(handle, key, &value) == 0)
   {
      if (missingKeyPolicy == MissingKeyPolicy::Null)
	 return View();
      return std::unexpected(Error::MissingKey);
   }
   return View(value);
}

std::expected<View, Error> View::at(std::size_t index) const noexcept
{
   if (type() != Type::Array)
      return std::unexpected(Error::TypeMismatch);
   if (index >= json_object_array_length(handle))
      return std::unexpected(Error::OutOfRange);
   return View(json_object_array_get_idx(handle, index));
}

bool View::operator==(const View &other) const noexcept
{
   if (*this == nullptr || other == nullptr)
      return (*this == nullptr) == (other == nullptr);
   return json_object_equal(handle, other.handle) != 0;
}

std::string View::stringify(Format format) const
{
   size_t length = 0;
   const int flags = (format == Format::Pretty ? JSON_C_TO_STRING_PRETTY : JSON_C_TO_STRING_PLAIN) | JSON_C_TO_STRING_NOSLASHESCAPE;
   const char *const text = json_object_to_json_string_length(handle, flags, &length);
   if (text == nullptr)
      throw std::bad_alloc();
   return std::string(text, length);
}

Value::Value(const View &other)
{
   if (other == nullptr)
      return;

   if (json_object_deep_copy(other.handle, &handle, nullptr) != 0)
      throw std::bad_alloc();
}

Value::~Value()
{
   json_object_put(handle);
}

Value::Value(Value &&other) noexcept : View(std::exchange(other.handle, nullptr)) {}

Value &Value::operator=(Value &&other) noexcept
{
   if (this != &other)
   {
      json_object_put(handle);
      handle = std::exchange(other.handle, nullptr);
   }
   return *this;
}

Value Value::object()
{
   return Value(nonNull(json_object_new_object()), Adopt{});
}

Value Value::array()
{
   return Value(nonNull(json_object_new_array()), Adopt{});
}

Value Value::boolean(bool value)
{
   return Value(nonNull(json_object_new_boolean(static_cast<json_bool>(value))), Adopt{});
}

Value Value::integer(std::int64_t value)
{
   return Value(nonNull(json_object_new_int64(value)), Adopt{});
}

Value Value::unsignedInteger(std::uint64_t value)
{
   return Value(nonNull(json_object_new_uint64(value)), Adopt{});
}

std::expected<Value, Error> Value::real(double value)
{
   if (not std::isfinite(value))
      return std::unexpected(Error::InvalidArgument);
   return Value(nonNull(json_object_new_double(value)), Adopt{});
}

std::expected<Value, Error> Value::string(std::string_view value)
{
   if (value.contains('\0'))
      return std::unexpected(Error::InvalidArgument);
   if (not std::in_range<int>(value.size()))
      return std::unexpected(Error::OutOfRange);
   return Value(nonNull(json_object_new_string_len(value.empty() ? "" : value.data(), static_cast<int>(value.size()))), Adopt{});
}

std::expected<Value, ParseError> Value::parse(std::string_view input)
{
   if (not std::in_range<int>(input.size())) // We cast down to int below
      return std::unexpected(ParseError{.code = ParseErrorCode::InputTooLarge, .offset = 0, .message = "JSON input is too large"});
   if (input.empty())
      return std::unexpected(ParseError{.code = ParseErrorCode::UnexpectedEnd, .offset = 0, .message = "JSON input is empty"});
   if (auto res = validateJsonSyntax(input); not res)
      return std::unexpected(std::move(res.error()));

   const std::unique_ptr<json_tokener, decltype(&json_tokener_free)> tokener(json_tokener_new_ex(JSON_TOKENER_DEFAULT_DEPTH), &json_tokener_free);
   if (not tokener)
      throw std::bad_alloc();
   json_tokener_set_flags(tokener.get(), JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);

   // Directly adopt the parser result so we do not need to call put manually on errors
   Value value{json_tokener_parse_ex(tokener.get(), input.data(), static_cast<int>(input.size())), Adopt{}};
   auto parseError = json_tokener_get_error(tokener.get());
   auto consumed = std::min(json_tokener_get_parse_end(tokener.get()), input.size());

   // json-c needs a final NUL to finish top-level numbers.
   if (parseError == json_tokener_continue && consumed == input.size())
   {
      const char terminator = '\0';
      value.handle = json_tokener_parse_ex(tokener.get(), &terminator, 1);
      parseError = json_tokener_get_error(tokener.get());
   }

   if (parseError != json_tokener_success)
   {
      ParseErrorCode code = ParseErrorCode::InvalidSyntax;
      if (parseError == json_tokener_continue || parseError == json_tokener_error_parse_eof)
	 code = ParseErrorCode::UnexpectedEnd;
      else if (parseError == json_tokener_error_depth)
	 code = ParseErrorCode::NestingLimitExceeded;
      else if (parseError == json_tokener_error_size)
	 code = ParseErrorCode::InputTooLarge;
      else if (parseError == json_tokener_error_memory)
	 throw std::bad_alloc();
      return std::unexpected(ParseError{.code = code, .offset = consumed, .message = json_tokener_error_desc(parseError)});
   }
   if (consumed != input.size())
      return std::unexpected(ParseError{.code = ParseErrorCode::InvalidSyntax, .offset = consumed, .message = "Trailing characters after the JSON value"});
   return value;
}

[[nodiscard]] std::expected<void, Error> Value::set(const char *key, Value value)
{
   if (key == nullptr)
      return std::unexpected(Error::InvalidArgument);
   if (type() != Type::Object)
      return std::unexpected(Error::TypeMismatch);
   if (json_object_object_add(handle, key, value.handle) != 0)
      throw std::bad_alloc();
   value.handle = nullptr;
   return {};
}

[[nodiscard]] std::expected<void, Error> Value::append(Value value)
{
   if (type() != Type::Array)
      return std::unexpected(Error::TypeMismatch);
   if (json_object_array_add(handle, value.handle) != 0)
      throw std::bad_alloc();
   value.handle = nullptr;
   return {};
}
} // namespace APT::JSON
