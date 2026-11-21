/*
 * json.h - JSON values and non-owning views
 *
 * SPDX-License-Identifier: GPL-2.0+
 */
#ifndef APT_JSON_H
#define APT_JSON_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <utility>

struct json_object;

namespace APT
{
inline namespace Internal
{
namespace JSON
{
using Handle = json_object;

enum class Type
{
   Null,
   Boolean,
   Integer,
   Real,
   String,
   Array,
   Object,
};

enum class Error
{
   TypeMismatch,
   MissingKey,
   OutOfRange,
   InvalidArgument,
};

enum class ParseErrorCode
{
   InvalidSyntax,
   UnexpectedEnd,
   NestingLimitExceeded,
   InputTooLarge,
   EmbeddedNul,
};

struct ParseError
{
   ParseErrorCode code;
   std::size_t offset;
   std::string message;
};

enum class Format
{
   Compact,
   Pretty,
};

enum class MissingKeyPolicy
{
   Error,
   Null,
};

class View;
class Value;

/** \brief A non-owning view of a JSON value.
 *
 * A view must not outlive its owning Value. Mutating or destroying the owning
 * value invalidates all views into it. The default view represents JSON null.
 */
class View
{
   friend class Value;
   Handle *handle = nullptr;

   explicit View(Handle *handle) noexcept : handle(handle) {}

   public:
   std::expected<bool, Error> asBoolean() const noexcept;
   std::expected<std::int64_t, Error> asInt64() const noexcept;
   std::expected<std::uint64_t, Error> asUInt64() const noexcept;
   std::expected<double, Error> asDouble() const noexcept;
   std::expected<std::string_view, Error> asString() const noexcept;

   View() noexcept = default;

   Type type() const noexcept;
   bool operator==(std::nullptr_t) const noexcept { return type() == Type::Null; }

   /// \brief Return the number of members in an object or elements in an array.
   std::expected<std::size_t, Error> size() const noexcept;
   /// \brief Find a NUL-terminated member key; a null key is reported as InvalidArgument.
   std::expected<View, Error> find(const char *key, MissingKeyPolicy missingKeyPolicy = MissingKeyPolicy::Error) const noexcept;
   std::expected<View, Error> at(std::size_t index) const noexcept;

   bool operator==(const View &other) const noexcept;
   std::string stringify(Format format = Format::Compact) const;
};

/** \brief An owning, move-only JSON value.
 *
 * Strings and object keys cannot contain embedded NUL characters. Non-finite
 * real numbers are rejected on construction and numeric access.
 */
class Value final : public View
{
   struct Adopt
   {
   };
   Value(Handle *handle, Adopt) noexcept : View(handle) {}

   public:
   /// \brief Construct a JSON null value.
   Value() noexcept = default;
   explicit Value(const View &other);

   ~Value();
   Value(Value &&other) noexcept;
   Value &operator=(Value &&other) noexcept;
   Value(const Value &) = delete;
   Value &operator=(const Value &) = delete;

   static Value object();
   static Value array();
   static Value boolean(bool value);
   static Value integer(std::int64_t value);
   static Value unsignedInteger(std::uint64_t value);
   static std::expected<Value, Error> real(double value);
   static std::expected<Value, Error> string(std::string_view value);

   static std::expected<Value, ParseError> parse(std::string_view input);

   /// \brief Replace or add a non-null NUL-terminated object member key, transferring ownership of value.
   [[nodiscard]] std::expected<void, Error> set(const char *key, Value value);
   /// \brief Append to an array, transferring ownership of value.
   [[nodiscard]] std::expected<void, Error> append(Value value);
};

} // namespace JSON
} // namespace Internal
} // namespace APT

#endif
