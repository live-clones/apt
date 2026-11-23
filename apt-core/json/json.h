/*
 * json.h - JSON values and non-owning views
 *
 * SPDX-License-Identifier: GPL-2.0+
 */
#ifndef APT_JSON_H
#define APT_JSON_H

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
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

/// \brief Instantiate to provide decoding for custom classes
template <typename T>
struct Decode;
template <typename T>
concept Decodable = requires(View v) {
   { Decode<T>{}(v) } -> std::same_as<std::expected<T, Error>>;
};

/// \brief Instantiate to provide encoding for custom classes
template <typename T>
struct Encode;
template <typename R>
concept EncodeResult = std::same_as<R, Value> || std::same_as<R, std::expected<Value, Error>>;
template <typename T>
concept Encodable = not std::derived_from<std::remove_cvref_t<T>, View> && requires(const T &val) {
   { Encode<std::remove_cvref_t<T>>{}(val) } -> EncodeResult;
};

/// \brief Instantiate to provide member reflection for custom classes
/// Note: A null value is treated like an absent field when parsing and writing.
template <typename T>
struct Reflect;
template <typename T>
concept Reflectable = requires(T &val, const T &cval) {
   Reflect<std::remove_cvref_t<T>>{}(val);
   Reflect<std::remove_cvref_t<T>>{}(cval);
};

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

   template <Decodable T>
   std::expected<T, Error> get() const noexcept(noexcept(Decode<T>{}(*this)))
   {
      return Decode<T>{}(*this);
   }

   template <Decodable T>
   std::expected<T, Error> get(const char *key, MissingKeyPolicy missingKeyPolicy = MissingKeyPolicy::Error) const
      noexcept(noexcept(Decode<T>{}(*this)))
   {
      return find(key, missingKeyPolicy).and_then(Decode<T>{});
   }

   template <Decodable T>
   [[nodiscard]] std::expected<void, Error> into(T &out) const noexcept(noexcept(get<T>()) && std::is_nothrow_move_assignable_v<T>)
   {
      return get<T>().transform([&out](auto &&val) noexcept(std::is_nothrow_move_assignable_v<T>) { out = std::move(val); });
   }

   template <Decodable T>
   [[nodiscard]] std::expected<void, Error> into(const char *key, T &out, MissingKeyPolicy missingKeyPolicy = MissingKeyPolicy::Error) const
      noexcept(noexcept(into(out)))
   {
      return find(key, missingKeyPolicy).and_then([&out](View v) noexcept(noexcept(v.into(out))) { return v.into(out); });
   }
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

   static std::expected<Value, Error> encode(const Encodable auto &val) { return Encode<std::remove_cvref_t<decltype(val)>>{}(val); }
   [[nodiscard]] std::expected<void, Error> set(const char *key, const Encodable auto &val)
   {
      return encode(val).and_then([&](auto v) { return set(key, std::move(v)); });
   }
   [[nodiscard]] std::expected<void, Error> append(const Encodable auto &val)
   {
      return encode(val).and_then([&](auto v) { return append(std::move(v)); });
   }
};

// clang-format off
template <> struct Decode<bool> { static auto operator()(View v) noexcept { return v.asBoolean(); } };
template <> struct Decode<double> { static auto operator()(View v) noexcept { return v.asDouble(); } };
template <> struct Decode<std::string_view> { static auto operator()(View v) noexcept { return v.asString(); } };
template <> struct Decode<std::string>
{
   static auto operator()(View v) { return v.asString().transform([](auto sv) { return std::string(sv); }); }
};
// clang-format on
template <Decodable T>
struct Decode<std::optional<T>>
{
   static std::expected<std::optional<T>, Error> operator()(View v) noexcept(noexcept(std::expected<std::optional<T>, Error>(v.get<T>())))
   {
      if (v == nullptr)
	 return std::nullopt;
      return v.get<T>();
   }
};
template <std::integral T>
requires(not std::same_as<T, bool>)
struct Decode<T>
{
   static auto operator()(View v) noexcept
   {
      auto narrow = [](auto value) noexcept -> std::expected<T, Error> {
	 if (not std::in_range<T>(value))
	    return std::unexpected(Error::OutOfRange);
	 return static_cast<T>(value);
      };
      if constexpr (std::is_signed_v<T>)
	 return v.asInt64().and_then(narrow);
      else
	 return v.asUInt64().and_then(narrow);
   }
};
template <typename Container>
requires(Decodable<typename Container::value_type> &&
	 not Reflectable<Container> &&
	 std::is_default_constructible_v<Container> &&
	 not std::convertible_to<Container, std::string_view> &&
	 requires(Container &c, typename Container::value_type &&val) {
	    c.insert(c.end(), std::move(val));
	 })
struct Decode<Container>
{
   static std::expected<Container, Error> operator()(View v)
   {
      if (v.type() != Type::Array)
	 return std::unexpected(Error::TypeMismatch);
      return v.size().and_then([&](std::size_t size) -> std::expected<Container, Error> {
	 Container out;
	 if constexpr (requires { out.reserve(size); })
	    out.reserve(size);
	 for (size_t i = 0; i < size; i++)
	 {
	    auto item = v.at(i).and_then(Decode<typename Container::value_type>{});
	    if (not item)
	       return std::unexpected(item.error());
	    out.insert(out.end(), std::move(*item));
	 }
	 return out;
      });
   }
};
// clang-format off
template <> struct Encode<bool> { static auto operator()(bool val) { return Value::boolean(val); } };
template <> struct Encode<double> { static auto operator()(double val) { return Value::real(val); } };
// clang-format on
template <Encodable T>
struct Encode<std::optional<T>>
{
   static auto operator()(const std::optional<T> &val) { return val.has_value() ? Value::encode(*val) : Value{}; }
};
template <typename T>
requires(std::convertible_to<T, std::string_view> && not std::same_as<std::remove_cvref_t<T>, std::nullptr_t>)
struct Encode<T>
{
   static std::expected<Value, Error> operator()(const auto &val)
   {
      // std::remove_cvref_t to not treat char[N] array as pointer and trigger nonnull warning
      if constexpr (std::is_pointer_v<std::remove_cvref_t<decltype(val)>>)
	 if (val == nullptr)
	    return std::unexpected(Error::InvalidArgument);
      return Value::string(val);
   }
};
template <std::integral T> requires(not std::same_as<T, bool>)
struct Encode<T>
{
   static Value operator()(T val)
   {
      if constexpr (std::is_signed_v<T>)
	 return Value::integer(val);
      else
	 return Value::unsignedInteger(val);
   }
};
template <typename R>
requires(std::ranges::input_range<const R> &&
	 Encodable<std::ranges::range_reference_t<const R>> &&
	 not std::convertible_to<R, std::string_view> &&
	 not Reflectable<R>)
struct Encode<R>
{
   static std::expected<Value, Error> operator()(const R &range)
   {
      auto arr = Value::array();
      for (const auto &elem : range)
	 if (auto res = arr.append(elem); not res)
	    return std::unexpected(res.error());
      return arr;
   }
};

template <Reflectable T>
struct Encode<T>
{
   static std::expected<Value, Error> operator()(const T &val)
   {
      auto obj = Value::object();
      std::expected<void, Error> status{};
      std::apply(
	 [&](const auto &...fields) noexcept(sizeof...(fields) == 0) {
	    if constexpr (sizeof...(fields) > 0)
	    {
	       auto setMember = [&](const auto &key, const auto &field) -> std::expected<void, Error> {
		  if constexpr (requires { field.has_value(); })
		  {
		     if (not field.has_value())
			return {};
		  }
		  return obj.set(key, field);
	       };
	       (void)((status = setMember(fields.first, fields.second.get())).has_value() && ...);
	    }
	 },
	 Reflect<T>{}(val));
      if (not status)
	 return std::unexpected(status.error());
      return obj;
   }
};

template <Reflectable T>
requires std::is_default_constructible_v<T>
struct Decode<T>
{
   static std::expected<T, Error> operator()(View v)
   {
      if (v.type() != Type::Object)
	 return std::unexpected(Error::TypeMismatch);

      T result;
      std::expected<void, Error> status{};
      std::apply(
	 [&](auto &&...fields) noexcept(sizeof...(fields) == 0) {
	    if constexpr (sizeof...(fields) > 0)
	    {
	       auto getMember = [&](const auto &key, auto &field) -> std::expected<void, Error> {
		  return v.into(key, field, MissingKeyPolicy::Null);
	       };
	       (void)((status = getMember(fields.first, fields.second.get())).has_value() && ...);
	    }
	 },
	 Reflect<T>{}(result));

      if (not status)
	 return std::unexpected(status.error());
      return result;
   }
};
} // namespace JSON
} // namespace Internal
} // namespace APT

#endif
