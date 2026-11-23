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
#include <functional>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>

struct json_object;

namespace APT::inline Internal::JSON
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

// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#define APT_FIELD_SELECT(key, ...) key

#define APT_FIELD(member, ...) \
   std::pair { APT_FIELD_SELECT(__VA_ARGS__ __VA_OPT__(, ) #member), std::ref(val.member) }

#define APT_REFLECT(Type, ...)                                              \
   template <>                                                              \
   struct APT::JSON::Reflect<Type>                                          \
   {                                                                        \
      static constexpr auto operator()([[maybe_unused]] auto &val) noexcept \
      {                                                                     \
	 return std::make_tuple(__VA_ARGS__);                               \
      }                                                                     \
   }
// NOLINTEND(cppcoreguidelines-macro-usage)

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
   [[nodiscard]] auto asBoolean() const noexcept -> std::expected<bool, Error>;
   [[nodiscard]] auto asInt64() const noexcept -> std::expected<std::int64_t, Error>;
   [[nodiscard]] auto asUInt64() const noexcept -> std::expected<std::uint64_t, Error>;
   [[nodiscard]] auto asDouble() const noexcept -> std::expected<double, Error>;
   [[nodiscard]] auto asString() const noexcept -> std::expected<std::string_view, Error>;

   View() noexcept = default;

   [[nodiscard]] auto type() const noexcept -> Type;
   auto operator==(std::nullptr_t) const noexcept -> bool { return type() == Type::Null; }

   /// \brief Return the number of members in an object or elements in an array.
   [[nodiscard]] auto size() const noexcept -> std::expected<std::size_t, Error>;
   /// \brief Find a NUL-terminated member key; a null key is reported as InvalidArgument.
   [[nodiscard]] auto find(const char *key, MissingKeyPolicy missingKeyPolicy = MissingKeyPolicy::Error) const noexcept -> std::expected<View, Error>;
   [[nodiscard]] auto at(std::size_t index) const noexcept -> std::expected<View, Error>;

   auto operator==(const View &other) const noexcept -> bool;
   [[nodiscard]] auto stringify(Format format = Format::Compact) const -> std::string;

   template <Decodable T>
   [[nodiscard]] auto get() const noexcept(noexcept(Decode<T>{}(*this))) -> std::expected<T, Error>
   {
      return Decode<T>{}(*this);
   }

   template <Decodable T>
   [[nodiscard]] auto get(const char *key, MissingKeyPolicy missingKeyPolicy = MissingKeyPolicy::Error) const
      noexcept(noexcept(Decode<T>{}(*this))) -> std::expected<T, Error>
   {
      return find(key, missingKeyPolicy).and_then(Decode<T>{});
   }

   template <Decodable T>
   [[nodiscard]] auto into(T &out) const noexcept(noexcept(get<T>()) && std::is_nothrow_move_assignable_v<T>) -> std::expected<void, Error>
   {
      return get<T>().transform([&out](auto &&val) noexcept(std::is_nothrow_move_assignable_v<T>) { out = std::forward<decltype(val)>(val); });
   }

   template <Decodable T>
   [[nodiscard]] auto into(const char *key, T &out, MissingKeyPolicy missingKeyPolicy = MissingKeyPolicy::Error) const
      noexcept(noexcept(into(out))) -> std::expected<void, Error>
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
   auto operator=(Value &&other) noexcept -> Value &;
   Value(const Value &) = delete;
   auto operator=(const Value &) -> Value & = delete;

   static auto object() -> Value;
   static auto array() -> Value;
   static auto boolean(bool value) -> Value;
   static auto integer(std::int64_t value) -> Value;
   static auto unsignedInteger(std::uint64_t value) -> Value;
   static auto real(double value) -> std::expected<Value, Error>;
   static auto string(std::string_view value) -> std::expected<Value, Error>;

   static auto parse(std::string_view input) -> std::expected<Value, ParseError>;

   /// \brief Replace or add a non-null NUL-terminated object member key, transferring ownership of value.
   [[nodiscard]] auto set(const char *key, Value value) -> std::expected<void, Error>;
   /// \brief Append to an array, transferring ownership of value.
   [[nodiscard]] auto append(Value value) -> std::expected<void, Error>;

   static auto encode(const Encodable auto &val) -> std::expected<Value, Error> { return Encode<std::remove_cvref_t<decltype(val)>>{}(val); }
   [[nodiscard]] auto set(const char *key, const Encodable auto &val) -> std::expected<void, Error>
   {
      return encode(val).and_then([&](auto v) { return set(key, std::move(v)); });
   }
   [[nodiscard]] auto append(const Encodable auto &val) -> std::expected<void, Error>
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
   static auto operator()(View v) noexcept(noexcept(std::expected<std::optional<T>, Error>(v.get<T>()))) -> std::expected<std::optional<T>, Error>
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
	 requires(Container &c, Container::value_type &&val) {
	    c.insert(c.end(), std::move(val));
	 })
struct Decode<Container>
{
   static auto operator()(View v) -> std::expected<Container, Error>
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
   static auto operator()(const auto &val) -> std::expected<Value, Error>
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
   static auto operator()(T val) -> Value
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
   static auto operator()(const R &range) -> std::expected<Value, Error>
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
   static auto operator()(const T &val) -> std::expected<Value, Error>
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
   static auto operator()(View v) -> std::expected<T, Error>
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
} // namespace APT::inline Internal::JSON
#endif
