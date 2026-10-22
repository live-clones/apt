/*
 * private-json-writer.h - Simple JSON writer for the JSON hooks
 *
 * Copyright (c) 2018 Canonical Ltd
 *
 * SPDX-License-Identifier: GPL-2.0+
 */
#ifndef APT_PRIVATE_JSON_WRITER_H
#define APT_PRIVATE_JSON_WRITER_H

#include <apt-pkg/macros.h>
#include <apt-pkg/strutl.h>

#include <locale>
#include <ostream>
#include <stack>
#include <string>

/**
 * @brief Simple JSON writer
 *
 * This performs no error checking, so be careful.
 */
class APT_HIDDEN JsonWriter
{
   std::ostream &os;
   std::locale old_locale;

   enum write_state
   {
      empty,
      in_array_first_element,
      in_array,
      in_object_first_key,
      in_object_key,
      in_object_val
   } state = empty;

   std::stack<write_state> old_states;

   void maybeComma()
   {
      switch (state)
      {
      case empty:
	 break;
      case in_object_val:
	 state = in_object_key;
	 break;
      case in_object_key:
	 state = in_object_val;
	 os << ',';
	 break;
      case in_array:
	 os << ',';
	 break;
      case in_array_first_element:
	 state = in_array;
	 break;
      case in_object_first_key:
	 state = in_object_val;
	 break;
      default:
	 abort();
      }
   }

   void pushState(write_state state)
   {
      old_states.push(this->state);
      this->state = state;
   }

   void popState()
   {
      this->state = old_states.top();
      old_states.pop();
   }

   public:
   explicit JsonWriter(std::ostream &os) : os(os), old_locale{os.imbue(std::locale::classic())} {}
   ~JsonWriter() { os.imbue(old_locale); }
   JsonWriter &beginArray()
   {
      maybeComma();
      pushState(in_array_first_element);
      os << '[';
      return *this;
   }
   JsonWriter &endArray()
   {
      popState();
      os << ']';
      return *this;
   }
   JsonWriter &beginObject()
   {
      maybeComma();
      pushState(in_object_first_key);
      os << '{';
      return *this;
   }
   JsonWriter &endObject()
   {
      popState();
      os << '}';
      return *this;
   }
   std::ostream &encodeString(std::ostream &out, std::string const &str)
   {
      out << '"';

      for (std::string::const_iterator c = str.begin(); c != str.end(); c++)
      {
	 if (*c <= 0x1F || *c == '"' || *c == '\\')
	    ioprintf(out, "\\u%04X", *c);
	 else
	    out << *c;
      }

      out << '"';
      return out;
   }
   JsonWriter &name(std::string const &name)
   {
      maybeComma();
      encodeString(os, name) << ':';
      return *this;
   }
   JsonWriter &value(std::string const &value)
   {
      maybeComma();
      encodeString(os, value);
      return *this;
   }
   JsonWriter &value(const char *value)
   {
      maybeComma();
      if (value == nullptr)
	 os << "null";
      else
	 encodeString(os, value);
      return *this;
   }
   JsonWriter &value(int value)
   {
      maybeComma();
      os << value;
      return *this;
   }
   JsonWriter &value(long value)
   {
      maybeComma();
      os << value;
      return *this;
   }
   JsonWriter &value(long long value)
   {
      maybeComma();
      os << value;
      return *this;
   }
   JsonWriter &value(unsigned long long value)
   {
      maybeComma();
      os << value;
      return *this;
   }
   JsonWriter &value(unsigned long value)
   {
      maybeComma();
      os << value;
      return *this;
   }
   JsonWriter &value(unsigned int value)
   {
      maybeComma();
      os << value;
      return *this;
   }
   JsonWriter &value(bool value)
   {
      maybeComma();
      os << (value ? "true" : "false");
      return *this;
   }
   JsonWriter &value(double value)
   {
      maybeComma();
      os << value;
      return *this;
   }
};

#endif
