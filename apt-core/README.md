# APT core libraries
The APT core libraries are C++23 libraries that implement fundamental
abstractions.

They are built as position-independent static libraries rather than
a shared library as they do NOT provide any ABI or API stability,
and are used in security-critical paths where we want to minimize
the code being linked in.

They have hidden symbol visibility and cannot be used across
DSOs.

# Threat model and design
These libraries process input in various formats and need to be
resilient against malformed inputs.

To that effect they are designed with safety from the ground up:

- **Ownership**: We prefer move-only types. For example, JSON::Value
  represents a reference to the object, and acts essentially like a
  move-only pointer.

- **Explicit errors**: Failures are returned via explicit error types
  such as std::expected, not exceptions or error stacks (like apt-pkg).
  The only exception being out of memory conditions which are thrown.

  As a convention, any std::expected<void, ...> must always be
  annotated [[nodiscard]] to ensure that the error is being handled.

- **Minimal libraries**: You can use individual core libraries such
  as JSON, without pulling in other libraries such as I/O or Varlink.
