apt history
===========

SYNOPSIS
--------

**apt history**-{list | info | undo | redo | rollback}

DESCRIPTION
-----------

:program:`apt history` performs a variety of operations on APT's history log.
The history log is a record of all package management operations performed
using APT. :program:`apt history` is strictly additive: it never modifies or
deletes existing entries in the history log.

The related commands are called by appending one of the following subcommands
as:

|

        :program:`apt` **history**-`<command>`

COMMANDS
~~~~~~~~

:program:`list`

   List the history log in a human-readable format. Each entry is assigned
   an ID, which can be used to refer to the entry in other :program:`apt
   history` commands.

:program:`info` [`<ids>`...]

    Display detailed information about specific history log entries
    specified by their IDs. This includes:

    - Transaction ID
    - Start and end time
    - Requestor
    - Command line arguments
    - Packages changed in alphabetical order, the operations performed on
      them, and how the versions changed

    Multiple IDs may be specified as a space-separated list.

:program:`undo` [`<ids>`...]

    Undo the operations performed in the specified history log entries.
    This will attempt to reverse the changes made by the original
    operations, which is particularly useful for removing temporary build
    dependencies installed by :program:`apt build-dep`. The undo operation
    will introduce one new entry in the history log.

    If the system has changed significantly since the original operations
    were performed, or if the operations involved complex changes to the
    system or APT sources, it may not always be possible to fully undo the
    changes. In such cases, the undo operation will attempt to reverse
    as much of the changes as possible, but may not be able to completely
    restore the system to its previous state.

    Multiple IDs may be specified as a space-separated list. If multiple IDs
    are specified, the undo operations will be performed in the order
    specified.

:program:`redo` [`<ids>`...]

    Redo the operations performed in the specified history log entries.
    This will attempt to reapply the changes made by the original operations.
    As with undo, success depends on the current system state and configured
    APT sources. A new entry is added to the history log.

    Multiple IDs may be specified as a space-separated list. If multiple IDs
    are specified, the redo operations will be performed in the order
    specified.

:program:`rollback` `<steps>`

    Undo the specified number of most recent entries in reverse chronological
    order. This will attempt to reverse the changes made by the original
    operations. As with undo, success depends on the current system state and
    configured APT sources. A new entry is added to the history log.

OPTIONS
-------

:program:`apt history` has no options of its own, but accepts the global
options of :manpage:`apt(8)`.

PACKAGE CHANGES
---------------

There are several types of package changes that can be recorded in
the history log, including:

- **Install** (**I**): A package was installed on the system.
- **Reinstall** (**rI**): A package was reinstalled on the system.
- **Upgrade** (**U**): A package was upgraded to a newer version.
- **Downgrade** (**D**): A package was downgraded to an older version.
- **Remove** (**R**): A package was removed from the system.
- **Purge** (**P**): A package was removed from the system along with its
  configuration files.

The version changes for each package are recorded alongside the operation type.

Explicitly installed/removed packages show the version change as:

|

    (``<version>``)

Automatically installed/removed packages (such as dependencies) show the
version change as:

|

    (``<version>``, automatic)

Explicitly upgraded/downgraded packages show the version change as:

|

    (``<previous-version>`` -> ``<current-version>``)

Automatically upgraded/downgraded packages show the version change as:

|

    (``<previous-version>`` -> ``<current-version>``, automatic)

AUTHORS
-------

**Simon Johnsson**

**APT Team**
