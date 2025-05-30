# - Try to find Tkrzw
# Once done, this will define
#
#  TKRZW_FOUND - system has Tkrzw
#  TKRZW_INCLUDE_DIRS - the Tkrzw include directories
#  TKRZW_LIBRARIES - the Tkrzw library
find_package(PkgConfig)

pkg_check_modules(TKRZW_PKGCONF tkrzw)

find_path(TKRZW_INCLUDE_DIRS
  NAMES tkrzw_dbm.h tkrzw_dbm_hash.h
  PATHS ${TKRZW_PKGCONF_INCLUDE_DIRS}
)


find_library(TKRZW_LIBRARIES
  NAMES tkrzw
  PATHS ${TKRZW_PKGCONF_LIBRARY_DIRS}
)

mark_as_advanced(TKRZW_INCLUDE_DIRS TKRZW_LIBRARIES)
