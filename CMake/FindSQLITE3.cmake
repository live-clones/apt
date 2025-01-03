# - Try to find SQLITE3
# Once done, this will define
#
#  SQLITE3_FOUND - system has SQLITE3
#  SQLITE3_INCLUDE_DIRS - the SQLITE3 include directories
#  SQLITE3_LIBRARIES - the SQLITE3 library
find_package(PkgConfig)

pkg_check_modules(SQLITE3_PKGCONF sqlite3)

find_path(SQLITE3_INCLUDE_DIRS
  NAMES sqlite3.h
  PATHS ${SQLITE3_PKGCONF_INCLUDE_DIRS}
)


find_library(SQLITE3_LIBRARIES
  NAMES sqlite3
  PATHS ${SQLITE3_PKGCONF_LIBRARY_DIRS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SQLITE3 DEFAULT_MSG SQLITE3_INCLUDE_DIRS SQLITE3_LIBRARIES)

mark_as_advanced(SQLITE3_INCLUDE_DIRS SQLITE3_LIBRARIES)
