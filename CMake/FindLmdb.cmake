# - Try to find LMDB
# Once done this will define
#
#  LMDB_FOUND - system has Lightning Memory DB
#  LMDB_INCLUDE_DIRS - the LMDB include directory
#  LMDB_LIBRARIES - Link these to use LMDB

find_package(PkgConfig)

pkg_check_modules(LMDB_PKGCONF lmdb)

find_path(LMDB_INCLUDE_DIRS
  NAMES lmdb.h
  PATHS ${LMDB_PKGCONF_INCLUDE_DIRS}
)

find_library(LMDB_LIBRARIES NAMES lmdb)

# mark_as_advanced(LMDB_INCLUDE_DIRS LMDB_LIBRARIES)
