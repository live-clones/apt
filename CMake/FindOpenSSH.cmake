find_package(PkgConfig)

pkg_check_modules(SSH_PKGCONF libssh2)

find_path(OPENSSH_INCLUDE_DIRS
  NAMES libssh2.h
  PATHS ${SSH_PKGCONF_INCLUDE_DIRS}
)

find_library(OPENSSH_LIBRARIES
  NAMES ssh2
  PATHS ${SSH_PKGCONF_LIBRARY_DIRS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(OpenSSH DEFAULT_MSG OPENSSH_INCLUDE_DIRS OPENSSH_LIBRARIES)

mark_as_advanced(OPENSSH_INCLUDE_DIRS OPENSSH_LIBRARIES)
