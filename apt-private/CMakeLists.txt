# Set the version of the library
set(MAJOR 0.0)
set(MINOR 0)

# Definition of the C++ files used to build the library - note that this
# is expanded at CMake time, so you have to rerun cmake if you add or remove
# a file (you can just run cmake . in the build directory)
file(GLOB_RECURSE library "*.cc")
file(GLOB_RECURSE headers "*.h")

# Create an object library using the C++ files, so they can be reused
# directly, e.g. by the unit tests. Note that this deliberately has no
# dependency on apt-pkg-object: the shared library resolves apt-pkg
# symbols from libapt-pkg, not from a second, built-in copy.
add_library(apt-private-object OBJECT ${library})
set_target_properties(apt-private-object PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_target_properties(apt-private-object PROPERTIES CXX_VISIBILITY_PRESET hidden)

# Create the shared library from the object library and set the SONAME
add_library(apt-private SHARED)
target_link_libraries(apt-private PRIVATE apt-private-object)
target_link_libraries(apt-private PUBLIC apt-pkg)
set_target_properties(apt-private PROPERTIES VERSION ${MAJOR}.${MINOR})
set_target_properties(apt-private PROPERTIES SOVERSION ${MAJOR})
add_version_script(apt-private)

# Install the library and the headers
install(TARGETS apt-private
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        NAMELINK_SKIP)

flatify(${PROJECT_BINARY_DIR}/include/apt-private/ "${headers}")
