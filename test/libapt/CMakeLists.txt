if (WITH_TESTS)
   set(PROJECT_TEST_LIBRARIES apt-pkg-object apt-private-object)

   include(FetchContent)

   set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
   set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)

   find_path(GTEST_SRCPATH CMakeLists.txt
      /usr/src/googletest
      /usr/src/googletest/googletest
      /usr/src/gtest
   )

   FetchContent_Declare(googletest
      SOURCE_DIR "${GTEST_SRCPATH}"
      FIND_PACKAGE_ARGS CONFIG
   )
   FetchContent_MakeAvailable(googletest)

   # Hegel needs those, add them before adding it so it picks them up
   add_optional_compile_options(Wno-noexcept)
   add_optional_compile_options(Wno-missing-field-initializers)

   # Hegel (https://hegel.dev) downloads a prebuilt libhegel at configure
   # time; disable with -DWITH_HEGEL_TESTS=OFF (as done in debian/rules).
   if (WITH_HEGEL_TESTS)
      include(FetchContent)
      # We do not use the reflect-cpp powered default_generator; disabling
      # it avoids fetching reflect-cpp.
      set(HEGEL_REFLECTION OFF CACHE BOOL "" FORCE)
      FetchContent_Declare(
         hegel
         GIT_REPOSITORY https://github.com/hegeldev/hegel.git
         GIT_TAG frontends/cpp/0.18.2
         SOURCE_SUBDIR frontends/cpp
      )
      FetchContent_MakeAvailable(hegel)
   endif()

   # gtest produces some warnings with the set of warnings we activate,
   # so disable the offending warnings while compiling tests for now
   add_optional_compile_options(Wno-undef)
   add_optional_compile_options(Wno-ctor-dtor-privacy)
   # Do not force override for gtest, gtest is missing override specifiers
   add_optional_compile_options(Wno-suggest-override)
   add_optional_compile_options(Wno-unused-parameter)

   # Definition of the C++ files used to build the test binary - note that this
   # is expanded at CMake time, so you have to rerun cmake if you add or remove
   # a file (you can just run cmake . in the build directory)
   file(GLOB files gtest_runner.cc *-helpers.cc *_test.cc)
   # Hegel tests are compiled only when enabled
   if (WITH_HEGEL_TESTS)
      file(GLOB hegel_files *_test_hegel.cc)
      list(APPEND files ${hegel_files})
   endif()
   add_executable(lib${PROJECT_NAME}_test ${files})
   target_include_directories(lib${PROJECT_NAME}_test PRIVATE ${GTEST_INCLUDE_DIRS})
   target_link_libraries(lib${PROJECT_NAME}_test GTest::gtest_main ${CMAKE_THREAD_LIBS_INIT} ${PROJECT_TEST_LIBRARIES} OpenSSL::Crypto ${CMAKE_DL_LIBS})
   target_compile_definitions(libapt_test PRIVATE
       CMAKE_CURRENT_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/"
   )
   if (WITH_HEGEL_TESTS)
      target_link_libraries(lib${PROJECT_NAME}_test hegel)
   endif()
   include(GoogleTest)
   gtest_discover_tests(lib${PROJECT_NAME}_test)
   set(CMAKE_CTEST_ARGUMENTS "-j" "--output-on-failure")
endif()
