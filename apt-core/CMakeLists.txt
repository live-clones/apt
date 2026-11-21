set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

# make headers available
file(CREATE_LINK
   "${CMAKE_CURRENT_SOURCE_DIR}"
   "${PROJECT_BINARY_DIR}/include/apt-core"
   SYMBOLIC
)

# JSON library
add_library(apt-core-json STATIC json/json.cc)
target_link_libraries(apt-core-json PRIVATE json-c::json-c)

# An interface bundling all the core libraries
add_library(apt-core INTERFACE)
target_link_libraries(apt-core INTERFACE apt-core-json)
