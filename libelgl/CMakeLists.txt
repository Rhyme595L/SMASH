# libelgl/CMakeLists.txt
file(GLOB_RECURSE LIBELGL_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/elgl/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/elgloffline/*.cpp"
)

add_library(libelgl STATIC ${LIBELGL_SRC})

target_include_directories(libelgl PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/elgl
    ${CMAKE_CURRENT_SOURCE_DIR}/elgloffline
)

target_link_libraries(libelgl PUBLIC mcl)
