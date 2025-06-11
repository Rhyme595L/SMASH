# testLYL/CMakeLists.txt

macro (add_test_executable_with_lib _name libs)
    add_executable(test_${_name} "${_name}.cpp")
    target_link_libraries(test_${_name} ${EMP-OT_LIBRARIES} mcl libelgl ${libs})
endmacro()

macro (add_test_case _name)
    add_test_executable_with_lib(${_name} "")
    add_test(NAME ${_name} COMMAND "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test_${_name}" WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/")
endmacro()

macro (add_test_case_with_runarg _name _arg)
    add_test_executable_with_lib(${_name} "")
    add_test(NAME ${_name} COMMAND "./run" "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test_${_name}" "${_arg}" WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/")
endmacro()

macro (add_test_case_with_run _name)
    add_test_case_with_runarg(${_name} "")
endmacro()

# add_test_case_with_run(secret_tensor)
add_test_case_with_run(FixedPointConverter)
# add_test_case_with_run(genTable)
# add_test_case_with_run(515test)
# add_test_case_with_run(517test)