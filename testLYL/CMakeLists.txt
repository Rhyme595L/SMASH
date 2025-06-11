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

add_test_case_with_run(gen_File)
add_test_case_with_run(gen_table2)
# add_test_case_with_run(lvt_load)
add_test_case_with_run(lvt)
add_test_case_with_run(lvt_batch)
# add_test_case_with_run(lvt_61)
# add_test_case_with_run(lvt2)
# add_test_case_with_run(mascot)
# add_test_case_with_run(spdz2k)
# add_test_case_with_run(tiny)
add_test_case_with_run(L2A_mascot)
add_test_case_with_run(A2L_mascot)
add_test_case_with_run(L2A_spdz2k)
add_test_case_with_run(A2L_spdz2k)

add_test_case_with_run(B2A_mascot)
add_test_case_with_run(B2A_spdz2k)
add_test_case_with_run(A2B_mascot)
add_test_case_with_run(A2B_spdz2k)
# add_test_case_with_run(BSGS)
# add_test_case_with_run(P2M)

# add_test_case_with_run(B2L)
# add_test_case_with_run(L2B)

# add_executable(lvt_service lvt_service.cpp)
# target_link_libraries(lvt_service mcl libelgl)
# target_include_directories(lvt_service PRIVATE
#     ${CMAKE_CURRENT_SOURCE_DIR}
#     ${CMAKE_CURRENT_SOURCE_DIR}/..
#     ${CMAKE_CURRENT_SOURCE_DIR}/../emp-aby
#     ${CMAKE_CURRENT_SOURCE_DIR}/../testLLM
# )