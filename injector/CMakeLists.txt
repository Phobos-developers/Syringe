cmake_minimum_required (VERSION 3.8)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

message("project: injector (main)")
message("COMPILIER IS `${CMAKE_CXX_COMPILER_ID}`")
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
	add_compile_options(/bigobj)
	add_link_options(/FORCE:MULTIPLE)
	add_link_options(/SUBSYSTEM:WINDOWS)
	#add_link_options(/ENTRY:mainCRTStartup)
#elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
#	#if(WIN32)
#	#	add_compile_options(-march=x86-64)
#	#endif()
#	#add_compile_options(-m64)					# 
#	#add_compile_options(-g)						# debug info, system specific
#	add_compile_options(-Og)						# optimization: debug
#	add_compile_options(-std=c++17)			# C++ standard
#	add_compile_options(-fpermissive)			# required for some pieces of code
#	add_compile_options(-Wchanges-meaning)
#	#add_compile_options(-Wa,-mbig-obj)	# File with no section limit (fix assembler: file too big)
#else()
endif()

file(GLOB_RECURSE src
	"*.cpp"
)

include_directories("${CMAKE_SOURCE_DIR}/utilities")
include_directories("${CMAKE_SOURCE_DIR}/debugger")
include_directories("${CMAKE_SOURCE_DIR}/include")

add_library (injector_lib ${src})

find_package(fmt CONFIG REQUIRED)
target_link_libraries(injector_lib PUBLIC fmt::fmt-header-only)

find_package(spdlog CONFIG REQUIRED)
target_link_libraries(injector_lib PUBLIC spdlog::spdlog spdlog::spdlog_header_only)

target_link_libraries(injector_lib PUBLIC Version)

message("project: injector - done")