cmake_minimum_required(VERSION 3.16)

project(DayZLinuxFix LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(DayZLinuxFix
	src/main.cpp
	src/utils/utils.cpp
	src/targets/windows.cpp
	src/targets/linux.cpp
)

target_include_directories(DayZLinuxFix PRIVATE src)

if(MSVC)
	target_precompile_headers(DayZLinuxFix PRIVATE src/pch.h)
endif()