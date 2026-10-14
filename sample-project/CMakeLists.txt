cmake_minimum_required(VERSION 3.16)
project(notes VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(notes
    src/main.cpp
    src/commands.cpp
    src/notebook.cpp
)
target_compile_options(notes PRIVATE -Wall -Wextra)
