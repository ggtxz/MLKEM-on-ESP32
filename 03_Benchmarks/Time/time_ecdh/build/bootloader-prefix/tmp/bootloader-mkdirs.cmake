# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/ggtxz/esp/esp-idf/components/bootloader/subproject"
  "/home/ggtxz/TCC/04_Sandbox/time_ecdh/build/bootloader"
  "/home/ggtxz/TCC/04_Sandbox/time_ecdh/build/bootloader-prefix"
  "/home/ggtxz/TCC/04_Sandbox/time_ecdh/build/bootloader-prefix/tmp"
  "/home/ggtxz/TCC/04_Sandbox/time_ecdh/build/bootloader-prefix/src/bootloader-stamp"
  "/home/ggtxz/TCC/04_Sandbox/time_ecdh/build/bootloader-prefix/src"
  "/home/ggtxz/TCC/04_Sandbox/time_ecdh/build/bootloader-prefix/src/bootloader-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/ggtxz/TCC/04_Sandbox/time_ecdh/build/bootloader-prefix/src/bootloader-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/ggtxz/TCC/04_Sandbox/time_ecdh/build/bootloader-prefix/src/bootloader-stamp${cfgdir}") # cfgdir has leading slash
endif()
