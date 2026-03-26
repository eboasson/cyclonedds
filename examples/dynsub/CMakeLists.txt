# Copyright(c) 2023 ZettaScale Technology and others
#
# This program and the accompanying materials are made available under the
# terms of the Eclipse Public License v. 2.0 which is available at
# http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
# v. 1.0 which is available at
# http://www.eclipse.org/org/documents/edl-v10.php.
#
# SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

cmake_minimum_required(VERSION 3.16)
project(dynsub LANGUAGES C)

if(NOT TARGET CycloneDDS::ddsc)
  find_package(CycloneDDS REQUIRED)
endif()

add_executable(dynsub
  dynsub.c
  type_cache.c
  type_cache.h
  print_type.c
  print_type.h
  print_sample.c
  print_sample.h
)
add_executable(xmltype
  xmltype.c
  xmltype.h
  domtree.c
  domtree.h
  type_cache.c
  type_cache.h
  print_type.c
  print_type.h
  print_sample.c
  print_sample.h
  compare_samples.c
  compare_samples.h
  scan_sample.c
  scan_sample.h
)

if(TARGET CycloneDDS::ddsc)
  # shouldn't need this ...
  target_include_directories(dynsub
    PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../../src/core/cdr/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../src/core/ddsi/include")
  target_include_directories(xmltype
    PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../../src/core/cdr/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../src/core/ddsi/include")
endif()
target_link_libraries(dynsub CycloneDDS::ddsc)
target_link_libraries(xmltype CycloneDDS::ddsc)

add_executable(variouspub variouspub.c)
idlc_generate(TARGET variouspub_lib FILES "variouspub_types.idl" WARNINGS no-implicit-extensibility)
target_link_libraries(variouspub variouspub_lib CycloneDDS::ddsc)
