#
# Copyright(c) 2022 ZettaScale Technology and others
#
# This program and the accompanying materials are made available under the
# terms of the Eclipse Public License v. 2.0 which is available at
# http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
# v. 1.0 which is available at
# http://www.eclipse.org/org/documents/edl-v10.php.
#
# SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
#

# Set project if built outside Cyclone.  The way I read the docs, it should be safe to
# always do this "project" thing, but it breaks everything.
if(NOT ${CMAKE_PROJECT_NAME} STREQUAL "CycloneDDS")
  cmake_minimum_required(VERSION 3.16)
  project(cdr VERSION 0.11.0 LANGUAGES C)
endif()

set(srcs_cdr
  "${CMAKE_CURRENT_LIST_DIR}/src/dds_cdrstream.c")

set(hdrs_private_cdr
  "${CMAKE_CURRENT_LIST_DIR}/include/dds/cdr/dds_cdrstream.h")

if(${CMAKE_PROJECT_NAME} STREQUAL "CycloneDDS")
  # If built as part of Cyclone DDS, then just add the sources to the big library
  target_sources(ddsc PRIVATE ${srcs_cdr} ${hdrs_private_cdr})
  target_include_directories(ddsc PRIVATE "${CMAKE_CURRENT_LIST_DIR}/include")

  install(
    DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/include/"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    COMPONENT dev)
else()
  # We still need ddsrt for some things
  #add_subdirectory(../../ddsrt)
  set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/../../../cmake/Modules")
  include(Generate)
  include(GenerateExportHeader)

  if (BUILD_SHARED_LIBS OR NOT DEFINED BUILD_SHARED_LIBS)
    add_library(cdr SHARED "")
  else()
    add_library(cdr)
  endif()

  add_library(${PROJECT_NAME}::cdr ALIAS cdr)

  target_sources(cdr PRIVATE
    ${srcs_cdr}
    ${hdrs_private_cdr}
    ../../ddsrt/src/bswap.c
    ../../ddsrt/include/dds/ddsrt/bswap.h)

  target_include_directories(cdr PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/include"
    "${CMAKE_BINARY_DIR}/src/core/cdr/include"
    "${CMAKE_CURRENT_LIST_DIR}/../../ddsrt/include"
    "${CMAKE_CURRENT_LIST_DIR}/../ddsc/include"
    "${CMAKE_BINARY_DIR}/include")

  configure_file(${CMAKE_CURRENT_LIST_DIR}/../../ddsrt/include/dds/config.h.in include/dds/config.h)
  configure_file(${CMAKE_CURRENT_LIST_DIR}/../../ddsrt/include/dds/features.h.in include/dds/features.h)
  configure_file(${CMAKE_CURRENT_LIST_DIR}/../../ddsrt/include/dds/version.h.in include/dds/version.h)

  generate_export_header(
    cdr BASE_NAME DDS EXPORT_FILE_NAME include/dds/export.h)

  install(
    TARGETS cdr
    EXPORT "${PROJECT_NAME}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" COMPONENT lib
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT lib
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT lib
  )

  install(
    DIRECTORY
      "${CMAKE_CURRENT_LIST_DIR}/include/"
      "${CMAKE_BINARY_DIR}/src/core/cdr/include/"
      "${CMAKE_CURRENT_LIST_DIR}/../../ddsrt/include/"
      "${CMAKE_CURRENT_LIST_DIR}/../ddsc/include/"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    COMPONENT dev)
endif()
