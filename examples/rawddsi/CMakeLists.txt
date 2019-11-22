#
# Copyright(c) 2006 to 2018 ADLINK Technology Limited and others
#
# This program and the accompanying materials are made available under the
# terms of the Eclipse Public License v. 2.0 which is available at
# http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
# v. 1.0 which is available at
# http://www.eclipse.org/org/documents/edl-v10.php.
#
# SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
#
add_executable(rawddsi rawddsi.c)

# must match libddsc, CMake probably has a dirty trick for that ...
add_definitions(-DDDSI_INCLUDE_NETWORK_PARTITIONS -DDDSI_INCLUDE_SSM -DDDSI_INCLUDE_SSL)

target_include_directories(
  rawddsi PRIVATE
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../src/core/ddsc/src>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../src/core/ddsi/include>")

target_link_libraries(rawddsi CycloneDDS::ddsc)
