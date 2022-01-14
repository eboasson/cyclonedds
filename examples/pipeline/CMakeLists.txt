#
# Copyright(c) 2021 ADLINK Technology Limited and others
#
# This program and the accompanying materials are made available under the
# terms of the Eclipse Public License v. 2.0 which is available at
# http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
# v. 1.0 which is available at
# http://www.eclipse.org/org/documents/edl-v10.php.
#
# SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
#
project(pipeline LANGUAGES C)
cmake_minimum_required(VERSION 3.10)

if(NOT TARGET CycloneDDS::ddsc)
  # Find the CycloneDDS package.
  find_package(CycloneDDS REQUIRED)
endif()

# This is a convenience function, provided by the CycloneDDS package,
# that will supply a library target related the the given idl file.
# In short, it takes the idl file, generates the source files with
# the proper data types and compiles them into a library.
idlc_generate(TARGET Pipeline_lib FILES "Pipeline.idl")
target_sources(Pipeline_lib PUBLIC ${CMAKE_CURRENT_LIST_DIR}/common.c ${CMAKE_CURRENT_LIST_DIR}/common.h)

# Both executables have only one related source file.
add_executable(PipelineSource source.c)
add_executable(PipelineProcess process.c)
add_executable(PipelineSink sink.c)

# Both executables need to be linked to the idl data type library and
# the ddsc API library.
target_link_libraries(PipelineSource Pipeline_lib CycloneDDS::ddsc)
target_link_libraries(PipelineProcess Pipeline_lib CycloneDDS::ddsc)
target_link_libraries(PipelineSink Pipeline_lib CycloneDDS::ddsc)
