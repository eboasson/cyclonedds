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

function(IDLC_GENERATE)
  set(one_value_keywords TARGET)
  set(multi_value_keywords FILES FEATURES INCLUDES)
  cmake_parse_arguments(
    IDLC "" "${one_value_keywords}" "${multi_value_keywords}" "" ${ARGN})

  idlc_generate_generic(TARGET ${IDLC_TARGET}
    FILES ${IDLC_FILES}
    FEATURES ${IDLC_FEATURES}
    INCLUDES ${IDLC_INCLUDES}
  )
endfunction()

function(IDLC_GENERATE_GENERIC)
  set(one_value_keywords TARGET BACKEND)
  set(multi_value_keywords FILES FEATURES INCLUDES SUFFIXES DEPENDS)
  cmake_parse_arguments(
    IDLC "" "${one_value_keywords}" "${multi_value_keywords}" "" ${ARGN})

  # find idlc binary
  if(CMAKE_CROSSCOMPILING)
    find_program(_idlc_executable idlc NO_CMAKE_FIND_ROOT_PATH REQUIRED)

    if(_idlc_executable)
      set(_idlc_depends "")
    else()
      message(FATAL_ERROR "Cannot find idlc executable")
    endif()
  else()
    set(_idlc_executable CycloneDDS::idlc)
    set(_idlc_depends CycloneDDS::idlc)
  endif()

  if(NOT IDLC_TARGET AND NOT IDLC_FILES)
    # assume deprecated invocation: TARGET FILE [FILE..]
    list(GET IDLC_UNPARSED_ARGUMENTS 0 IDLC_TARGET)
    list(REMOVE_AT IDLC_UNPARSED_ARGUMENTS 0 IDLC_)
    set(IDLC_FILES ${IDLC_UNPARSED_ARGUMENTS})
    if (IDLC_TARGET AND IDLC_FILES)
      message(WARNING " Deprecated use of idlc_generate. \n"
                      " Consider switching to keyword based invocation.")
    endif()
    # Java based compiler used to be case sensitive
    list(APPEND IDLC_FEATURES "case-sensitive")
  endif()

  if(NOT IDLC_TARGET)
    message(FATAL_ERROR "idlc_generate called without TARGET")
  elseif(NOT IDLC_FILES)
    message(FATAL_ERROR "idlc_generate called without FILES")
  endif()

  # remove duplicate features
  if(IDLC_FEATURES)
    list(REMOVE_DUPLICATES IDLC_FEATURES)
  endif()
  foreach(_feature ${IDLC_FEATURES})
    list(APPEND IDLC_ARGS "-f" ${_feature})
  endforeach()

  # add directories to include search list
  if(IDLC_INCLUDES)
    foreach(_dir ${IDLC_INCLUDES})
      list(APPEND IDLC_INCLUDE_DIRS "-I" ${_dir})
    endforeach()
  endif()

  # generate using which language (defaults to c)?
  if(IDLC_BACKEND)
    string(APPEND _language "-l" ${IDLC_BACKEND})
  endif()

  # set source suffixes (defaults to .c and .h)
  if(IDLC_SUFFIXES)
    foreach(_s ${IDLC_SUFFIXES})
      string(FIND ${_s} ".c" _spos)
      string(FIND ${_s} ".h" _hpos)
      if(_spos GREATER_EQUAL 0)
        set(_ssuffix ${_s})
      elseif(_hpos GREATER_EQUAL 0)
        set(_hsuffix ${_s})
      endif()
    endforeach()
  else()
    set(_hsuffix ".h")
    set(_ssuffix ".c")
  endif()

  # set dependencies
  if(IDLC_DEPENDS)
    list(APPEND _depends ${_idlc_depends} ${IDLC_DEPENDS})
  else()
    set(_depends ${_idlc_depends})
  endif()

  set(_dir ${CMAKE_CURRENT_BINARY_DIR})
  set(_target ${IDLC_TARGET})
  foreach(_file ${IDLC_FILES})
    get_filename_component(_path ${_file} ABSOLUTE)
    list(APPEND _files "${_path}")
  endforeach()

  foreach(_file ${_files})
    get_filename_component(_name ${_file} NAME_WE)

    if(NOT IDLC_BACKEND)
      set(_source "${_dir}/${_name}${_ssuffix}")
      list(APPEND _sources "${_source}")
    endif()

    set(_header "${_dir}/${_name}${_hsuffix}")
    list(APPEND _headers "${_header}")

    add_custom_command(
      OUTPUT   ${_source} ${_header}
      COMMAND  ${_idlc_executable}
      ARGS     ${_language} ${IDLC_ARGS} ${IDLC_INCLUDE_DIRS} ${_file}
      DEPENDS  ${_files} ${_depends})
  endforeach()

  add_custom_target("${_target}_generate" DEPENDS "${_sources}" "${_headers}")
  add_library(${_target} INTERFACE)
  target_sources(${_target} INTERFACE ${_sources} ${_headers})
  target_include_directories(${_target} INTERFACE "${_dir}")
  add_dependencies(${_target} "${_target}_generate")
endfunction()
