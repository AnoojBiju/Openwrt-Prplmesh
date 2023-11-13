# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
#
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

find_library(AMXRT_LIBRARY "libamxrt.so")
find_path(AMXRT_INCLUDE_DIRS
    NAMES amxrt/amxrt.h
)

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(amxrt DEFAULT_MSG
    AMXRT_LIBRARY
    AMXRT_INCLUDE_DIRS
)

if (amxrt_FOUND)
    add_library(amxrt UNKNOWN IMPORTED)

    # Includes
    set_target_properties(amxrt PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${AMXRT_INCLUDE_DIRS}/"
    )

    # Library
    set_target_properties(amxrt PROPERTIES
        IMPORTED_LINK_INTERFACE_LANGUAGES "C"
        IMPORTED_LOCATION "${AMXRT_LIBRARY}"
    )
endif()
