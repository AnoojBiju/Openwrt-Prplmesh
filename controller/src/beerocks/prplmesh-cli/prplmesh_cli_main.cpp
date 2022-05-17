/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "prplmesh_cli.h"

#include <iostream>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    beerocks::prplmesh_api::prplmesh_cli test;
    int opt;
    std::string command_string;
    while ((opt = getopt(argc, argv, "c:")) != -1) {
        switch (opt) {
        case 'c': {
            command_string = std::string(optarg);
            test.prpl_conn_map();
            break;
        }
        default: { /* '?' */
            return 1;
        }
        }
    }

    return 0;
}
