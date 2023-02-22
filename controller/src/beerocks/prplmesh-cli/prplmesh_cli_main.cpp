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
    beerocks::prplmesh_api::prplmesh_cli prpl_cli;
    if (argc < 2) {
        prpl_cli.print_help();
        return 1;
    }

    int opt;
    std::string command_string;
    while ((opt = getopt(argc, argv, "c:v")) != -1) {
        switch (opt) {
        case 'c': {
            command_string = std::string(optarg);
            if (command_string == "conn_map") {
                prpl_cli.prpl_conn_map();
            } else if (command_string == "help") {
                prpl_cli.print_help();
            } else {
                std::cerr << "Error, command not found: " << command_string << std::endl
                          << "Run '-c help' to see supported commands" << std::endl;
            }

            break;
        }
        case 'v': {
            prpl_cli.print_version();
            return 0;
        }
        default: {
            prpl_cli.print_help();
            return 1;
        }
        }
    }

    return 0;
}
