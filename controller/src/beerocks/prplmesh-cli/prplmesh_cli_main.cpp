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

beerocks::prplmesh_api::prplmesh_cli prpl_cli;

bool set_ssid(int argc, char *argv[])
{
    int opt;
    char *ap   = 0;
    char *ssid = 0;

    while ((opt = getopt(argc, argv, "o:n:")) != -1) {
        switch (opt) {
        case 'o':
            ap = optarg;
            break;
        case 'n':
            ssid = optarg;
            break;
        default:
            return false;
        }
    }

    return ap and ssid and prpl_cli.set_ssid(ap, ssid);
}

bool set_security(int argc, char *argv[])
{
    int opt;
    char *ap         = 0;
    char *mode       = 0;
    char *passphrase = 0;

    while ((opt = getopt(argc, argv, "o:m:p:")) != -1) {
        switch (opt) {
        case 'o':
            ap = optarg;
            break;
        case 'm':
            mode = optarg;
            break;
        case 'p':
            passphrase = optarg;
            break;
        default:
            return false;
        }
    }

    return ap and mode and prpl_cli.set_security(ap, mode, passphrase ?: "");
}

bool print_status(int argc, char *argv[])
{
    int opt;
    const char *format = 0;

    while ((opt = getopt(argc, argv, "o:")) != -1) {
        switch (opt) {
        case 'o':
            format = optarg;
            break;
        default:
            return false;
        }
    }

    if (!format) {
        format = isatty(STDOUT_FILENO) ? "pretty" : "json";
    }

    return !prpl_cli.print_status(format);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        prpl_cli.print_help();
        return 1;
    }

    int opt;
    std::string command_string;
    while ((opt = getopt(argc, argv, "c:vh")) != -1) {
        switch (opt) {
        case 'c': {
            command_string = std::string(optarg);
            if (command_string == "conn_map") {
                prpl_cli.prpl_conn_map();
            } else if (command_string == "show_ap") {
                prpl_cli.show_ap();
            } else if (command_string == "set_ssid") {
                return !set_ssid(argc, argv);
            } else if (command_string == "set_security") {
                return !set_security(argc, argv);
            } else if (command_string == "version") {
                prpl_cli.print_version();
            } else if (command_string == "help") {
                prpl_cli.print_help();
            } else if (command_string == "mode") {
                return !prpl_cli.print_mode();
            } else if (command_string == "status") {
                return print_status(argc, argv);
            } else {
                std::cerr << "Error, command not found: " << command_string << std::endl
                          << "Run '-c help' to see supported commands" << std::endl;
                return 1;
            }

            break;
        }
        case 'v': {
            prpl_cli.print_version();
            return 0;
        }
        case 'h': /* breakthrough */
        default: {
            prpl_cli.print_help();
            return opt != 'h';
        }
        }
    }

    return 0;
}
