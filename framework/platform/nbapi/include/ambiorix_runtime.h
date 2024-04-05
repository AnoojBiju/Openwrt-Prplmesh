/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef AMBIORIX_RT_H
#define AMBIORIX_RT_H
#include <map>
#include <string>

// Ambiorix
#include <amxrt/amxrt.h>

namespace beerocks {
namespace nbapi {
class Amxrt {

public:
    Amxrt()
    {
        m_index = 0;
        amxrt_new();
    }
    ~Amxrt()
    {
        amxrt_stop();
        amxrt_delete();
    }

    /**
    * @brief  Initializes the default runtime configuration.
    * Sets the default values for all default configuration options.
    * Also uses the command line option parser and if needed adapts the configuration  accordingly.
    * @param argc the number of arguments available
    * @param argv the vector containing the commandline arguments
    * @param handler (optional) a pointer to a callback function to handle the option or NULL
    * @return 0 if no error occured.
    */
    int Initialize(int argc, char *argv[], amxrt_arg_fn_t handler)
    {
        return amxrt_config_init(argc, argv, &m_index, handler);
        // Add error handling if needed
    }

    /**
   *  @brief Load odls files mentioned on the command line or the default odl file.

   * By default odl files can be specified after the command line options.
   * This function will load these odl files.

   * If no odl files are specified at the command line, the default odl file will
   * be loaded. The application name (Argv[0]) will be used to find the default odl file.

   * The default odl file is "/etc/amx/<appname>/<appname>.odl".

   * If no odl files are defined at the commandline and the default odl file does't  exist, nothing is loaded an no error is thrown.

   * This function will also scan the default mib dir for the application. If  a mib dir is available and contains mib definitions, these are not loaded by default.
   * Mib definitions will be loaded when needed.

   * @param argc the number of arguments available
   * @param argv the vector containing the commandline arguments
   * @return  Non zero indicates an error
    */
    int LoadOdlFiles(int argc, char *argv[])
    {
        return amxrt_load_odl_files(argc, argv, m_index);
        // Add error handling if needed
    }

    static void AddAutoSave(amxo_entry_point_t callback)
    {
        amxo_parser_add_entry_point(amxrt_get_parser(), callback);
    }

    static void Connect()
    {
        amxrt_connect();
        // Add error handling if needed
    }

    static void EnableSyssigs()
    {
        amxc_var_t *config  = amxrt_get_config();
        amxc_var_t *syssigs = GET_ARG(config, "system-signals");
        if (syssigs != NULL) {
            amxrt_enable_syssigs(syssigs);
        }
    }

    static int RegisterOrWait()
    {
        return amxrt_register_or_wait();
        // Add error handling if needed
    }

    static void RunEventLoop() { amxrt_el_start(); }

    static amxd_dm_t *getDatamodel() { return amxrt_get_dm(); }
    static amxo_parser_t *getParser() { return amxrt_get_parser(); }

    /**
    * @brief Gets the htable variant containing the configuration options
    * 
    * @return The htable variant containing the configuration options.
    */
    static amxc_var_t *getConfig() { return amxrt_get_config(); }

    /**
    * Adds a command line option definition.
    * This function adds a command line option definition to the list of accepted options.
    * @param id the id of the option, if 0 is given the short_option is used as id.
    * @param short_option a single character representing the short option/
    * @param long_option a string literal containing the name of the long option without the double '-'
    * @param has_args must be one of no_argument (if the option does not take an argument),
    *                    required_argument (if the option requires an argument) or
    *                    optional_argument (if the takes an optional argument).
    * @param doc a string literal describing the option
    * @param arg_doc a string literal describing the argument or NULL if the option doesn't have an argument

    @return  0 when option definition is added, any other value indicates an error.
    */
    int cmd_line_add_option(int id, char short_option, const char *long_option, int has_args,
                                  const char *doc, const char *arg_doc)
    {
        return amxrt_cmd_line_add_option(id, short_option, long_option, has_args, doc, arg_doc);
    }

private:
    int m_index;
};
} // namespace nbapi
} // namespace beerocks
#endif
