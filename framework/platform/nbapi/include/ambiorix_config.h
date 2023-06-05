/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef AMBIORIX_CONFIG_H
#define AMBIORIX_CONFIG_H
// Ambiorix
#include "ambiorix_amxc.h"

#include <amxp/amxp.h>

#include <amxd/amxd_action.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_event.h>
#include <amxd/amxd_transaction.h>

#include <amxb/amxb.h>
#include <amxb/amxb_register.h>

#include <amxo/amxo.h>
#include <amxo/amxo_save.h>

#include <string>
#include <map>
#include <memory>

#include "ambiorix_parser.h"

class AMXOConfig : public AMXOParser{
private:
    std::shared_ptr<amxc_var_t> cmd_options;
    std::string name;
    void configBuild();
public:
    AMXOConfig(std::string name);
    AMXOConfig();

    void configInit();
    void configClean();

    void configAddDir(amxc_var_t* varDirs, const std::string dir);
    void configSetDefaultDirs(amxo_parser_t* parser);


    void configAddOption(std::string name, amxc_var_t* value);
    std::shared_ptr<amxc_var_t> getCmdOptions();
    void setCmdOptions(const std::shared_ptr<amxc_var_t> &newCmd_options);
    void setName(const std::string &newName)
    {
        name = newName;
    }
};

#endif
