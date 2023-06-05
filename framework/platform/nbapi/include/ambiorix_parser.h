/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef AMBIORIX_PARSER_H
#define AMBIORIX_PARSER_H
#include <string>
#include <map>

// Ambiorix


#include <amxo/amxo.h>
#include <amxo/amxo_save.h>
#include <amxd/amxd_action.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_event.h>
#include <amxd/amxd_transaction.h>
class AMXOParser {

    // clang-format on
    amxd_dm_t dm;
    amxo_parser_t parser;
public:
    AMXOParser(){
        amxd_dm_init(&dm);
        amxo_parser_init(&parser);
    }
    ~AMXOParser(){
    }

    enum {
        COPT_URIS,
        COPT_DATA_URIS,
        COPT_BACKENDS,
        COPT_AUTO_DETECT,
        COPT_AUTO_CONNECT,
        COPT_INCDIRS,
        COPT_LIBDIRS,
        COPT_MIBDIRS,
        COPT_ODL,
        COPT_DAEMON,
        COPT_PRIORITY,
        COPT_PID_FILE,
        COPT_NAME,
        COPT_PREFIX_PATH,
        COPT_PLUGIN_DIR,
        COPT_CFG_DIR,
        COPT_BACKEND_DIR,
        COPT_LISTEN,
        COPT_EVENT,
        COPT_DUMP_CONFIG,
        COPT_BACKENDS_DIR,
        COPT_RW_DATA_PATH,
        COPT_STORAGE_DIR,
        COPT_STORAGE_TYPE,
        COPT_ODL_CONFIG,
        COPT_LOG,
        COPT_REQUIRES,
        COPT_HANDLE_EVENTS,
        COPT_SUSPEND,
        CVAL_PLUGIN_DIR,
        CVAL_CFG_DIR,
        CVAL_BACKENDS_DIR,
        CVAL_STORAGE_TYPE,
        CVAL_RWDATAPATH,
        CVAL_DIRECTORY,
        CVAL_DEFAULTS,
        CVAL_EVENTS,
        CVAL_OBJECTS,
        CVAL_LOAD,
        CVAL_SAVE,
        CVAL_ON_CHANGED,
        CVAL_DELAY,
        CVAL_STORAGE
    };
    static const char *OdlConfig_str(int enum_value) {
        switch (enum_value) {
        case COPT_URIS:return "uris";
        case COPT_DATA_URIS:return "data-uris";
        case COPT_BACKENDS:return "backends";
        case COPT_AUTO_DETECT:return "auto-detect";
        case COPT_AUTO_CONNECT:return "auto-connect";
        case COPT_INCDIRS:return "include-dirs";
        case COPT_LIBDIRS:return "import-dirs";
        case COPT_MIBDIRS:return "mib-dirs";
        case COPT_ODL:return "ODL";
        case COPT_DAEMON:return "daemon";
        case COPT_PRIORITY:return "priority";
        case COPT_PID_FILE:return "pid-file";
        case COPT_NAME:return "name";
        case COPT_PREFIX_PATH:return "prefix";
        case COPT_PLUGIN_DIR:return "plugin-dir";
        case COPT_CFG_DIR:return "cfg-dir";
        case COPT_LISTEN:return "listen";
        case COPT_EVENT:return "dm-eventing-enabled";
        case COPT_DUMP_CONFIG:return "dump-config";
        case COPT_BACKENDS_DIR:return "backend-dir";
        case COPT_RW_DATA_PATH:return "rw_data_path";
        case COPT_STORAGE_DIR:return "storage-path";
        case COPT_STORAGE_TYPE:return "storage-type";
        case COPT_ODL_CONFIG:return "odl";
        case COPT_LOG:return "log";
        case COPT_REQUIRES:return "requires";
        case COPT_HANDLE_EVENTS:return "dm-events-before-start";
        case COPT_SUSPEND:return "dm-events-suspend-when-requires";
        case CVAL_PLUGIN_DIR:return "/usr/lib/amx";
        case CVAL_CFG_DIR:return "/etc/amx";
        case CVAL_BACKENDS_DIR:return "/usr/bin/mods/amxb";
        case CVAL_STORAGE_TYPE:return "odl";
//TODO : pass it through CMAKE
        case CVAL_RWDATAPATH:return "/etc/configamx";
        case CVAL_DIRECTORY:return "odl.directory";
        case CVAL_DEFAULTS:return "odl.dm-defaults";
        case CVAL_EVENTS:return "odl.load-dm-events";
        case CVAL_OBJECTS:return "odl.dm-objects";
        case CVAL_LOAD:return "odl.dm-load";
        case CVAL_SAVE:return "odl.dm-save";
        case CVAL_ON_CHANGED:return "odl.dm-save-on-changed";
        case CVAL_DELAY:return "odl.dm-save-delay";
        case CVAL_STORAGE:return "storage-type";
        }
        static std::string out_str = std::to_string(int(enum_value));
        return out_str.c_str();
    }

    amxd_dm_t* getDatamodel() {
        return &dm;
    }
    amxo_parser_t* getParser(){  return &parser;}
    amxc_var_t* getConfig(){  return &parser.config;}
};



#endif
