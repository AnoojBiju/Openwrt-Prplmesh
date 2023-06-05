#ifndef AMBIORIXSTORAGE_H
#define AMBIORIXSTORAGE_H
#include "ambiorix_amxc.h"
#include "ambiorix_config.h"
#include <easylogging++.h>
#include <amxp/amxp_dir.h>

static int isdot(int c) {
    return c == '.';
}

class AmbiorixOdlManager : public AMXOParser
{
    amxc_llist_t save_paths;
    std::string odlGetDirectory() {
        const char* odl_dir = GETP_CHAR(AMXOParser::getConfig(),
                                        AMXOParser::OdlConfig_str(AMXOParser::CVAL_DIRECTORY)) ?:
                                  GETP_CHAR(AMXOParser::getConfig(), AMXOParser::OdlConfig_str(COPT_STORAGE_DIR));
        if (!odl_dir) return NULL;

        LOG(WARNING) << "Import - CVAL_DIRECTORY "<<std::string(GETP_CHAR(AMXOParser::getConfig(),
                                                                           AMXOParser::OdlConfig_str(AMXOParser::CVAL_DIRECTORY)));

        LOG(WARNING) << "Import - COPT_STORAGE_DIR "<<std::string(GETP_CHAR(AMXOParser::getConfig(),
                                                                           AMXOParser::OdlConfig_str(AMXOParser::COPT_STORAGE_DIR)));
        amxc_string_t dir;
        amxc_string_init(&dir, 0);
        amxc_string_setf(&dir, "%s", odl_dir);
        amxc_string_resolve(&dir, AMXOParser::getConfig());

        return std::string(dir.buffer);
    }

//    int runtime_register() {
//        int retval = 0;

//        amxc_var_set(bool, GET_ARG(AMXOParser::getConfig(), AMXOParser::OdlConfig_str(AMXOParser::COPT_EVENT)), true);
//        retval =amxo_parser_invoke_entry_points(AMXOParser::getParser(), AMXOParser::getDatamodel(), AMXO_START);
//        if(AMXOParser::getParser()->post_includes != NULL) {
//            retval |= amxo_parser_invoke_entry_points(AMXOParser::getParser(), AMXOParser ::getDatamodel(), AMXO_ODL_LOADED);
//        }
//        return retval;
//    }

    int odlDmLoad() {
        int status = 0;
        amxc_string_t include;
        bool is_empty_dir = false;

        amxd_object_t* root = amxd_dm_get_root(AMXOParser::getDatamodel());
        std::string odl_dir = odlGetDirectory();
        LOG(WARNING) << "Import - odl_dm_load "<<odl_dir;
        amxc_var_t* eventing = GET_ARG(AMXOParser::getConfig(), AMXOParser::OdlConfig_str(AMXOParser::COPT_EVENT));
        bool orig_eventing = GET_BOOL(eventing, NULL);
        bool dm_eventing_enabled = GETP_BOOL(AMXOParser::getConfig(), AMXOParser::OdlConfig_str(AMXOParser::CVAL_EVENTS));

        amxc_string_init(&include, 0);

        if(odl_dir.empty()) {
            LOG(WARNING) << "Import - No odl directory specified";
            goto exit;
        }

        amxc_var_set(bool, eventing, dm_eventing_enabled);
        amxp_sigmngr_enable(&AMXOParser::getDatamodel()->sigmngr, dm_eventing_enabled);

        amxc_string_setf(&include, "include \"%s\";", odl_dir.c_str());
        status = amxo_parser_parse_string(AMXOParser::getParser(), amxc_string_get(&include, 0), root);
        if(status == 0) {
            is_empty_dir = amxp_dir_is_empty(odl_dir.c_str());
        }
        if((status != 0) || is_empty_dir) {
            const char* def = GETP_CHAR(AMXOParser::getConfig(), AMXOParser::OdlConfig_str(AMXOParser::CVAL_DEFAULTS));
            LOG(WARNING) << "Import - Failed to load from "<< odl_dir;
            if((def == NULL) || (*def == 0)) {
                goto exit;
            }
            LOG(WARNING) << "Import - Try to load default from "<<def;
            amxc_string_setf(&include, "include \"%s\";", def);
            status = amxo_parser_parse_string(AMXOParser::getParser(), amxc_string_get(&include, 0), root);
            if(status != 0) {
                LOG(WARNING) << "Import - Failed to load defaults from "<< def;
            }
        }

    exit:
        amxp_sigmngr_enable(&AMXOParser::getDatamodel()->sigmngr, true);
        amxc_var_set(bool, eventing, orig_eventing);
        amxc_string_clean(&include);
        return status;
    }

    bool odlSaveCheckTree(amxd_object_t* object) {
        bool persistent = true;
        auto parent = amxd_object_get_parent(object);

        while(amxd_object_get_type(parent) != amxd_object_root && persistent) {
            persistent &= amxd_object_is_attr_set(object, amxd_oattr_persistent);
            parent = amxd_object_get_parent(parent);
        }

        return persistent;
    }

    int odlDmSaveObject(amxo_parser_t* parser,
                                           amxd_object_t* object,
                                           const char* dir,
                                           const char* name) {
        int status = 0;
        amxc_string_t file;
        amxc_string_init(&file, 0);

        amxc_string_setf(&file, "%s/%s.odl", dir, name);
        LOG(INFO) << "odl_dm_save_object"<<std::string(amxc_string_get(&file, 0));

        status = amxo_parser_save_object(parser, amxc_string_get(&file, 0), object, false);
        if(status != 0) {
            syslog(LOG_USER | LOG_WARNING,
                   "Export - Failed to write %s file", amxc_string_get(&file, 0));
        }
        LOG(INFO) << "odl_dm_save_object "<<status;

        amxc_string_clean(&file);
        return status;
    }

    char* odlGetDirectory(amxo_parser_t* parser) {
        amxc_string_t dir;
        const char* odl_dir = GETP_CHAR(&parser->config, AMXOParser::OdlConfig_str(AMXOParser::CVAL_DIRECTORY));
        char* resolved_dir = NULL;
        LOG(INFO) << "odl_dir "<<std::string(odl_dir);
        amxc_string_init(&dir, 0);
        if(odl_dir == NULL) {
            odl_dir = GETP_CHAR(&parser->config, AMXOParser::OdlConfig_str(AMXOParser::COPT_STORAGE_DIR));
            LOG(INFO) << "odl_dir1 "<<std::string(odl_dir);
        }
        if(odl_dir != NULL) {
            amxc_string_setf(&dir, "%s", odl_dir);
            amxc_string_resolve(&dir, &parser->config);
            resolved_dir = amxc_string_take_buffer(&dir);
            LOG(INFO) << "resolved_dir "<<std::string(resolved_dir);
        }

        return resolved_dir;
    }

    int odlDmSave(amxd_dm_t* dm, amxo_parser_t* parser) {
        int status = 0;
        amxc_var_t* paths = odl_get_save_objects(parser);
        char* odl_dir = odlGetDirectory(parser);
        uint32_t index = 0;
        amxc_string_t file_name;

        amxc_string_init(&file_name, 0);
        //    if(odl_get_state() != odl_state_running) {
        //        goto exit;
        //    }
        LOG(INFO) << "dl directory : "<<std::string(odl_dir);
        if((odl_dir == NULL) || (*odl_dir == 0)) {
            LOG(INFO) << "0";

            syslog(LOG_USER | LOG_WARNING, "Export - No odl directory specified");
            goto exit;
        }
        if(paths == NULL) {
            LOG(INFO) << "1";

            amxd_object_t* root = amxd_dm_get_root(dm);
            const char* name = GETP_CHAR(&parser->config, AMXOParser::OdlConfig_str(AMXOParser::COPT_NAME));
            const char* COPT_STORAGE_DIR = GETP_CHAR(&parser->config, AMXOParser::OdlConfig_str(AMXOParser::COPT_STORAGE_DIR));
            LOG(INFO) << "COPT_NAME"<<std::string(name);
            LOG(INFO) << "COPT_STORAGE_DIR"<<std::string(COPT_STORAGE_DIR);
            if(name == NULL) {LOG(INFO) << "1.1";
                status = -1;
                goto exit;
            }
            status = odlDmSaveObject(parser, root, odl_dir, name);
            goto exit;
        }
        LOG(INFO) << "2";

        if(amxc_var_type_of(paths) != AMXC_VAR_ID_LIST) {
            goto exit;
        }

        amxc_var_for_each(path, paths) {
            const char* op = amxc_var_constcast(cstring_t, path);
            amxc_string_setf(&file_name, "%2.2d_%s", index, op);
            amxc_string_trimr(&file_name, isdot);
            amxd_object_t* obj = amxd_dm_findf(dm, "%s", op);
            if(obj == NULL) {
                syslog(LOG_USER | LOG_WARNING, "Export - Object %s not found", op);
                continue;
            }
            status = odlDmSaveObject(parser, obj, odl_dir, amxc_string_get(&file_name, 0));
            index++;
        }

    exit:
        amxc_string_clean(&file_name);
        free(odl_dir);
        return status;
    }

    void odlSaveAddPath(const char* path) {
        //TODO : analyze this
        LOG(INFO) << "amxc_string_from_llist_it";
        amxc_string_t* save_path = NULL;
        bool is_set = false;

        amxc_llist_iterate(it, (&save_paths)) {
            amxc_string_t* set_path = amxc_string_from_llist_it(it);
            LOG(INFO) << "amxc_string_from_llist_it"<<amxc_string_get(set_path, 0);
            if(strcmp(path, amxc_string_get(set_path, 0)) == 0) {
                is_set = true;
                break;
            }
        }
        if(!is_set) {
            amxc_string_new(&save_path, 0);
            amxc_string_setf(save_path, "%s", path);
            amxc_llist_append(&save_paths, &save_path->it);
        }
    }
    amxc_var_t* odl_get_save_objects(amxo_parser_t* parser) {
        amxc_var_t* paths = GETP_ARG(AMXOParser::getConfig(), AMXOParser::OdlConfig_str(AMXOParser::CVAL_OBJECTS));

        if(amxc_var_type_of(paths) == AMXC_VAR_ID_CSTRING) {
            amxc_var_cast(paths, AMXC_VAR_ID_CSV_STRING);
            amxc_var_cast(paths, AMXC_VAR_ID_LIST);
        } else if(amxc_var_type_of(paths) == AMXC_VAR_ID_CSV_STRING) {
            amxc_var_cast(paths, AMXC_VAR_ID_LIST);
        } else if(amxc_var_type_of(paths) != AMXC_VAR_ID_LIST) {
            syslog(LOG_USER | LOG_WARNING, "Export - Export objects specified in wrong format");
            goto exit;
        }

    exit:
        return paths;
    }
    bool odlSaveCheckPaths(amxo_parser_t* parser, amxd_object_t* object) {
        bool save_needed = false;
        char* obj_path = amxd_object_get_path(object, AMXD_OBJECT_INDEXED);
        LOG(INFO) << "odl_save_check_paths : >> "<<std::string(obj_path);

        amxc_var_t* paths = odl_get_save_objects(parser);
        if(paths == NULL) {
            LOG(INFO) << "odl_save_check_paths paths == NULL";
            save_needed = true;
            goto exit;
        }

        if(amxc_var_type_of(paths) != AMXC_VAR_ID_LIST) {
            LOG(INFO) << "odl_save_check_paths AMXC_VAR_ID_LIST";
            goto exit;
        }

        amxc_var_for_each(path, paths) {
            LOG(INFO) << "odl_save_check_paths amxc_var_for_each";
            const char* str_path = amxc_var_constcast(cstring_t, path);
            int len = strlen(str_path);
            if(strncmp(str_path, obj_path, len) == 0) {
                odlSaveAddPath(str_path);
                save_needed = true;
                break;
            }
        }

    exit:
        free(obj_path);
        return save_needed;
    }

    bool odlSaveCheckPersistentParams(amxd_object_t* object, const amxc_var_t* data) {
        bool persistent = false;
        AMXContainer params = amxc_var_get_key(data, "parameters", AMXC_VAR_FLAG_DEFAULT);

        for (amxc_var_t* param : params) {
            const char* name = amxc_var_key(param);
            amxd_param_t* param_def = amxd_object_get_param_def(object, name);
            LOG(INFO) << "odl_save_check_persistent_params :"<<std::string(name)<<" , "<<amxd_param_is_attr_set(param_def, amxd_pattr_persistent)<<";";

            persistent |= amxd_param_is_attr_set(param_def, amxd_pattr_persistent);
            if(persistent) {
                break;
            }
        }

        return persistent;
    }



public:
    AmbiorixOdlManager():AMXOParser(){
        amxp_sigmngr_add_signal(NULL, "connection-added");
        amxp_sigmngr_add_signal(NULL, "connection-wait-write");
        amxp_sigmngr_add_signal(NULL, "listen-added");
        amxp_sigmngr_add_signal(NULL, "listen-deleted");
        amxp_sigmngr_add_signal(NULL, "connection-deleted");
        amxp_sigmngr_add_signal(NULL, "config:changed");
        amxp_sigmngr_add_signal(NULL, "wait:done");
        amxp_sigmngr_add_signal(NULL, "wait:cancel");
        bool dm_eventing_enabled = GETP_BOOL(AMXOParser::getConfig(), AMXOParser::OdlConfig_str(AMXOParser::CVAL_EVENTS));
        amxp_sigmngr_enable(&AMXOParser::getDatamodel()->sigmngr, dm_eventing_enabled);
    }
    bool loadRootDM(std::string path){
        amxd_object_t* rootObj = amxd_dm_get_root(AMXOParser::getDatamodel());
        if (!rootObj) {
            LOG(ERROR) << "Failed to get datamodel root object.";
            return false;
        }

        amxp_slot_connect(&AMXOParser::getDatamodel()->sigmngr, "dm:object-changed", NULL, AmbiorixOdlManager::dispatchAndSaveEvent, this);
        amxp_slot_connect(&AMXOParser::getDatamodel()->sigmngr, "dm:instance-added", NULL, AmbiorixOdlManager::dispatchAndSaveEvent, this);
        amxp_slot_connect(&AMXOParser::getDatamodel()->sigmngr, "dm:instance-removed", NULL, AmbiorixOdlManager::dispatchAndSaveEvent, this);

        amxp_sigmngr_enable(&AMXOParser::getDatamodel()->sigmngr, false);
        amxo_parser_parse_file(AMXOParser::getParser(), path.c_str(), rootObj);

        amxp_sigmngr_enable(&AMXOParser::getDatamodel()->sigmngr, true);
        //TODO : using this the mods can be loaded but for some reason this causes crash
//        runtime_register();

        LOG(DEBUG) << "The data model loaded successfully.";
        //TODO handle ret values
        return true;
    }

    void populateDataModel(){
        std::string root_odl_dir = odlGetDirectory();
        if(amxp_dir_make(root_odl_dir.c_str(), 0777) != 0) {
            LOG(WARNING) << "Failed to create directory "<<root_odl_dir.c_str();
        }
        if(GETP_BOOL(AMXOParser::getConfig(), AMXOParser::OdlConfig_str(AMXOParser::CVAL_LOAD))) {
            odlDmLoad();
        }
        //        if(GETP_BOOL(&parser->config, ON_CHANGED)) {
        //            amxp_timer_new(&storage.save_timer, odl_timed_save, NULL);
        //            odl_save_subscribe(dm);
        //        }
    }

    void handleSaveRequest(const char* const sig_name, const amxc_var_t* const data) {

        amxd_object_t* object = amxd_dm_signal_get_object(AMXOParser::getDatamodel(), data);
        bool check_save_tree = odlSaveCheckTree(object);
        std::string sig_event_name = sig_name;
        bool check_save_needed = false;
        if(sig_event_name == "dm:object-removed"){
            LOG(INFO) << "dm:object-removed";
            check_save_needed = true;
        }else if (sig_event_name == "dm:object-changed"&&
                   amxd_object_is_attr_set(object, amxd_oattr_persistent) &&
                   check_save_tree) {
            LOG(INFO) << "dm:object-changed";
            check_save_needed = check_save_tree;
            odlSaveCheckPersistentParams(object, data);
        }else {
            check_save_needed = check_save_tree;
        }
        LOG(INFO) << "check_save_needed "<<check_save_needed<<" check_save_tree "<<check_save_tree<< " odl_save "<<odlSaveCheckPersistentParams(object, data);
        if(check_save_needed) {
            check_save_needed = odlSaveCheckPaths(AMXOParser::getParser(), object);
        }
        if (check_save_needed) {
            LOG(INFO) << "schudle saving process ";
            odlDmSave(getDatamodel(), getParser());
            //amxp_timer_start(storage.save_timer, save_delay == 0 ? 500 : save_delay);
        }
    }
    static void dispatchAndSaveEvent(const char* const sig_name, const amxc_var_t* const data, void* const priv){
        AmbiorixOdlManager* instance = static_cast<AmbiorixOdlManager*>(priv);
        instance->handleSaveRequest(sig_name, data);
        //TODO move handler to sub classes : Storage class and Persistent Storage class
        //instance->pcm_svc_param_changed(sig_name, data, priv);
    }

};

#endif // AMBIORIXSTORAGE_H
