#ifndef AMBIORIXSTORAGE_H
#define AMBIORIXSTORAGE_H
#include "ambiorix_amxc.h"
#include "ambiorix_config.h"
#include <easylogging++.h>
#include <amxp/amxp_dir.h>

class AmbiorixOdlManager : public AMXOConfig
{
    amxc_llist_t save_paths;

    //    int runtime_register() {
    //        int retval = 0;

    //        amxc_var_set(bool, GET_ARG(AMXOParser::getConfig(), AMXOParser::OdlConfig_str(AMXOParser::COPT_EVENT)), true);
    //        retval =amxo_parser_invoke_entry_points(AMXOParser::getParser(), AMXOParser::getDatamodel(), AMXO_START);
    //        if(AMXOParser::getParser()->post_includes != NULL) {
    //            retval |= amxo_parser_invoke_entry_points(AMXOParser::getParser(), AMXOParser ::getDatamodel(), AMXO_ODL_LOADED);
    //        }
    //        return retval;
    //    }

    bool odlSaveCheckTree(amxd_object_t* object);
    int odlDmSaveObject(amxo_parser_t* parser,
                        amxd_object_t* object,
                        const char* dir,
                        const char* name);

    std::string odlGetDirectory();
    int odlDmSave(amxd_dm_t* dm, amxo_parser_t* parser);
    void odlSaveAddPath(const char* path);
    amxc_var_t* odlGetSaveObjects(amxo_parser_t* parser);
    bool odlSaveCheckPaths(amxo_parser_t* parser, amxd_object_t* object);
    bool odlSaveCheckPersistentParams(amxd_object_t* object, const amxc_var_t* data);

public:

    AmbiorixOdlManager();
    bool loadRootDM(std::string path);
    int populateDataModel();
    void handleSaveRequest(const char* const sig_name, const amxc_var_t* const data);
    static void dispatchAndSaveEvent(const char* const sig_name, const amxc_var_t* const data, void* const priv);

};

#endif // AMBIORIXSTORAGE_H
