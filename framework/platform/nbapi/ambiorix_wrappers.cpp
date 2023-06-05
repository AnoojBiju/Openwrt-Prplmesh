#include "ambiorix_config.h"
#include <easylogging++.h>


static amxd_dm_t* context_dm;
static amxc_var_t* context_cmds;

AMXOConfig::AMXOConfig(std::string name) {
    this->name = name;
    cmd_options = std::make_shared<amxc_var_t>();
    configInit();
    configBuild();
}
AMXOConfig::AMXOConfig() {
    cmd_options = std::make_shared<amxc_var_t>();
    configInit();
    configBuild();
}
inline void AMXOConfig::configAddDir(amxc_var_t *varDirs, const std::string dir) {
    bool found = false;
    auto dirs = amxc_var_constcast(amxc_llist_t, varDirs);

    AMXCListContainer dirContainer(dirs);

    for(const auto& it : dirContainer) {
        amxc_var_t* varDir = amxc_var_from_llist_it(it);
        const char* storedDir = amxc_var_constcast(cstring_t, varDir);
        if((storedDir != nullptr) && dir == storedDir) {
            found = true;
            break;
        }
    }

    if(!found) {
        amxc_var_add(cstring_t, varDirs, dir.c_str());
    }
}

inline void AMXOConfig::configSetDefaultDirs(amxo_parser_t *parser) {
    amxc_var_t* incDirs = amxo_parser_claim_config(parser, AMXOParser::OdlConfig_str(AMXOParser::COPT_INCDIRS));
    amxc_var_t* libDirs = amxo_parser_claim_config(parser, AMXOParser::OdlConfig_str(AMXOParser::COPT_LIBDIRS));
    amxc_var_t* mibDirs = amxo_parser_claim_config(parser, AMXOParser::OdlConfig_str(AMXOParser::COPT_MIBDIRS));

    configAddDir(incDirs, ".");
    configAddDir(incDirs, "${prefix}${cfg-dir}/${name}");
    configAddDir(incDirs, "${prefix}${cfg-dir}/modules");

    configAddDir(libDirs, "${prefix}${plugin-dir}/${name}");
    configAddDir(libDirs, "${prefix}${plugin-dir}/modules");
    configAddDir(libDirs, "${prefix}/usr/local/lib/amx/${name}");
    configAddDir(libDirs, "${prefix}/usr/local/lib/amx/modules");

    configAddDir(mibDirs, "${prefix}${cfg-dir}/${name}/mibs");
}

// Config options are scoped within the odl file, so when an include is done,
// it is possible the config options are back to the original value
static void config_include_end(amxo_parser_t* parser, const char* file) {
    amxd_dm_t* dm = context_dm;
    amxp_sigmngr_enable(&dm->sigmngr, GET_BOOL(&parser->config, AMXOParser::OdlConfig_str(AMXOParser::COPT_EVENT)));
}
// When a config section is done, check if any settings must be applied
static void config_section_end(amxo_parser_t* parser, int section_id) {
    amxd_dm_t* dm = context_dm;
    if(section_id == 0) {
        amxp_sigmngr_enable(&dm->sigmngr, GET_BOOL(&parser->config, AMXOParser::OdlConfig_str(AMXOParser::COPT_EVENT)));
    }
}

static void config_option_changed(amxo_parser_t* parser, const char* option, amxc_var_t* value) {
    AMXContainer cmds = context_cmds;
    (void)cmds;
    for (auto cmd : cmds){
        //TODO Solve this loop
//        const char* path = amxc_var_key(cmd);
        (void)cmd;

        LOG(INFO) << "const char* path = amxc_var_key(cmd) : ";
        //amxc_var_set_path(&parser->config, path, cmd, AMXC_VAR_FLAG_UPDATE | AMXC_VAR_FLAG_COPY);
    }
}

static amxo_hooks_t amxrt_hooks = {
    .it = { .next = NULL, .prev = NULL, .llist = NULL },
    .comment = NULL,
    .start = NULL,
    .end = NULL,
    .start_include = NULL,
    .end_include = config_include_end,
    .set_config = config_option_changed,
    .start_section = NULL,
    .end_section = config_section_end,
    .create_object = NULL,
    .add_instance = NULL,
    .select_object = NULL,
    .end_object = NULL,
    .add_param = NULL,
    .set_param = NULL,
    .end_param = NULL,
    .add_func = NULL,
    .add_func_arg = NULL,
    .end_func = NULL,
    .add_mib = NULL,
    .set_counter = NULL,
    };

void AMXOConfig::configBuild(){

}
void AMXOConfig::configInit() {
    amxc_var_t* config = AMXOParser::getConfig();
    AMXContainer container(config);

    container.addNewKeyAmxcLlist(AMXOParser::OdlConfig_str(AMXOParser::COPT_BACKENDS), nullptr);
    container.addNewKeyAmxcLlist(AMXOParser::OdlConfig_str(AMXOParser::COPT_URIS), nullptr);
    container.addNewKeyBool(AMXOParser::OdlConfig_str(AMXOParser::COPT_AUTO_DETECT), true);
    container.addNewKeyBool(AMXOParser::OdlConfig_str(AMXOParser::COPT_AUTO_CONNECT), true);
    container.addNewKeyBool(AMXOParser::OdlConfig_str(AMXOParser::COPT_DAEMON), false);
    container.addNewKeyUint32(AMXOParser::OdlConfig_str(AMXOParser::COPT_PRIORITY), 0);
    container.addNewKeyBool(AMXOParser::OdlConfig_str(AMXOParser::COPT_PID_FILE), true);
    container.addNewKeyCString(AMXOParser::OdlConfig_str(AMXOParser::COPT_PREFIX_PATH), "");
    container.addNewKeyCString(AMXOParser::OdlConfig_str(AMXOParser::COPT_PLUGIN_DIR), AMXOParser::OdlConfig_str(AMXOParser::CVAL_PLUGIN_DIR));
    container.addNewKeyCString(AMXOParser::OdlConfig_str(AMXOParser::COPT_CFG_DIR), AMXOParser::OdlConfig_str(AMXOParser::CVAL_PLUGIN_DIR));
    container.addNewKeyAmxcLlist(AMXOParser::OdlConfig_str(AMXOParser::COPT_LIBDIRS), nullptr);
    container.addNewKeyAmxcLlist(AMXOParser::OdlConfig_str(AMXOParser::COPT_INCDIRS), nullptr);
    container.addNewKeyAmxcLlist(AMXOParser::OdlConfig_str(AMXOParser::COPT_MIBDIRS), nullptr);
    container.addNewKeyAmxcLlist(AMXOParser::OdlConfig_str(AMXOParser::COPT_LISTEN), nullptr);
    container.addNewKeyBool(AMXOParser::OdlConfig_str(AMXOParser::COPT_EVENT), false);
    container.addNewKeyBool(AMXOParser::OdlConfig_str(AMXOParser::COPT_DUMP_CONFIG), false);
    container.addNewKeyCString(AMXOParser::OdlConfig_str(AMXOParser::COPT_BACKENDS_DIR), AMXOParser::OdlConfig_str(AMXOParser::CVAL_BACKENDS_DIR));
    container.addNewKeyCString(AMXOParser::OdlConfig_str(AMXOParser::COPT_STORAGE_TYPE), AMXOParser::OdlConfig_str(AMXOParser::CVAL_STORAGE_TYPE));
    container.addNewKeyBool(AMXOParser::OdlConfig_str(AMXOParser::COPT_LOG), false);
    std::string rw_path("${prefix}");
    rw_path+= AMXOParser::OdlConfig_str(AMXOParser::CVAL_RWDATAPATH);
    container.addNewKeyCString(AMXOParser::OdlConfig_str(AMXOParser::COPT_RW_DATA_PATH), rw_path.c_str());
    container.addNewKeyCString(AMXOParser::OdlConfig_str(AMXOParser::COPT_STORAGE_DIR), "${rw_data_path}/${name}/");
    container.addNewKeyAmxcLlist(AMXOParser::OdlConfig_str(AMXOParser::COPT_REQUIRES), nullptr);
    container.addNewKeyBool(AMXOParser::OdlConfig_str(AMXOParser::CVAL_LOAD), true);
    (void)amxrt_hooks;
    context_dm = getDatamodel();
    context_cmds =  getCmdOptions().get();
    // set hooks to monitor config option changes
    //todo :  FIX HOOKS
amxo_parser_set_hooks(AMXOParser::getParser(), &amxrt_hooks);
//    // command line options given with -F are stored here and can not be overwritten
//    // by odl config section options
    amxc_var_init(cmd_options.get());
    amxc_var_set_type(cmd_options.get(), AMXC_VAR_ID_HTABLE);
}


std::shared_ptr<amxc_var_t> AMXOConfig::getCmdOptions()
{
    return cmd_options;
}

inline void AMXOConfig::setCmdOptions(const std::shared_ptr<amxc_var_t> &newCmd_options)
{
    cmd_options = newCmd_options;
}

void AMXOConfig::configClean() {
    // Fill with the original code here
    // base_name.c_str() can be used instead of char* base_name
}

void AMXOConfig::configAddOption(std::string name, amxc_var_t* value) {
    // Fill with the original code here
    // name.c_str() can be used instead of const char* name
}
