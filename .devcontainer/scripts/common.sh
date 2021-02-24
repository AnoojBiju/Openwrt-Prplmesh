#!/usr/bin/env bash

# Codespaces themes - partly inspired by https://github.com/ohmyzsh/ohmyzsh/blob/master/themes/robbyrussell.zsh-theme
CODESPACES_BASH="$(cat \
<<EOF
#!/usr/bin/env bash
prompt() {
    if [ "\$?" != "0" ]; then
        local arrow_color=\${bold_red}
    else
        local arrow_color=\${reset_color}
    fi
    if [ ! -z "\${GITHUB_USER}" ]; then
        local USERNAME="@\${GITHUB_USER}"
    else
        local USERNAME="\\u"
    fi
    local cwd="\$(pwd | sed "s|^\${HOME}|~|")"
    PS1="\${green}\${USERNAME} \${arrow_color}➜\${reset_color} \${bold_blue}\${cwd}\${reset_color} \$(scm_prompt_info)\${white}$ \${reset_color}"
    
    # Prepend Python virtual env version to prompt
    if [[ -n \$VIRTUAL_ENV ]]; then
        if [ -z "\${VIRTUAL_ENV_DISABLE_PROMPT:-}" ]; then
            PS1="(\`basename \"\$VIRTUAL_ENV\"\`) \${PS1:-}"
        fi
    fi
}
SCM_THEME_PROMPT_PREFIX="\${reset_color}\${cyan}(\${bold_red}"
SCM_THEME_PROMPT_SUFFIX="\${reset_color} "
SCM_THEME_PROMPT_DIRTY=" \${bold_yellow}✗\${reset_color}\${cyan})"
SCM_THEME_PROMPT_CLEAN="\${reset_color}\${cyan})"
SCM_GIT_SHOW_MINIMAL_INFO="true"
safe_append_prompt_command prompt
EOF
)"

# Adapted Oh My Zsh! install step to work with both "Oh Mys" rather than relying on an installer script
# See https://github.com/ohmyzsh/ohmyzsh/blob/master/tools/install.sh for offical script.
install-oh-my()
{
    local OH_MY=$1
    local OH_MY_INSTALL_DIR="${USER_RC_PATH}/.oh-my-${OH_MY}"
    local TEMPLATE="${OH_MY_INSTALL_DIR}/templates/$2"
    local OH_MY_GIT_URL=$3
    local USER_RC_FILE="${USER_RC_PATH}/.${OH_MY}rc"

    if [ -d "${OH_MY_INSTALL_DIR}" ] || [ "${INSTALL_OH_MYS}" != "true" ]; then
        return 0
    fi

    umask g-w,o-w
    mkdir -p "${OH_MY_INSTALL_DIR}"
    git clone --depth=1 \
        -c core.eol=lf \
        -c core.autocrlf=false \
        -c fsck.zeroPaddedFilemode=ignore \
        -c fetch.fsck.zeroPaddedFilemode=ignore \
        -c receive.fsck.zeroPaddedFilemode=ignore \
        "${OH_MY_GIT_URL}" "${OH_MY_INSTALL_DIR}" 2>&1
    echo -e "$(cat "${TEMPLATE}")\nDISABLE_AUTO_UPDATE=true\nDISABLE_UPDATE_PROMPT=true" > "${USER_RC_FILE}"
    if [ "${OH_MY}" = "bash" ]; then
        sed -i -e 's/OSH_THEME=.*/OSH_THEME="codespaces"/g' "${USER_RC_FILE}"
        mkdir -p "${OH_MY_INSTALL_DIR}/custom/themes/codespaces"
        echo "${CODESPACES_BASH}" > "${OH_MY_INSTALL_DIR}/custom/themes/codespaces/codespaces.theme.sh"
    else
        echo "Only bash shell is supported by this script!"
        exit 1
    fi
    # Shrink git while still enabling updates
    cd "${OH_MY_INSTALL_DIR}" || (echo "cd ${OH_MY_INSTALL_DIR} failed!"; exit 1)
    git repack -a -d -f --depth=1 --window=1

    if [ "${USERNAME}" != "root" ]; then
        cp -rf "${USER_RC_FILE}" "${OH_MY_INSTALL_DIR}" /root
        chown -R "${USERNAME}:${USERNAME}" "${USER_RC_PATH}"
    fi
}

USERNAME="root"
INSTALL_OH_MYS="true"

# ** Shell customization section **
if [ "${USERNAME}" = "root" ]; then 
    USER_RC_PATH="/root"
else
    USER_RC_PATH="/home/${USERNAME}"
fi

install-oh-my bash bashrc.osh-template https://github.com/ohmybash/oh-my-bash
