#!/bin/bash 

# In order to use the script in non interactive mode, 
# enter first argument to be the repo name, one of the following: 'framework', 'common', 'controller', 'agent'

#set -x

echo kwcheck --version
echo current folder: `pwd`
echo number of input arguments: "$#"

declare -a REPOS=("framework" "common" "controller" "agent")

# set an initial value for the flag
PASSIVE_MODE=false

# read the options
OPTS=`getopt -o p -n 'kw.sh' -- "$@"`
eval set -- "$OPTS"

# extract options and their arguments into variables.
while true ; do
      case "$1" in
            "") break ;;
            -p) PASSIVE_MODE=true; shift; break ;;
            * ) break ;;
      esac   
done

PASSIVE_MODE_OPT=""
if $PASSIVE_MODE ; then
      PASSIVE_MODE_OPT="-f PASSIVE_MODE=ON"
      echo "PASSIVE_MODE=ON"
else
      echo "PASSIVE_MODE=OFF"
fi

################################################################
####################### Local Functions ########################
################################################################

kw()
{ 
echo Performing KW on: $REPO.

# Generate input script to klocwork checker
rm -rf _GO_KW
cat  > _GO_KW << DONE
#!/bin/bash
cd `pwd`/../../$REPO
echo "starting kw from folder: \`pwd\`"
echo "../tools/maptools.sh build $REPO $PASSIVE_MODE_OPT -c clean make"
../tools/maptools.sh build $REPO $PASSIVE_MODE_OPT -c clean make
exit
DONE

# Create a klocwork project based on the feeds compilation
rm -rf .kw*/
kwcheck create
chmod +x _GO_KW
kwshell -s ./_GO_KW

# Add checkers/overrides that are used by UGW for SDL
git archive --remote=ssh://git@gts-chd.intel.com:29418/sw_ugw/ugw_sw.git HEAD:kw_support/ kw_override.h | tar -x
git archive --remote=ssh://git@gts-chd.intel.com:29418/sw_ugw/ugw_sw.git HEAD:kw_support/ klocwork_database.kb | tar -x
git archive --remote=ssh://git@gts-chd.intel.com:29418/sw_ugw/ugw_sw.git HEAD:kw_support/ analysis_profile.pconf | tar -x
kwcheck import kw_override.h
kwcheck import klocwork_database.kb
kwcheck import analysis_profile.pconf

# Analyze and generate reports
ROOT_PATH=$(realpath `pwd`/../../)
REPO_PATH=$(realpath `pwd`/../../$REPO)
declare TOOLCHAIN_PATH
if $PASSIVE_MODE; then
      TOOLCHAIN_PATH=$(realpath `pwd`/../../../../atom_rdkbos/build/tmp/work/core2-32-rdk-linux)
else 
      TOOLCHAIN_PATH=$(grep -Po "(?<=^PLATFORM_BASE_DIR=).*" $(realpath `pwd`/../../external_toolchain.cfg))
fi

REPORT_PATH=$REPO_PATH/kw_reports
mkdir -p $REPORT_PATH
kwcheck run -j auto
echo ""
echo Generating reports...
kwcheck list -F detailed --status 'Analyze','Fix' --report ${REPORT_PATH}/kwreport_all.log
kwcheck list -F detailed --severity 1 --status 'Analyze','Fix' --report ${REPORT_PATH}/kwreport_critical.log
kwcheck list -F detailed --severity 2 --status 'Analyze','Fix' --report ${REPORT_PATH}/kwreport_error.log
kwcheck list -F detailed --severity 3 --status 'Analyze','Fix' --report ${REPORT_PATH}/kwreport_warning.log
kwcheck list -F detailed --severity 4 --status 'Analyze','Fix' --report ${REPORT_PATH}/kwreport_review.log

# finalize reports
# remove local prefixes from source controlled reports
declare -a KW_REPORTS=(${REPORT_PATH}/kwreport_all.log ${REPORT_PATH}/kwreport_critical.log ${REPORT_PATH}/kwreport_error.log ${REPORT_PATH}/kwreport_warning.log ${REPORT_PATH}/kwreport_review.log)
for r in ${KW_REPORTS[@]}; do
      cp $r ${r}.tmp
      sed -i -e "s/${ROOT_PATH////\\/}\///g" $r # remove local path prefixes from multiap modules
      sed -i -e "s/${TOOLCHAIN_PATH////\\/}\///g" $r # remove local path prefixes from external toolchain files
done

# Generate output summary
declare -a KW_TYPES=("1:Critical" "2:Error" "3:Warning" "4:Review")

echo -e "Summary by components:" > ${REPORT_PATH}/kwreport_summary.log
cp ${REPORT_PATH}/kwreport_all.log ${REPORT_PATH}/kwreport_tmp.log
for t in ${KW_TYPES[@]}; do
      issue_cnt=`grep -c $t ${REPORT_PATH}/kwreport_all.log`
      echo "    $t: $issue_cnt" >> ${REPORT_PATH}/kwreport_summary.log
done
rm ${REPORT_PATH}/kwreport_tmp.log
echo -e "\nLast KW: `date +'%d/%m/%Y %H:%M'`" >> ${REPORT_PATH}/kwreport_summary.log

echo ""

}

################################################################
####################### Script begining ########################
################################################################

# Repo Select
read -p "On which repo do you with to perfrom klocwork? [1-framework, 2-common, 3-controller, 4-agent, 5-all]: " REPO
case $REPO in
      "1") REPO="framework"    ;;
      "2") REPO="common"       ;;
      "3") REPO="controller"   ;;
      "4") REPO="agent"        ;;
      "5") REPO="all"          ;;
      *)   
            echo "Error: unrecognized input value:'$REPO'" 
            exit 128 # Invalid argument to exit
            ;;
esac

if [ "$REPO" == "all" ]; then
      echo "Performing KW on all repos!" 
      for REPO in ${REPOS[@]}; do
            kw
      done
else
      kw
fi

echo DONE!



