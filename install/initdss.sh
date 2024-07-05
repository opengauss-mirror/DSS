#!/bin/bash
#
# Copyright (C), 2022-2038, Huawei Tech. Co., Ltd.
# File Name         : init_dss.sh
# Description       : init dss
#
set -e

declare    VG_COUNT=0
declare -a VG_NAME
declare -a VOLUMN_NAME

curr_path=$(dirname $(readlink -f $0))
curr_filename=$(basename $(readlink -f $0))
os_user=$(whoami)
file_user=$(ls -l ${curr_path}"/${curr_filename}" | awk '{print $3}')

if [ ${file_user} != ${os_user} ]; then
    echo "Can't run ${curr_filename}, because it does not belong to the current user!"
    exit 1
fi

source $(dirname $0)/common_func.sh

usage()
{
    echo "Usage: $0 [local_datadir]"
    echo "local_datadir:"
    echo "    local datadir"
}

if [[ $# -ne 1 ]]
then
    log "parameter numbers not meet, num=$#."
    usage
    exit 255
fi

#variables
assert_nonempty 1 ${1}
LOCAL_DATADIR=$1

check_dss_config()
{
    log "Checking dss_inst.ini before start dss..."
    if [[ ! -e ${LOCAL_DATADIR}/cfg/dss_inst.ini ]]
    then
        log "${LOCAL_DATADIR}/cfg/dss_inst.ini must exist"
        exit 255
    fi

    log "Checking dss_vg_conf.ini before start dss..."
    if [[ ! -e ${LOCAL_DATADIR}/cfg/dss_vg_conf.ini ]]
    then
        log "${LOCAL_DATADIR}/cfg/dss_vg_conf.ini must exist"
        exit 255
    fi
}

get_vg_data()
{
    FILE_NAME=${LOCAL_DATADIR}/cfg/dss_vg_conf.ini
    while read line
    do
        echo  $line >>/dev/null
        if [[ $? == 0 ]] ;then
            let VG_COUNT++
            VG_NAME[$VG_COUNT]=$(echo $line | awk -F ":" '{print $1}')
            VOLUME_NAME[$VG_COUNT]=$(echo $line | awk -F ":" '{print $2}')
        fi
   done <$FILE_NAME
}

create_vg()
{
    export DSS_HOME=${LOCAL_DATADIR}
    for((i=1;i<=${VG_COUNT};i++))
    do  
        echo "> creating volume group ${VG_NAME[$i]}"
        chmod 600 ${VOLUME_NAME[$i]}
        dd if=/dev/zero bs=2048 count=1000 of=${VOLUME_NAME[$i]}
        dsscmd cv -g ${VG_NAME[$i]} -v ${VOLUME_NAME[$i]} -D ${LOCAL_DATADIR} >> /dev/null 2>&1
    done
}

check_dss_config
get_vg_data
create_vg
echo "initdss success."
exit 0
