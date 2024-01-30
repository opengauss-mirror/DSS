#!/bin/bash
#
# Copyright (C), 2022-2038, Huawei Tech. Co., Ltd.
# File Name         : dss_clear.sh
# Description       : clear dss
#

curr_path=$(dirname $(readlink -f $0))
curr_filename=$(basename $(readlink -f $0))
os_user=$(whoami)
file_user=$(ls -l ${curr_path}"/${curr_filename}" | awk '{print $3}')

if [ ${file_user} != ${os_user} ]; then
    echo "Can't run ${curr_filename}, because it does not belong to the current user!"
    exit 1
fi

usage()
{
    echo "Usage: $0 [DSS_HOME]"
    echo "DSS_HOME:"
    echo "    dssserver data path"
}

if [ $# -lt 1 ]
then
    echo "parameter numbers not meet, num=$#."
    usage
    exit 1
fi

log()
{
    time=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$time][DSS]$1"
}

assert_nonempty()
{
    if [[ -z ${2} ]]
    then
        log "[SCRIPT]The ${1} parameter is empty."
        exit 1
    fi
}

assert_nonempty 1 ${1}
export DSS_HOME=${1}

function check_dss_config()
{
    log "[UNREG]Checking dss_inst.ini before unreg"
    if [[ ! -e ${DSS_HOME}/cfg/dss_inst.ini ]]
    then
        log "[UNREG]${DSS_HOME}/cfg/dss_inst.ini must exist"
        exit 1
    fi

    log "[UNREG]Checking dss_vg_conf.ini before unreg"
    if [[ ! -e ${DSS_HOME}/cfg/dss_vg_conf.ini ]]
    then
        log "[UNREG]${DSS_HOME}/cfg/dss_vg_conf.ini must exist"
        exit 1
    fi
}

function unregister()
{
    LOCAL_INSTANCE_ID=$(awk '/INST_ID/{print}' ${DSS_HOME}/cfg/dss_inst.ini | awk -F= '{print $2}' | xargs)
    if [[ -z ${LOCAL_INSTANCE_ID} ]]
    then
        log "[UNREG]can't find inst id. Aborting."
        exit 1
    fi

    log "[UNREG] Start unreg."
        dsscmd unreghl -t 0 -D ${DSS_HOME} >> /dev/null 2>&1  
    log "[UNREG] Unreg success."
}

check_dss_config
unregister
