#!/bin/bash
#
# Copyright (C), 2022-2038, Huawei Tech. Co., Ltd.
# File Name         : common_func.sh
# Description       : common function
#
set -e

curr_path=$(dirname $(readlink -f $0))
curr_filename=$(basename $(readlink -f $0))
os_user=$(whoami)
file_user=$(ls -l ${curr_path}"/${curr_filename}" | awk '{print $3}')

if [ ${file_user} != ${os_user} ]; then
    echo "Can't run ${curr_filename}, because it does not belong to the current user!"
    exit 1
fi

log()
{
    time=$(date "+%Y-%m-%d %H:%M:%S")
    echo "$time $1"
}

assert_empty()
{
    return
}

assert_nonempty()
{
    if [[ -z ${2} ]]
    then
        log "The ${1} parameter is empty."
        exit 1
    fi
}

dssserver_pid()
{
    pid=$(ps -f f -u \`whoami\` | grep -v grep | grep "dssserver "| grep ${1}$ | awk '{print $2}')
    echo ${pid}
}

kill_program()
{
    assert_nonempty 1 ${1}
    pid=$(dssserver_pid $1)
    if [[ -z ${pid} ]]
    then
        log "dssserver is already dead."
        return
    fi

    kill -9 ${pid}   
    sleep 3
    ps -f -p "${pid}" | grep dssserver
    if [ $? = 0 ]
    then
        log "ERROR! dssserver with pid:${pid} is not killed..."
        exit 0
    fi
}

check_dss_start()
{
    started=0
    for (( i=1; i<30; i++ ))
    do
        pid=$(dssserver_pid ${1})
        if [[ ! -z ${pid} ]]
        then
            started=1
            break
        fi
        sleep 1
    done

    if [[ ${started} -eq 0 ]]
    then
        log "ERROR! start dssserver in dir ${1} failed"
        exit 1
    fi
}

function clear_script_log()
{
    local _log_dir=$1
    local _log_name=$2
    local _max_log_backup=$3

    if [ -L ${_log_dir} ]; then
        typeset log_num=$(find -L "${_log_dir}" -maxdepth 1 -type f -name "${_log_name}*" | wc -l)
        if [ ${log_num} -ge ${_max_log_backup} ];then
            find -L "${_log_dir}" -maxdepth 1 -type f -name "${_log_name}*" | xargs ls -t {} 2>/dev/null | tail -n $(expr ${log_num} - ${_max_log_backup}) | xargs -i rm -f {}
        fi
    else
        typeset log_num=$(find "${_log_dir}" -maxdepth 1 -type f -name "${_log_name}*" | wc -l)
        if [ ${log_num} -ge ${_max_log_backup} ];then
            find "${_log_dir}" -maxdepth 1 -type f -name "${_log_name}*" | xargs ls -t {} 2>/dev/null | tail -n $(expr ${log_num} - ${_max_log_backup}) | xargs -i rm -f {}
        fi
    fi
}

check_log_file()
{
    log_path=$1
    log_file=$2
    operation=$3
    # max log file size 16 * 1024 * 1024
    MAX_LOG_SIZE=16777216
    MAX_LOG_BACKUP=10
    log_file_size=$(ls -l ${log_file} |awk '{print $5}')
    if [ -f ${log_file} ];then
        if [ ${log_file_size} -ge ${MAX_LOG_SIZE} ];then
            mv -f ${log_file} "${log_path}/${operation}-$(date +%Y-%m-%d_%H%M%S).log" 2>/dev/null
            clear_script_log "${log_path}" "${operation}-" $MAX_LOG_BACKUP
        fi
    fi
}

touch_logfile()
{
    log_file=$1
    if [ ! -f "$log_file" ]
    then
        touch "$log_file"
    fi
}
