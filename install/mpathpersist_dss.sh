#!/bin/bash
#
# Copyright (C), 2025-2025, Huawei Tech, Co., Ltd.
# File Name       : mpathpersist_dss.sh
# Description     : reg/unreg/kick
#
set -e

function checkDir() {
    local dir=$1
    for (( i=0; i<${#dir}; i++)); do
        char="${dir:$i:1}"
        if ! [[ "$char" =~ ^[0-9a-zA-Z] ]]; then
            if [ "$char" != "-" ]&&[ "$char" != "_" ]&&[ "$char" != "." ]&&[ "$char" != "/" ]; then
                echo "command failed,dir error:$dir"
                exit 1
            fi
        fi
    done
}

function checkDev() {
    local dev_prefix=$(echo $1 | awk '{print substr($0, 1, 9)}')
    if [ "$dev_prefix" != "--device=" ]; then
        echo "command failed,parameter dev error dev_prefix:$dev_prefix"
        exit 1
    fi
    local dev=$(echo $1|awk -F '=' '{print $2}')
    if [ ${#dev} -gt 63 ]; then
        echo "command failed,parameter too long:$dev"
        exit 1
    fi
    checkDir $dev
}

function checkRkSark() {
    local number=$1
    if (( number <= 0 || number >= 256 )); then
        echo "command failed,parameter error : $number"
        exit 1
    fi
}

function checkRk() {
    local rk_prefix=$(echo $1|awk -F '=' '{print $1}')
    local rk_number=$(echo $1|awk -F '=' '{print $2}')
    if [ "$rk_prefix" != "--param-rk" ]; then
        echo "command failed,reserve parameter error:$rk_prefix"
        exit 1
    fi
    checkRkSark $rk_number
}

function checkSark() {
    local sark_prefix=$(echo $1|awk -F '=' '{print $1}')
    local sark_number=$(echo $1|awk -F '=' '{print $2}')
    if [ "$sark_prefix" != "--param-sark" ]; then
        echo "command failed,preempt parameter error:$sark_prefix"
        exit 1
    fi
    checkRkSark $sark_number
}

function checkProutType() {
    local pt_prefix=$(echo $1|awk -F '=' '{print $1}')
    local pt_number=$(echo $1|awk -F '=' '{print $2}')
    if [ "$pt_prefix" != "--prout-type" ]; then
        echo "command failed,parameter error:$pt_prefix"
        exit 1
    fi
    if (( pt_number < 1 || pt_number > 8 )); then
        echo "command failed,parameter error:$pt_number"
        exit 1
    fi
}

function checkRegParam() {
    local prefix=$(echo $1|awk -F '=' '{print $1}')
    local number=$(echo $1|awk -F '=' '{print $2}')
    if [ "$prefix" != "--param-sark" ]&&[ "$prefix" != "--param-rk" ]; then
        echo "command failed,reg parameter error prefix:$prefix"
        exit 1
    fi
    checkRkSark $number
}

function checkResvParam() {
    checkRk $1
    checkProutType $2
}

function checkPreemptParam() {
    checkRk $1
    checkSark $2
    checkProutType $3
}

function checkParam() {
    local out=$1
    local cmd=$2
    local dev=$3
    local param_all=$@
    if [ "$out" != "--out" ]&&[ "$out" != "--in" ]; then
        echo "command failed,parameter error:$out"
        exit 1
    fi
    checkDev $dev
    if [ "$cmd" = "--register" ]; then
        if [ $# -ne 4 ]; then
            echo "command failed,parameter number error:$param_all"
            exit 1
        fi
        checkRegParam $4
    elif [ "$cmd" = "--reserve" ]; then
        if [ $# -ne 5 ]; then
            echo "command failed,parameter number error:$param_all"
            exit 1
        fi
        checkResvParam $4 $5
    elif [ "$cmd" = "--preempt" ]; then
        if [ $# -ne 6 ]; then
            echo "command failed,parameter number error:$param_all"
            exit 1
        fi
        checkPreemptParam $4 $5 $6
    elif [ "$cmd" = "--read-keys" ]; then
        if [ $# -ne 3 ]; then
            echo "command failed,parameter number error:$param_all"
            exit 1
        fi
    else
        echo "command failed,cmd type error:$param_all"
        exit 1
    fi
}

function skipLink() {
    local dev=$1
    while true
    do
        link_type=$(stat -c %F $dev)
        if [ "link_type" != "symbolic link" ]; then
            echo "$dev"
            exit
        fi
        real_path=$(readlink -f "$dev")
        dev=$real_path
    done
}

log()
{
    time=$(date "+%Y-%m-%d %H:%M:%S)
    echo "[$time][DSS]$1" >> ${mpathpersist_dss_log} 2>&1
}
touch_logfile()
{
    log_file=$1
    if [ ! -f "$log_file" ]
    then
        touch $log_file
        chmod 600 $log_file
        chown $SUDO_USER: $log_file
    fi
}
get_mpathpersist_dss_log()
{
    if [[ ! -z "${LOG_HOME}" ]]
    then
        if [ "$SUDO_USER" != "$(stat -c %U $LOG_HOME)" ]; then
            echo "command failed,log home user not match:$LOG_HOME"
            exit 1
        fi
        mpathpersist_dss_log=${LOG_HOME}/mpathpersist_dss.log
        touch_logfile $mpathpersist_dss_log
    else
        echo "command failed,log home not exist:$LOG_HOME"
        exit 1
    fi
}

function main() {
    LOG_HOME=$1
    shift 1
    if [ ${#LOG_HOME} -gt 188 ]; then
        echo "command failed,parameter too long:$LOG_HOME"
        exit 1
    fi
    checkDir $LOG_HOME
    get_mpathpersist_dss_log
    local mpathpersist_param=$*
    log "mpathpersist_dss.sh $LOG_HOME $mpathpersist_param"
    checkParam $mpathpersist_param
    local dev_prefix=$(echo $3 | awk '{print substr($0, 1, 9)}')
    if [ "$dev_prefix" != "--device=" ]; then
        echo "command failed,parameter error:$3"
        echo "dev_prefix:$dev_prefix"
        exit 1
    fi
    local dev=$(echo $3 | awk -F '=' '{print $2}')
    dev=$(skipLink $dev)
    dev_owner=$(stat -c %U $dev)
    if [ -n "$SUDO_USER" ]; then
        if [ "$SUDO_USER" = "$dev_owner" ]; then
            mpathpersist $mpathpersist_param
        else
            echo "command failed,user not match,sudo user:$SUDO_USER,dev_owner:$dev_owner"
            exit 1
        fi
    else
        echo "command failed,need to be sudo,exit 1"
        exit 1
    fi
}

main "$@"
