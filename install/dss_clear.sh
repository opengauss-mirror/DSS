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
    echo "Usage: $0 [DSS_HOME] [type]"
    echo "DSS_HOME:"
    echo "    dssserver data path"
    echo "type:"
    echo "    if type is NULL, default value is unregister"
    echo "    -clearVg: Clearing and Recreating Vg base on your backup information"
    echo "        Usage: $0 [DSS_HOME] -clearVg [backup_file] [except_vg_name]"
    echo "        backup_file:"
    echo "            backup information file path, get backup_file from dsscmd lsvg -t d"
    echo "        except_vg_name:"
    echo "            --except_vg_name=xxx, xxx is vg name which you do not want to clear"
    echo "            if you want to clear all vg, just do not put the param"
}

if [ $# -lt 1 ]
then
    echo "parameter numbers not meet, num=$#."
    usage
    exit 1
fi

assert_nonempty()
{
    if [[ -z "${2}" ]]
    then
        echo "[SCRIPT]The ${1} parameter is empty."
        exit 1
    fi
}

assert_nonempty 1 ${1}
export DSS_HOME=${1}
CMD=${2}
clear_dss_log=${DSS_HOME}/clear_dss.log

log()
{
    time=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$time][DSS]$1"
    echo "[$time][DSS]$1" >> ${clear_dss_log} 2>&1
}

function check_dss_config()
{
    log "Checking dss_inst.ini before dss clear"
    if [[ ! -e ${DSS_HOME}/cfg/dss_inst.ini ]]
    then
        log "${DSS_HOME}/cfg/dss_inst.ini must exist"
        exit 1
    fi

    log "Checking dss_vg_conf.ini before dss clear"
    if [[ ! -e ${DSS_HOME}/cfg/dss_vg_conf.ini ]]
    then
        log "${DSS_HOME}/cfg/dss_vg_conf.ini must exist"
        exit 1
    fi
}

create_log_directory()
{
    log_directory=$1
    if [ ! -d "$log_directory" ]
    then
        mkdir -p $log_directory
        chmod 700 $log_directory
    fi
}

touch_logfile()
{
    log_file=$1
    if [ ! -f "$log_file" ]
    then
        touch $log_file
        chmod 600 $log_file
    fi
}

get_clear_dss_log()
{
    LOG_HOME=$(cat ${DSS_HOME}/cfg/dss_inst.ini | sed s/[[:space:]]//g | grep -Eo "^LOG_HOME=.*" | awk -F '=' '{ print $2 }')
    if [[ ! -z "${LOG_HOME}" ]]
    then
        create_log_directory ${LOG_HOME}
        clear_dss_log=${LOG_HOME}/clear_dss.log
        touch_logfile $clear_dss_log
    else
        if [[ ! -d "${DSS_HOME}" ]]
        then
            clear_dss_log=/dev/null
        else
            touch_logfile $clear_dss_log
        fi
    fi
}

function parse_vg_info()
{
    vg_flag=0
    volume_count=0
    p_vg_volume_index=0
    while read line
    do
        if [[ "$line" == *volume_name:* ]]; then
            if [[ "$volume_count" == "0" ]] || [[ "$vg_flag" != "2" ]]; then
                log "[CLEARVG]Invalid vg info file!"
                exit 1
            fi
            volume_name=${line:12}
            VOLUME_NAME[$p_vg_volume_index]=$volume_name
            let volume_count--
            let p_vg_volume_index++
            if [[ "$volume_count" == "0" ]]; then
                let VG_COUNT++
                vg_flag=0
            fi
        elif [[ "$line" == *vg_name:* ]]; then
            if [[ "$volume_count" != "0" ]] || [[ "$vg_flag" != "0" ]]; then
                log "[CLEARVG]Invalid vg info file!"
                exit 1
            fi
            vg_name=${line:8}
            let vg_flag++
            volume_count=0
            VG_NAME[$VG_COUNT]=$vg_name
            continue
        elif [[ "$line" == *volume_count:* ]]; then
            if [[ "$volume_count" != "0" ]] || [[ "$vg_flag" != "1" ]]; then
                log "[CLEARVG]Invalid vg info file!"
                exit 1
            fi
            let vg_flag++
            volume_count=${line:13}
            VOLUME_COUNT[$VG_COUNT]=$volume_count
        fi
    done <$VG_INFO_FILE

    if [[ "$p_vg_volume_index" == "0" ]]; then
        log "[CLEARVG]Invalid vg info file, volume count is 0!"
        exit 1
    elif [[ "$vg_flag" != "0" ]]; then
        log "[CLEARVG]Invalid vg info file!"
        exit 1
    fi
}

function check_except_param()
{
    except_param=$1
    if [[ "$except_param" == --except_vg_name=* ]]; then
        EXCEPT=${except_param:17}
        log "[CLEARVG]except_vg_name is $EXCEPT"
    elif [[ -z "$except_param" ]]; then
        log "[CLEARVG]except_vg_name is NULL"
    else
        log "[CLEARVG]Invalid except_vg_name parameter!"
        exit 1
    fi
    except_flag=0
    for ((i=0; i<$VG_COUNT; i++)); do
        if [[ ${VG_NAME["$i"]} == "$EXCEPT" ]]; then
            if [[ "$except_flag" == "1" ]]; then
                log "[CLEARVG]Except_vg_name match two vg, please check parameter or backup file!"
                exit 1
            fi
            let except_flag++
            continue
        fi
    done
    if [[ ! -z "$except_param" ]] && [[ "$except_flag" == "0" ]]; then
        log "[CLEARVG]Invalid except_vg_name parameter, not match vg name"
        exit 1
    fi
}

function clear_vg()
{
    if [ $# -ne 4 ] && [ $# -ne 3 ]
    then
        log "[CLEARVG]-clearVg parameter numbers not meet 3 or 4, num=$#."
        usage
        exit 1
    fi
    declare -a VG_NAME
    declare -a VOLUME_COUNT
    declare -a VOLUME_NAME
    assert_nonempty 3 ${3}
    VG_COUNT=0
    VG_INFO_FILE=$3
    CLEAR_VG_EXCEPT=$4
    parse_vg_info
    volume_index=0
    check_except_param $4
    for ((i=0; i<$VG_COUNT; i++)); do
        if [[ ${VG_NAME["$i"]} == "$CLEAR_VG_EXCEPT" ]]; then
            log "[CLEARVG]except_vg_name, skip clear Vg:${VG_NAME[$i]}, volume count:${VOLUME_COUNT[$i]}"
            volume_index=$(($volume_index+${VOLUME_COUNT[$i]}))
            continue
        fi
        log "[CLEARVG]Begin to clear Vg ${VG_NAME[$i]}, ${VOLUME_COUNT[$i]}"
        for ((j=0; j<${VOLUME_COUNT[$i]}; j++)); do
            log "[CLEARVG]Begin to clear volume is ${VOLUME_NAME[$volume_index]}"
            if [[ "$j" == "0" ]]; then
                log "[CLEARVG]Clear vg:${VG_NAME[$i]}, volume:${VOLUME_NAME[$volume_index]}, index:$j"
                dd if=/dev/zero of=${VOLUME_NAME[$volume_index]} bs=512 count=1 seek=0 conv=notrunc
                log "[CLEARVG]dsscmd create vg:${VG_NAME[$i]} volume:${VOLUME_NAME[$volume_index]}, home:$DSS_HOME"
                dsscmd cv -g ${VG_NAME[$i]} -v ${VOLUME_NAME[$volume_index]} -D $DSS_HOME
                let volume_index++
                continue
            fi
            log "[CLEARVG]Clear vg:${VG_NAME[$i]}, volume:${VOLUME_NAME[$volume_index]}, index:$j"
            dd if=/dev/zero of=${VOLUME_NAME[$volume_index]} bs=512 count=1 seek=0 conv=notrunc
            log "[CLEARVG]dsscmd add volume vg:${VG_NAME[$i]} volume:${VOLUME_NAME[$volume_index]}"
            expect << EOF
            set timeout -1
            spawn dsscmd adv -g ${VG_NAME[$i]} -v ${VOLUME_NAME[$volume_index]} -f
            expect {
            "Please ensure that the cluster is stopped, enter yes*" { send "yes\r"; exp_continue }
            }
            expect eof
            exit
EOF
            let volume_index++
            continue
        done
    done
    log "[CLEARVG]Success to clear Vg"
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

function Main()
{
    get_clear_dss_log
    check_dss_config
    if [ "$CMD" == "-clearVg" ]; then
        clear_vg "$@"
        exit 0
    else
        unregister
        exit 0
    fi
}

Main "$@"