/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * DSS is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * dss_shm_hashmap.c
 *
 *
 * IDENTIFICATION
 *    src/common/dss_shm_hashmap.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_shm_hashmap.h"
#include "dss_errno.h"

// clang-format off
static uint32 const shm_primes[] = {
    7,
    13,
    31,
    61,
    127,
    251,
    509,
    1021,
    2039,
    4093,
    8191,
    16381,
    32749,
    65521,
    131071,
    262139,
    524287,
    1048573,
    1048583,
    2097143,
    4194301,
    8388593,
    16777213,
    33554393,
    67108859,
    134217689,
    268435399,
    536870909,
    1073741789,
    2147483647,
    0xfffffffb
};

// clang-format on
static uint32 shm_oamap_get_near_prime(unsigned long n)
{
    uint32 low = 0;
    uint32 cnt = (uint32)(sizeof(shm_primes) / sizeof(uint32));
    uint32 high = cnt;

    while (low != high) {
        unsigned int mid = low + (high - low) / 2;
        if (n > shm_primes[mid]) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }

    if (low < cnt) {
        return shm_primes[low];
    } else {
        return (uint32)n;
    }
}

int32 shm_hashmap_init(shm_hashmap_t *map, uint32 init_bucket_capacity, uint32 id, cm_oamap_compare_t compare_func)
{
    uint64 size;
    void *addr = NULL;
    uint32 shm_key;

    if (map == NULL) {
        LOG_DEBUG_ERR("Null pointer specified");
        return ERR_DSS_INVALID_PARAM;
    }
    map->num = shm_oamap_get_near_prime(init_bucket_capacity);
    if (map->num >= MAX_OAMAP_BUCKET_NUM) {
        LOG_DEBUG_ERR("Invalid bucket num specified");
        return ERR_DSS_INVALID_PARAM;
    }

    size = map->num * (uint32)sizeof(shm_hashmap_bucket_t);
    map->not_extend = 1;
    addr = cm_get_shm(SHM_TYPE_HASH, id, size, CM_SHM_ATTACH_RW);
    if (addr == NULL) {
        LOG_DEBUG_ERR("db_get_shm failed");
        return ERR_ALLOC_MEMORY;
    }
    shm_key = cm_shm_key_of(SHM_TYPE_HASH, id);

    map->buckets = cm_trans_shm_offset(shm_key, addr);
    map->shm_id = id;
    map->func = compare_func;

    errno_t err = memset_s(addr, size, 0, size);
    if (err != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void shm_hashmap_destroy(shm_hashmap_t *map, uint32 id)
{
    CM_ASSERT(map != NULL);
    map->num = 0;

    if (map->buckets != SHM_INVALID_ADDR) {
        (void)cm_del_shm(SHM_TYPE_HASH, id);
        map->buckets = SHM_INVALID_ADDR;
    }
}
