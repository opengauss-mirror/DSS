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
 * dsscmd_encrypt.c
 *
 *
 * IDENTIFICATION
 *    src/cmd/dsscmd_encrypt.c
 *
 * -------------------------------------------------------------------------
 */

#include "dsscmd_encrypt.h"
#include "cm_utils.h"
#include "dss_malloc.h"
#ifdef WIN32
#include <conio.h>
#else
#include <termios.h>
#endif

static int32 dss_get_one_char()
{
#ifdef WIN32
    return _getch();
#else
    size_t count;
    int32 char_ascii;
    struct termios oldt;
    struct termios newt;
    (void)tcgetattr(STDIN_FILENO, &oldt);

    count = sizeof(newt);
    MEMS_RETURN_IFERR(memcpy_s(&newt, count, &oldt, count));
    newt.c_lflag &= ~(ECHO | ICANON | ECHOE | ECHOK | ECHONL | ICRNL);
    newt.c_cc[VMIN] = 1;
    newt.c_cc[VTIME] = 0;
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    char_ascii = getchar();
    /* Restore the old setting of terminal */
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return char_ascii;
#endif
}

status_t dss_receive_info_from_terminal(char *buff, int32 buff_size, bool32 is_plain_text)
{
    int32 pos = 0;
    char char_ascii;
    int32 key = 0;
    bool32 len_exceed = CM_FALSE;
    CM_POINTER(buff);
    do {
        key = dss_get_one_char();
        if (key < 0) {
            (void)printf("invalid char which may be EOF found");
            return CM_ERROR;
        }
        char_ascii = (char)key;
#ifdef WIN32
        if (char_ascii == KEY_BS) {
#else
        if (char_ascii == KEY_BS || char_ascii == KEY_BS_LNX) {
#endif
            if (pos > 0) {
                buff[pos] = '\0';
                pos--;
                /*
                * Recv a key of backspace, print a '\b' backing a char
                and printing
                * a space replacing the char displayed to screen
                with the space.
                */
                (void)printf("\b");
                (void)printf(" ");
                (void)printf("\b");
            } else {
                continue;
            }
        } else if (char_ascii == KEY_LF || char_ascii == KEY_CR) {
            break;
        } else {
            /*
             * Only recv the limited length of pswd characters, on beyond,
             * contine to get a next char entered by user.
             */
            if (pos >= buff_size - 1) {
                len_exceed = CM_TRUE;
                continue;
            }
            if (is_plain_text) {
                (void)printf("%c", char_ascii);
            } else {
                /* Faking a mask star * */
                (void)printf("*");
            }
            buff[pos] = char_ascii;
            pos++;
        }
    } while (CM_TRUE);
    int32 end = pos < buff_size - 1 ? pos : buff_size - 1;
    buff[end] = '\0';
    (void)printf("\n");
    if (len_exceed == CM_TRUE) {
        (void)printf("invalid password, maximum length is %d\n", buff_size - 1);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t dss_verify_password_str(const char *text, const char *rptext)
{
    uint32 len, rlen;
    char *name = "sys";
    CM_POINTER2(text, rptext);

    // Verify input twice pswd
    len = (uint32)strlen(text);
    rlen = (uint32)strlen(rptext);
    if (len != rlen || strcmp(text, rptext) != 0) {
        (void)printf("Input twice passwords are inconsistent.\n");
        return CM_ERROR;
    }
    uint32 pwd_len = CM_PASSWD_MIN_LEN;
    return cm_verify_password_str(name, text, pwd_len);
}

// catch plain from terminal
status_t dss_catch_input_text(char *plain, uint32 plain_size)
{
    char first[CM_PASSWD_MAX_LEN + 1] = {0};
    char second[CM_PASSWD_MAX_LEN + 1] = {0};
    status_t ret;
    errno_t errcode;
    do {
         (void)printf("Please enter password to encrypt: \n");
        ret = dss_receive_info_from_terminal(first, (int32)sizeof(first), CM_TRUE);
        DSS_BREAK_IF_ERROR(ret);

         (void)printf("Please input password again: \n");
        ret = dss_receive_info_from_terminal(second, (int32)sizeof(second), CM_FALSE);
        DSS_BREAK_IF_ERROR(ret);

        ret = dss_verify_password_str(first, second);
        if (ret != CM_SUCCESS) {
            (void)printf("1.password can't be more than 64 characters\n"
                         "2:password can't be less than %d characters\n"
                         "3.password should contain at least "
                         "three type the following characters:\n"
                         "A. at least one lowercase letter\n"
                         "B. at least one uppercase letter\n"
                         "C. at least one digit\n"
                         "D. at least one special character: `~!@#$%%^&*()-_=+\\|[{}]:\'\",<.>/? and space\n",
                CM_PASSWD_MIN_LEN);
            break;
        }

        errcode = memcpy_s(plain, plain_size, first, CM_PASSWD_MAX_LEN + 1);
        if (errcode != EOK) {
            ret = CM_ERROR;
            CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            break;
        }
    } while (0);

    MEMS_RETURN_IFERR(memset_s(first, CM_PASSWD_MAX_LEN + 1, 0, CM_PASSWD_MAX_LEN + 1));
    MEMS_RETURN_IFERR(memset_s(second, CM_PASSWD_MAX_LEN + 1, 0, CM_PASSWD_MAX_LEN + 1));
    return ret;
}
