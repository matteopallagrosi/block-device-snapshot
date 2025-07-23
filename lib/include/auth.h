#ifndef _AUTH_
#define _AUTH_

#include <linux/types.h>
#include <linux/uaccess.h>

#define MAX_PASSWD_SIZE 32

extern const u8 stored_passwd_hash[MAX_PASSWD_SIZE];

int check_password(const char *passwd);

#endif