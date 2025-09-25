#ifndef _AUTH_
#define _AUTH_

#include <linux/types.h>
#include <linux/uaccess.h>

#define HASHED_PASSWD_SIZE 32
#define MAX_PASSWD_SIZE 20

int check_password(const char *passwd);
int set_password_hash(char *password);

#endif