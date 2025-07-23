#include <linux/module.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "./include/auth.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Matteo Pallagrosi");
MODULE_DESCRIPTION("authentication service");

#define LIBNAME "AUTH"

const u8 stored_passwd_hash[MAX_PASSWD_SIZE] = {
    0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65, 0x9a, 0x2f, 0xea, 0xa0, 0xc5, 0x5a, 0xd0, 0x15, 0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c, 0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08
};

int check_password(const char __user *passwd) {
    char kpasswd[MAX_PASSWD_SIZE];
    u8 hash[32];
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int ret;

    size_t len = strnlen_user(passwd, MAX_PASSWD_SIZE);
    if (len == 0 || len > MAX_PASSWD_SIZE)
        return -EINVAL;

    if (copy_from_user(kpasswd, passwd, len))
        return -EFAULT;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
        return -EINVAL;

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }
    desc->tfm = tfm;

    ret = crypto_shash_digest(desc, kpasswd, len-1, hash);
    kfree(desc);
    crypto_free_shash(tfm);
    if (ret)
        return -EINVAL;

    if (memcmp(hash, stored_passwd_hash, 32) == 0)
        return 0;
    return -EPERM;
}
