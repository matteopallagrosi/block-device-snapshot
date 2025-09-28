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

static u8 stored_passwd_hash[HASHED_PASSWD_SIZE];

static int compute_hashed_password(const char *passwd, u8 *hash, size_t len) {
    struct crypto_shash *cipher;
    struct shash_desc *desc;
    int ret;

    //Alloca il cipher da utilizzare per calcolare l'hash della password    
    cipher = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(cipher)) {
        printk("Error during cipher creation: %ld", PTR_ERR(cipher));
        return -EINVAL;
    }

    //Dalla documentazione: 
    //The operational state is defined with struct shash_desc where the size of that data structure is to be calculated as sizeof(struct shash_desc) + crypto_shash_descsize(alg)
    desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(cipher), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(cipher);
        printk("Error while allocating memory");
        return -ENOMEM;
    }
    desc->tfm = cipher;

    //Calcola il digest per la password fornita
    ret = crypto_shash_digest(desc, passwd, len, hash);
    kfree(desc);
    crypto_free_shash(cipher);
    if (ret != 0) {
        printk("Error during digest computation");
        return -EINVAL;
    }

    return 0;

}

int set_password_hash(char *password) {
    u8 hash[HASHED_PASSWD_SIZE];
    int ret;

    size_t len = strlen(password);
    if (len == 0 || len > MAX_PASSWD_SIZE) {
        printk("%s: password size is invalid\n", LIBNAME);
        return -EINVAL;
    }

    ret = compute_hashed_password(password, hash, len);
    if (ret < 0)
        return ret;

    memcpy(stored_passwd_hash, hash, HASHED_PASSWD_SIZE);
    return 0;
}

int check_password(const char *passwd) {
    char kpasswd[MAX_PASSWD_SIZE];
    u8 hash[HASHED_PASSWD_SIZE];
    int ret;


    size_t len = strnlen_user(passwd, MAX_PASSWD_SIZE);
    if (len == 0 || len > MAX_PASSWD_SIZE) {
        printk("%s: password size is invalid\n", LIBNAME);
        return -EINVAL;
    }
    len--;

    //Copia la password fornita dall'utente in un buffer del kernel
    if (copy_from_user(kpasswd, passwd, len)) {
        printk("Error during copy from user");
        return -EFAULT;
    }
    kpasswd[len] = '\0';

    ret = compute_hashed_password(kpasswd, hash, len);
    if (ret < 0) {
        return ret;
    }

    //Confronta l'hash calcolato con la password salvata offuscata
    if (memcmp(hash, stored_passwd_hash, HASHED_PASSWD_SIZE) == 0) {
        return 0;
    }

    return -EPERM;
}
