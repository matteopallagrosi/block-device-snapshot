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

int compute_hashed_password(const char *passwd, u8 *hash, size_t len) {
    struct crypto_shash *cipher;
    struct shash_desc *desc;
    int ret;

    //Alloca il cyper da utilizzare per calcolare l'hash della password    
    cipher = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(cipher)) {
        printk("Error during cipher creation: %ld", PTR_ERR(cipher));
        return -EINVAL;
    }

    printk("errore 1\n");

    //Dalla documentazione: 
    //The operational state is defined with struct shash_desc where the size of that data structure is to be calculated as sizeof(struct shash_desc) + crypto_shash_descsize(alg)
    desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(cipher), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(cipher);
        printk("Error while allocating memory");
        return -ENOMEM;
    }
    desc->tfm = cipher;

     printk("errore 2\n");

    //Calcola il digest per la password fornita
    ret = crypto_shash_digest(desc, passwd, len-1, hash);
    kfree(desc);
    crypto_free_shash(cipher);
    if (ret != 0) {
        printk("Error during digest computation");
        return -EINVAL;
    }

    printk("Hash computed successfully\n");

    return 0;

}

int set_password_hash(char *password) {
    u8 hash[HASHED_PASSWD_SIZE];
    int ret;

    size_t len = strnlen(password, MAX_PASSWD_SIZE);
    if (len == 0 || len > MAX_PASSWD_SIZE) {
        printk("%s: password size is invalid, equal to %d\n", LIBNAME, len);
        return -EINVAL;
    }

    printk("La password è %s", password);

    ret = compute_hashed_password(password, hash, len);
    if (ret < 0)
        return ret;

    printk(KERN_INFO "Hash calcolata: ");
    for (size_t i = 0; i < HASHED_PASSWD_SIZE; i++)
        printk(KERN_CONT "%02x", hash[i]);
    printk(KERN_CONT "\n");

    memcpy(stored_passwd_hash, hash, HASHED_PASSWD_SIZE);
    return 0;
}

int check_password(const char *passwd) {
    char kpasswd[MAX_PASSWD_SIZE];
    u8 hash[HASHED_PASSWD_SIZE];
    int ret;


    size_t len = strnlen_user(passwd, MAX_PASSWD_SIZE);
    if (len == 0 || len > MAX_PASSWD_SIZE) {
        printk("%s: password size is invalid, equal to %d\n", LIBNAME, len);
        return -EINVAL;
    }

    //Copia la password fornita dall'utente in un buffer del kernel
    if (copy_from_user(kpasswd, passwd, len)) {
        printk("Error during copy from user");
        return -EFAULT;
    }

    printk("La password da confrontare è %s", kpasswd);

    ret = compute_hashed_password(kpasswd, hash, len);
    if (ret < 0) {
        return ret;
    }

    printk("qui ci arrivo\n");

    printk(KERN_INFO "Hash corretta: ");
    for (size_t i = 0; i < HASHED_PASSWD_SIZE; i++)
        printk(KERN_CONT "%02x", stored_passwd_hash[i]);
    printk(KERN_CONT "\n");


    printk(KERN_INFO "Hash inserita: ");
    for (size_t i = 0; i < HASHED_PASSWD_SIZE; i++)
        printk(KERN_CONT "%02x", hash[i]);
    printk(KERN_CONT "\n");

    //Confronta l'hash calcolato con la password salvata offuscata
    if (memcmp(hash, stored_passwd_hash, HASHED_PASSWD_SIZE) == 0) {
        printk("Password is correct\n");
        return 0;
    }

    printk("Password is incorrect\n");
    return -EPERM;
}
