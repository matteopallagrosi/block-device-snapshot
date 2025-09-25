#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#define CONFIG_FILE "../snapshot.conf"

static long syscall_activate = -1;
static long syscall_deactivate = -1;

// Legge i numeri delle syscall dal file di configurazione
int load_syscall_numbers(const char *config_file) {
    FILE *f = fopen(config_file, "r");
    if (!f) {
        perror("Error while opening config file");
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "SYSCALL_ACTIVATE=%ld", &syscall_activate) == 1) continue;
        if (sscanf(line, "SYSCALL_DEACTIVATE=%ld", &syscall_deactivate) == 1) continue;
    }

    fclose(f);

    if (syscall_activate == -1 || syscall_deactivate == -1) {
        fprintf(stderr, "Config file missing syscall numbers\n");
        return -1;
    }
    return 0;
}


int main(int argc, char** argv) {

    char *syscall_name   = argv[1];
    char *dev_path = argv[2];
    char *password = argv[3];
    long ret;

    if (argc != 4) {
        fprintf(stderr, "Please use: sudo %s <activate|deactivate> <device_path> <password>\n", argv[0]);
        return 1;
    }

    if (load_syscall_numbers(CONFIG_FILE) < 0) {
        fprintf(stderr, "Error while loading system call numbers from configuration file\n");
        return 1;
    }

    if (strcmp(syscall_name, "activate") == 0) {
        ret = syscall(syscall_activate, dev_path, password);
    } else if (strcmp(syscall_name, "deactivate") == 0) {
        ret = syscall(syscall_deactivate, dev_path, password);
    } else {
        fprintf(stderr, "Unknown system call: %s\n", syscall_name);
        return 1;
    }

    if (ret < 0) {
        perror("syscall failed");
        return 1;
    }

    printf("%s_snapshot on %s executed successfully\n", syscall_name, dev_path);
    return 0;
}
