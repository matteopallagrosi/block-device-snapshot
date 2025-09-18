#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <libgen.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#define SNAPSHOT_BASE_DIR "/snapshot"
#define BLOCK_SIZE 4096
#define MAX_SNAPSHOT_NUMBER 30

//Costruisce il nome della directory snapshot a partire dal path del file device fornito
void snapshot_dir_name_from_path(const char *input, char *output, size_t size) {
    int j = 0;

    // Copia carattere per carattere, sostituendo '/' con '_'
    for (int i = 0; input[i] != '\0' && j < size - 1; ++i) {
        if (input[i] == '/') {
            output[j++] = '_';
        } else {
            output[j++] = input[i];
        }
    }

    output[j] = '\0';
}

//Cerca tutte le sottodirectory contenenti lo snapshot per il file device specificato.
//In particolare cerca tutte le directory con parte iniziale del nome coincidente con prefix (che deve essere nel formato corretto previsto per quel file device).
//Uno stesso file device può avere infatti più snapshot, corrispondenti a timestamp di montaggio diversi.
//Ritorna il numero di snapshot trovati.
int find_snapshots(const char *prefix, char snapshot_paths[][PATH_MAX]) {
    printf("Searching for snapshot directories with prefix: %s\n", prefix);
    DIR *dir = opendir(SNAPSHOT_BASE_DIR);
    struct dirent *entry;
    int count = 0;

    if (!dir) {
        perror("Error while opening /snapshot");
        return -1;
    }

    //Itera sulle sottodirectory di /snapshot, cercando quelle relative al file device specificato
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR && strncmp(entry->d_name, prefix, strlen(prefix)) == 0) {
            snprintf(snapshot_paths[count], PATH_MAX, "%s/%s", SNAPSHOT_BASE_DIR, entry->d_name);
            count++;
            if (count >= MAX_SNAPSHOT_NUMBER) break;
        }
    }

    closedir(dir);
    return count;
}

// Ripristina i blocchi dalla directory snapshot_dir sul device file_path
int restore_snapshot(const char *snapshot_dir, const char *file_path) {
    DIR *dir;
    struct dirent *entry;

    dir = opendir(snapshot_dir);
    if (!dir) {
        perror("Error while opening snapshot directory");
        return -1;
    }

    int device_fd = open(file_path, O_WRONLY);
    if (device_fd < 0) {
        perror("Error while opening file device");
        return -1;
    }

    printf("Restoring from: %s -> %s\n", snapshot_dir, file_path);

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_REG) continue;

        //Recupera il numero del blocco dal nome del file
        int block_num = atoi(entry->d_name);
        if (block_num < 0) continue;

        char block_path[PATH_MAX];
        snprintf(block_path, sizeof(block_path), "%s/%s", snapshot_dir, entry->d_name);

        int block_fd = open(block_path, O_RDONLY);
        if (block_fd < 0) {
            perror("Error while opening block file snapshot");
            return -1;
        }
        
        //Legge il contenuto originale del blocco dal file di snapshot
        char buffer[BLOCK_SIZE];
        ssize_t read_bytes = read(block_fd, buffer, BLOCK_SIZE);
        close(block_fd);

        if (read_bytes != BLOCK_SIZE) {
            fprintf(stderr, "Error while reading block %d (%zd bytes read)\n", block_num, read_bytes);
            return -1;
        }

        off_t offset = (off_t)block_num * BLOCK_SIZE;
        if (lseek(device_fd, offset, SEEK_SET) < 0) {
            perror("Error seek in file device");
            return -1;
        }

        //Ripristina il blocco originale sul file device
        ssize_t written_bytes = write(device_fd, buffer, BLOCK_SIZE);
        if (written_bytes != BLOCK_SIZE) {
            fprintf(stderr, "Error while writing block %d\n", block_num);
        } else {
            printf("Block %d restored\n", block_num);
        }
    }

    closedir(dir);
    close(device_fd);
    return 0;
}

int main(int argc, char *argv[]) {
    //In input è previsto come argv[1] il percorso del device di cui ripristinate lo snapshot
    if (argc != 2) {
        printf("Wrong command format, use: %s <path_device_to_restore>\n", argv[0]);
        return -1;
    }

    
    char *file_path = argv[1];

    //Costruisce a partire dal path del file device il nome previsto per la directory snapshot (senza includere il timestamp finale)
    char snap_dir_name[PATH_MAX];
    snapshot_dir_name_from_path(file_path, snap_dir_name, sizeof(snap_dir_name));

    //Cerca le sottodirectory di /snapshot che contengono snapshot per il file device specificato (relativi a diversi timestamp di montaggio)
    char snapshot_paths[MAX_SNAPSHOT_NUMBER][PATH_MAX];
    int count = find_snapshots(snap_dir_name, snapshot_paths);

    if (count <= 0) {
        fprintf(stderr, "No snapshot found for %s\n", file_path);
        return -1;
    }

    //Permette all'utente di selezionare quale snapshot ripristinare, se ce n'è più di uno
    int choice = 0;
    if (count == 1) {
        printf("Found one snapshot: %s\n", snapshot_paths[0]);
    } else {
        printf("Found %d snapshot available for %s:\n", count, file_path);
        for (int i = 0; i < count; ++i) {
            const char *timestamp = strrchr(snapshot_paths[i], '_');
            timestamp++;
            printf(" [%d] %s\n", i, timestamp);
        }

        printf("Select snapshot to use: ");
        if (scanf("%d", &choice) != 1 || choice < 0 || choice >= count) {
            printf("Invalid choice\n");
            return -1;
        }
    }

    //Ripristina lo snapshot selezionato
    int res = restore_snapshot(snapshot_paths[choice], file_path);
    return res;
}
