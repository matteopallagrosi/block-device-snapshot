 # Project SOA: block-device snapshot manager

 ## Project specification
 This specification is related to a Linux Kernel Module (LKM) implementing a snapshot service for block devices hosting file systems. The setup/switch-off of the service needs to be carried out via the following two API functions:

    activate_snapshot(char * dev_name, char * passwd)
    deactivate_snapshot(char * dev_name, char * passwd) 

When activating the snapshot, the dev_name needs to be recorded at kernel level, so that when the device associated with that name gets mounted then the snapshot service for the corresponding file system gets activated. At the same time, the snapshot deactivating API is used to notify that such snapshot service does not need to occur any-longer for that specific dev_name upon remounting it. The passwd parameter needs to be a credential managed by the snapshot service (not corresponding to any credential used for logging into the system) so that the thread which calls one of the above two API functions can be authenticated. In order for the above API not to fail, the calling thread also needs to have (effective-)root-id.

For "loop" devices, the dev_name parameter will correspond to the actual path-name associated to the file managed as device-file.

When the snapshot service gets activated, a subdirectory needs to be created in the /snapshot directory of the root file system. Such subdirectory should keep any file and data that represent the snapshot being managed. The subdirectory should have a name expressing the original dev_name for which the snapshot has been activated and a timestamp indicating the time of the mount operation of that device.

When the snapshot service is active for a device, we need to be able to log the original content of any block that is modified by VFS operations occurring on the file system hosted on the device. Restoring the content of these modified blocks allows therefore to rebuild the exact content of that file system prior its mount operation.

Deferred work is expected to be exploited for keeping low the on-critical-path activity executed by the snapshot service along the application threads using VFS.

The overall project will also need to offer a facility for restoring the snapshot of the device after the corresponding file system has been un-mounted. This part of the project can be limited to device-file management.

The project needs to be testable using the minimal file system layout and logic available in the directory `SINGLEFILE-FS`.


## System requirements
- The module `BLOCK DEVICE SNAPSHOT SERVICE` requires Linux systems with kernel versions >= 6.3.

- The filesystem `SINGLEFILE-FS` used to test the module requires Linux systems with kernel versions >= 6.3.


## Syscall table discoverer installation
To install the syscall table discovery module, run the following commands in the directory `Linux-sys_call_table-discoverer`:
- `make all` to compile

- `./load.sh` to mount the module.

This module is required to locate entries in the system call table that are used to register the system calls provided by the block-device snapshot manager.

## Block-device snapshot manager installation
To install the block-device snapshot manager module, run the following commands in the root directory of the project:
- `make all` to compile

- `sudo make mount` to mount the module and create the `/snapshot` directory in the system root directory.

In this way, the activate_snapshot and deactivate_snapshot system calls will be registered.

By using the command `sudo dmesg`, it is possible to retrieve the indexes of the system call table entries associated with the registered system calls. These values must be entered into the `snapshot.conf` configuration file.

## Single-file filesystem installation
Run the following commands in the directory `SINGLEFILE-FS`:
- `make all` to compile

- `sudo make load-FS-driver` to load the filesystem drivers required to handle operations for this filesystem

- `make create-fs` to create a file-device `image` that contains the singlefile-fs filesystem layout, including a single file with example content.

- `sudo make mount-fs` to create a `mount` directory and mount the filesystem stored in the `image` file-device there.

The `SINGLEFILE-FS` subdirectory contains a README showing the filesystem layout and the supported operations.

Additionally, you can use the command `sudo umount ./mount` to unmount the filesystem.

## Module Usage
The `user` directory contains a program to interact with the system calls provided by the module. After compiling user.c with:
- `gcc -o snapshot-service user.c`

you can run:
- `sudo ./snapshot-service <activate|deactivate> <device_path> <password>`

to enable or disable the snapshot service on a specific device (or loop device).
- `<device_path>`: the device name, or the full path to the file for a loop device.
- `<password>`: the password required to use the system calls, set when mounting the module.

The `sudo` command is used to allow execution of system calls that require the calling thread to have (effective) root privileges.

On filesystem mount, the module checks if the snapshot service is active. If so, a subdirectory is created under /snapshot named after the device and mount timestamp. The first time a block of the single-file filesystem is modified, a snapshot of the block is created in the subdirectory, allowing the original content to be restored after unmount, using the `restore-service`.

If deactivate_snapshot is called while the filesystem is mounted, the snapshot service stays active until unmount, and will be disabled for the next mount.

## Restoring Snapshots
The snapshot restore facility is intended for file-devices only. Inside the `restore-service` directory, after compiling with:
- `gcc -o restore-snapshot restore-snapshot.c`

you can restore a snapshot on a specific file-device using the following command:
- `sudo ./restore-snapshot <device_path>`

`<device_path>` represents the full path of the file-device to be restored.

If multiple snapshots are available for different filesystem mount timestamps, the program allows the user to select which snapshot to restore.

## Modules cleanup
To remove the block-device snapshot manager, run the following command in the root directory of the project:
- `sudo make unmount` to unmount the module and restore the system call table. The `/snapshot` directory is removed.

- `make clean` to remove all files generated during compilation.


To remove the syscall table discovery module, run the following command in the `Linux-sys_call_table-discoverer` directory:
- `./unload.sh` to unmount the module. WARNING: the module is not removable on kernel versions >= 5.15.

- `make clean` to remove all files generated during compilation.

To remove the single-file filesystem drivers, run the following command in the `SINGLEFILE-FS` directory:
- `sudo rmmod singlefilefs` to unmount the drivers

- `make clean` to remove all files generated during compilation.











