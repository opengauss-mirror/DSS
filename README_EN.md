# DSS

Distributed Storage Service (DSS) is a basic component.
It supports access and management of raw devices, covering API operations and O&M tools for creating, deleting, and accessing volume groups, volumes, directories, and files. It also supports multi-node synchronization of the same file metadata to share the database storage architecture.

#### 1. Project Description
##### 1. Programming language: C
##### 2. Compilation tool: CMake (recommended) or Make
##### 3. Directories:
-   `DSS`: the main directory. The `CMakeLists.txt` file is the main project entry.
-   `src`: the source code directory. Common functions are grouped by sub-directory.
-   `build`: the project building script

#### 2. Using Ceph
##### 1. Creating a Ceph Block Device (Storage Pool and Image)
-   Create a storage pool: `ceph osd pool create dsspool 64 64`
-   Create an image: `rbd create dssimage --size 10240MB --pool dsspool --image-format 2 --image-feature layering`
-   Mount the image: `rbd map dsspool/dssimage`
##### 2. Writing Ceph Configurations During DSS Initialization
-   DSSDATA=/dev/rbd0
-   DSSHOME=${DSSDATA}
-   echo "VOLUME_TYPES=${DSSDATA}=1" > ${DSSHOME}/cfg/dss_inst.ini
-   echo "POOL_NAMES=${DSSDATA}=dsspool" >> ${DSSHOME}/cfg/dss_inst.ini
-   echo "IMAGE_NAMES=${DSSDATA}=dssimage" >> ${DSSHOME}/cfg/dss_inst.ini
-   echo "CEPH_CONFIG=/etc/ceph/ceph.conf" >> ${DSSHOME}/cfg/dss_inst.ini
-   `DSSDATA=/dev/rbd0` is the mounted Ceph block device.
-   POOL_NAMES is the storage pool configuration, in the format of `/dev/rbd0=dsspool`.
-   IMAGE_NAMES is the image configuration, in the format of `/dev/rbd0=dssimage`.
-   CEPH_CONFIG is the configuration file of the Ceph cluster. It defaults to `/etc/ceph/ceph.conf`.

#### 3. Compilation Guide
##### 1. OS and Software Dependencies
The following OSs are supported:
-   CentOS 7.6 (x86)
-   openEuler 20.03 LTS
-   openEuler 22.03 LTS
-   openEuler 24.03 LTS

For details about how to adapt to other OSs, see the openGauss compilation guide.
##### 2. Downloading DSS
Download DSS from the open-source community.
##### 3. Compiling Code
Use `DSS/build/linux/opengauss/build.sh` to compile the code. The following table describes the parameters.<br>
| Option| Parameter              | Description                                    |
| ---  |:---               | :---                                     |
| -3rd | [binarylibs path] | Specifies the `binarylibs` path. It must be an absolute path. |
| -m   | [version_mode]    | Specifies the target version of the compilation. It can be `Debug` or `Release` (default).|
| -t   | [build_tool]      | Specifies the compilation tool, which can be `cmake` (default) or `make`.    |

Run the following command to perform compilation:<br>
`[user@linux ]$ sh build.sh -3rd [binarylibs path] -m Release -t cmake`<br>
After the compilation is complete, the dynamic library is generated under the `DSS/output/lib` directory.
