# 0x03_Linux磁盘管理

## 磁盘空间满的排查方法

### 查看磁盘物理卷和逻辑卷详细信息

```bash
$ lsblk
NAME      MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
xvda      202:0    0   40G  0 disk
├─xvda1   202:1    0  3.7G  0 part [SWAP]
└─xvda2   202:2    0 36.3G  0 part /
xvde      202:64   0  180G  0 disk
└─vg1-lv1 252:0    0  180G  0 lvm  /data


$ fdisk -l
Disk /dev/sda: 64 GB  # 硬盘大小

# 设备 是否启动分区 起点 末尾 扇区 大小 Id 类型
Device Boot Start End Blocks Id System
/dev/sda1 * 2048 2099199 1048576 83 Linux

# 逻辑卷
Disk /dev/mapper/vgxxx-lvxxx: 10.7 GB
```

![](../../../img/fdisk.png)

### 查看逻辑卷组

```bash
$ vgdisplay
--- Volume group ---
VG Name    xxx
VG Size    39.00 GB
PE Size    4.00 MB
Total PE   9984
Alloc PE / Size    9984 / 39.00 GB
Free PE / Size     0 / 0
```

### 查看磁盘挂载和使用情况

```bash
$ df -h
Filesystem Size Used Avail Use% Mounted on
/dev/sda1 1G 100M 900M 10% /boot
/dev/mapper/vgxxx-lvxxx 20G 300M 1% /
```

### 查看哪个目录占用空间大

```bash
$ du -s /* | sort -nr
# 逐层排查
$ du -s /usr/* | sort -nr
```

### 查看当前目录下哪个目录/文件占用空间大

```bash
$ du -h --max-depth=1 | sort -nr
```

### 查看已删除文件进程仍占用, 重启进程

```bash
$ lsof | grep deleted
COMMAND PID TID USER FD TYPE DEVICE SIZE/OFF NODE NAME
```


!!! quote "参考链接: [linux磁盘已满，查看哪个文件占用多](https://blog.csdn.net/a854517900/article/details/80824966)"


## 硬盘分区

!!! example "fdisk /dev/xxx"
    1. 输入 m 获取帮助。
    2. 输入 p 打印分区表。
    3. 输入 n 添加新分区。
        1. 输入 p 硬盘为[主要]分割区(primary)。

            ```bash
            Command (m for help): n
            Partition number (4-128, default 4):
            First sector (12163483648-54687496158, default 12163483648):
            Last sector, +sectors or +size{K,M,G,T,P} (12163483648-54687496158, default 54687496158): {==+1G==}

            Created a new partition 4 of type 'Linux filesystem' and of size 1 GiB.
            ```

        1. 输入 e 硬盘为[延伸]分割区(extend)。

    1. 输入 t 更改分区类型。　　　　　　　　　　
        - t: 分区系统id号
            - L:
                - 31: Linux LVM
                - 82: linux swap
                - 83: linux
                - 86: NTFS window分区

    1. 输入 w 将分区表写入磁盘并退出。
    6. 输入 d 删除分区。
    7. 输入 q 退出而不保存更改。
    3. 输入 a 设定硬盘启动区。

kernel重新读取分区表: `$ partprobe`


## 添加磁盘并开机自动挂载

```bash
fdisk -l  #查看磁盘名称
pvcreate /dev/xvde  #创建PV
vgcreate vg1 /dev/xvde  #创建VG
vgdisplay  #查看VG大小
lvcreate -l ***** -n lv1 vg1  #创建LV，*为VG大小
# or
lvcreate -l 100%VG -n lv_sdb4 vg_sdb4
```


### SUSE

```bash
mkfs.ext3 -j /dev/vg1/lv1
tune2fs -c 0 -i 0 /dev/vg1/lv1  #格式化磁盘
fdisk -l  #查看磁盘状态，生成/dev/dm-0
mkdir /data  #创建挂载目录
mount /dev/dm-0 /data  #挂载磁盘（注意如果目录中存在内容，将会被隐藏）
vim /etc/fstab  #重启后自动挂载
/dev/dm-0 /data ext3 defaults 0 0  #在最后一行增加
df -h  #查看磁盘挂载状态
```


### Ubuntu

```bash
mkfs.ext4 -j /dev/vg1/lv1
tune2fs -c 0 -i 0 /dev/vg1/lv1  #格式化磁盘
mkdir /data  #创建挂载目录
mount /dev/vg1/lv1 /data  #挂载磁盘（注意如果目录中存在内容，将会被隐藏）
echo "/dev/mapper/vg1-lv1 /data ext4 defaults 0 0" >> /etc/fstab  #开机自动挂载磁盘
```

### EulerOS

```bash
$ mkfs -t xfs /dev/vg_sdb4/lv_sdb4
$ mount /dev/vg_sdb4/lv_sdb4 /xxx
$ echo "/dev/vg_sdb4/lv_sdb4 /std xfs defaults 0 0" >> /etc/fstab
```


## 0x02_分区指定文件系统

- `mke2fs /dev/sdb1`  # 默认是ext2
- `mke2fs -j /dev/sdb1`  # -j 是ext3
- `mke2fs -t ext4 /dev/sdb1`  # ext4
- `e2fsck -p /dev/sdb1`  # 检查文件系统：文件、扇区是否有错误 参数-p 是自动修复
- `tune2fs -l /dev/sdb1`  # 查看文件系统的详细信息

## 0x03_自动挂载

!!! example "/etc/fstab"
    ```
    # 设备名称 设备挂载点 文件系统 文件系统参数 是否dump备份 是否检验扇区
    /dev/sdb1 /dir ext4 defaults 0 0
    ```

    !!! note "是否dump备份"
        - 0 不做dump备份
        - 1 每天进行dump
        - 2 不定期dump

    !!! note "是否检验扇区"
        - 0 不要检验
        - 1 最早检验
        - 2 1级别检验完成后检验


## FAQ

```bash
ll /dev/mapper/
dmsetup remove vg1-lv1
```
