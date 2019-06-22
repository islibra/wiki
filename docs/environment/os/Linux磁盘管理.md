# Linux磁盘管理

## 0x00_查看硬盘详细信息

!!! example "fdisk -l"
    ![fdisk -l](../../../img/fdisk.png)

    - Disk /dev/xxx，硬盘大小
    - 设备 启动 起点 末尾 扇区 大小 Id 类型，硬盘分区信息


## 0x01_硬盘分区

!!! example "fdisk /dev/xxx"
    1. 输入 m 获取帮助。
    2. 输入 p 打印分区表。
    3. 输入 a 设定硬盘启动区。
    4. 输入 n 添加新分区。
        1. 输入 e 硬盘为[延伸]分割区(extend)。
        2. 输入 p 硬盘为[主要]分割区(primary)。
    5. 输入 t 更改分区类型。　　　　　　　　　　
        - t:分区系统id号
            - L:82:linux swap
            - 83:linux
            - 86：NTFS window分区
    6. 输入 d 删除分区。
    7. 输入 q 退出而不保存更改。
    8. 输入 w 将分区表写入磁盘并退出。

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


## 0x04_查看硬盘分区使用情况

`df -h`


## 添加磁盘并开机自动挂载

```bash
fdisk -l  #查看磁盘名称
pvcreate /dev/xvde  #创建PV
vgcreate vg1 /dev/xvde  #创建VG
vgdisplay  #查看VG大小
lvcreate -l ***** -n lv1 vg1  #创建LV，*为VG大小
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


## FAQ

```bash
ll /dev/mapper/
dmsetup remove vg1-lv1
```
