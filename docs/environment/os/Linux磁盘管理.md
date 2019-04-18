---
title: Linux磁盘管理
date: 2018-10-12 21:19:38
categories: os
tags:
---

# 添加磁盘并开机自动挂载

```bash
fdisk -l  #查看磁盘名称
pvcreate /dev/xvde  #创建PV
vgcreate vg1 /dev/xvde  #创建VG
vgdisplay  #查看VG大小
lvcreate -l ***** -n lv1 vg1  #创建LV，*为VG大小
```


## SUSE

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


## Ubuntu

```bash
mkfs.ext4 -j /dev/vg1/lv1
tune2fs -c 0 -i 0 /dev/vg1/lv1  #格式化磁盘
mkdir /data  #创建挂载目录
mount /dev/vg1/lv1 /data  #挂载磁盘（注意如果目录中存在内容，将会被隐藏）
echo "/dev/mapper/vg1-lv1 /data ext4 defaults 0 0" >> /etc/fstab  #开机自动挂载磁盘
```


# FAQ

```bash
ll /dev/mapper/
dmsetup remove vg1-lv1
```
