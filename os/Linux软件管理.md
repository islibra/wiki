---
title: Linux软件管理
date: 2018-07-30 21:33:50
categories: os
tags:
---

```bash
#Redhat查询软件是否安装
rpm -qa xxx

#Ubuntu配置国内镜像站点/etc/apt/sources.list
deb http://mirrors.163.com/ubuntu/ trusty main restricted universe multiverse
deb http://mirrors.163.com/ubuntu/ trusty-security main restricted universe multiverse
deb http://mirrors.163.com/ubuntu/ trusty-updates main restricted universe multiverse
deb http://mirrors.163.com/ubuntu/ trusty-proposed main restricted universe multiverse
deb http://mirrors.163.com/ubuntu/ trusty-backports main restricted universe multiverse
deb-src http://mirrors.163.com/ubuntu/ trusty main restricted universe multiverse
deb-src http://mirrors.163.com/ubuntu/ trusty-security main restricted universe multiverse
deb-src http://mirrors.163.com/ubuntu/ trusty-updates main restricted universe multiverse
deb-src http://mirrors.163.com/ubuntu/ trusty-proposed main restricted universe multiverse
deb-src http://mirrors.163.com/ubuntu/ trusty-backports main restricted universe multiverse
#Ubuntu安装软件
sudo apt-get install xxx
#Ubuntu更新安装包
apt update
```

# 压缩解压文件

## 1. tar

```bash
$ tar xvf FileName.tar  #解包
$ tar cvf FileName.tar DirName  #打包（注：tar是打包，不是压缩！）
```

## 2. gz

```bash
$ gunzip FileName.gz  #解压1
$ gzip -d FileName.gz  #解压2
$ gzip FileName  #压缩
```

## 3. tar.gz

```bash
$ tar -zxvf file.tar.gz  #解压
$ tar -zcvf file.tar.gz dir  #压缩
```

## 4. bz2

```bash
$ bzip2 -d FileName.bz2  #解压1
$ bunzip2 FileName.bz2  #解压2
$ bzip2 -z FileName  #压缩
```

## 5. tar.bz2

```bash
$ tar -jxvf FileName.tar.bz2  #解压1
$ bzip2 -d file.tar.bz2 & tar -xvf file.tar  #解压2
$ tar jcvf FileName.tar.bz2 DirName  #压缩
```

## 6. bz

```bash
$ bzip2 -d FileName.bz  #解压1
$ bunzip2 FileName.bz  #解压2
```

## 7. tar.bz

```bash
$ tar jxvf FileName.tar.bz  #解压
```

## 8. Z

```bash
$ uncompress FileName.Z  #解压
$ compress FileName  #压缩
```

## 9. tar.Z

```bash
$ tar Zxvf FileName.tar.Z  #解压
$ tar Zcvf FileName.tar.Z DirName  #压缩
```

## 10. tgz

```bash
$ tar zxvf FileName.tgz  #解压
```

# 11. tar.tgz

```bash
$ tar zxvf FileName.tar.tgz  #解压
$ tar zcvf FileName.tar.tgz FileName  #压缩
```

## 12. zip

```bash
$ unzip FileName.zip  #解压
$ zip FileName.zip DirName  #压缩
```

## 13. lha

```bash
$ lha -e FileName.lha  #解压
$ lha -a FileName.lha FileName  #压缩
```

## 14. rar

```bash
$ rar a FileName.rar  #解压
$ rar e FileName.rar  #压缩
```

> rar需下载，解压后将`rar_static`拷贝到`/usr/bin`目录（其他由$PATH环境变量指定的目录也行）

```bash
$ cp rar_static /usr/bin/rar
```