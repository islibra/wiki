---
title: sudoers文件
date: 2018-07-15 17:04:41
categories: os
tags:
---

文件路径：`/etc/sudoers`

允许普通用户在不输入root密码的情况下执行sudo命令。

> 通过`visudo`命令编辑

# 通过以下关键词设置别名

* Host_Alias
* User_Alias
* Cmnd_Alias

# 语法

> %groupname  #用户组

```bash
user    MACHINE=COMMANDS
root    ALL=(ALL)       ALL  #允许root在所有机器上执行所有命令
%sys ALL = NETWORKING, SOFTWARE, SERVICES, STORAGE, DELEGATING, PROCESSES, LOCATE, DRIVERS  #允许sys用户组执行网络等命令
%wheel        ALL=(ALL)       NOPASSWD: ALL  #允许wheel用户组在不输入自己密码的情况下执行所有命令
%users  ALL=/sbin/mount /mnt/cdrom, /sbin/umount /mnt/cdrom  #允许users用户组执行mount/unmount /mnt/cdrom命令
%users  localhost=/sbin/shutdown -h now  #允许users用户组在本机执行关机操作
xxx ALL=(ALL) NOPASSWD: /usr/bin/su  #允许xxx用户在不输入自己密码的情况下执行/usr/bin/su命令
```

> `#include /etc/sudoers.d/sudoers.paas`  #包含其他文件[^1]

[^1]: 前面的#不是注释。
