---
title: Linux用户管理
date: 2018-07-15 17:15:36
categories: os
tags:
---

* 用户`/etc/passwd`
* 用户组`/etc/group`

# 增加用户
```bash
useradd kk  #添加用户kk
```

# 切换用户
```bash
whoami  #显示当前用户
pwd  #显示当前目录
su root  #切换到root用户
```

# 修改密码
```bash
passwd w3cschool  #设置w3cschool用户的密码
Enter new UNIX password:  #输入新密码，输入的密码无回显
Retype new UNIX password:  #确认密码
passwd: password updated successfully
```

# 更改个人资讯
```bash
chfn
Changing finger information for root.
Name [root]: hnlinux
Office []: hn
Office Phone []: 888888
Home Phone []: 9999999
Finger information changed.
```

# 修改用户属性
```bash
usermod -g usergroup username
```
