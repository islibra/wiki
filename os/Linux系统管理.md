---
title: Linux系统管理
date: 2018-07-30 21:32:59
categories: os
tags:
---

# Ubuntu允许root通过ssh直接登录

```bash
#修改/etc/ssh/sshd_config
PermitRootLogin yes
#重启ssh服务
ssh stop/waiting
ssh start/running, process 27639
```