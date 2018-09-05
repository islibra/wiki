---
title: 设置ssh连接不超时
date: 2018-08-05 16:15:41
categories: os
tags:
---

# 修改sshd_config

配置文件路径: `/etc/ssh/sshd_config`

> ClientAliveInterval 300  #服务器向客户端请求消息的时间间隔, 设置成3600秒或更长.
> ClientAliveCountMax 0  #服务器发出请求后客户端没有响应的最大次数, 超过自动断开. 默认客户端不会响应. 设置成3或更大.

重新载入配置文件

```bash
service sshd reload
```


# 修改TMOUT环境变量

配置文件路径: `/etc/profile`

> export TMOUT=300  #设置为3600或更长.

重新载入配置文件

```bash
source profile
echo $TMOUT  #查看是否生效
```

参考：[https://www.cnblogs.com/enjoycode/p/5022607.html](https://www.cnblogs.com/enjoycode/p/5022607.html)
