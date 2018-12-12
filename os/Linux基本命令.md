---
title: Linux基本命令
date: 2018-07-29 10:09:25
categories: os
tags:
---

显示命令历史记录：`HISTSIZE=1000`

# 字符串处理

## 转换大小写

```bash
echo 'hello' | tr 'a-z' 'A-Z'
echo 'HELLO' | tr 'A-Z' 'a-z'
```

# 文件处理

## 远程拷贝

```bash
scp file.xxx user@hostip:/home/user
```
