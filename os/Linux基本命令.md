---
title: Linux基本命令
date: 2018-07-29 10:09:25
categories: os
tags:
---

# 一、字符串处理

## 1. 转换大小写

```bash
echo 'hello' | tr 'a-z' 'A-Z'
echo 'HELLO' | tr 'A-Z' 'a-z'
```


# 二、文件处理

## 1. 远程拷贝

```bash
scp file.xxx user@hostip:/home/user
```
