---
title: grep&awk
date: 2018-09-08 11:48:21
categories: os
tags:
---

# grep

在每个FILE或标准输入中查找PATTERN.

## Demo

```bash
grep -i 'hello world' first.java second.properties
```

## 参数

> + -i --ignore-case 忽略大小写
> + -v --invert-match 查找不匹配的行

# awk

awk [-F field-separator] 'commands' input-file(s)  
其中，commands 是真正awk命令，[-F域分隔符]是可选的，input-file(s) 是待处理的文件。  
在awk中，文件的每一行中，由域分隔符分开的每一项称为一个域。通常，在不指名-F域分隔符的情况下，默认的域分隔符是空格。

例：`$ cat /etc/passwd | awk  -F ':'  '{print $1}'`，将passwd中的每一行，以:分割，打印第一个。
