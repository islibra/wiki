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

## 显示文件内容

```bash
cat file #查看全部内容
more file, file | more #分页查看
tail file, tail -f file #查看末尾几行
less file #滚动查看
```
