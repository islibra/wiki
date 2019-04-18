---
title: Linux设置Java环境变量
date: 2018-07-14 12:48:57
categories: java
tags:
---

# 修改文件路径

`/etc/profile`

在文件末尾加入：

```bash
export JAVA_HOME=xxx
export PATH=$JAVA_HOME/bin:$PATH  #以英文冒号分隔，不要覆盖掉原来的PATH
export CLASSPATH=.:$JAVA_HOME/lib  #不要忽略前面的点
```
