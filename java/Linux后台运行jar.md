---
title: Linux后台运行jar
date: 2018-08-25 20:25:28
categories: java
tags:
---

```bash
java -jar XXX.jar  #当前ssh窗口被锁定；使用Ctrl + C打断程序运行；窗口关闭，程序退出。
java -jar XXX.jar &  #后台运行；窗口关闭，程序退出。
nohup java -jar XXX.jar &  #终端关闭，程序仍然运行。所有输出被重定向到nohup.out。
nohup java -jar XXX.jar >temp.txt &  #输出重定向。
jobs  #查看后台运行的任务，显示编号。
fg 23  #将编号指定任务调回到前台控制。
```