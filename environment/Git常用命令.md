---
title: Git常用命令
date: 2018-07-15 17:22:07
categories: environment
tags:
---

# 一、通过分支MERGE
```bash
git clone xxx.git #将要提交代码仓路径clone到本地
cd #进入代码目录
git branch #查看当前分支
git pull origin master #更新本地分支
git checkout -b newbranch #checkout到个人分支
git branch #查看当前分支为个人分支
git push origin newbranch #将checkout出来的个人分支push到CodeClub
git status #查看本地修改的文件
git add -A . #将本地修改的文件add到本地仓个人分支
git commit -m "xxx" #将本地修改的文件提交到本地仓个人分支
git push origin newbranch #将本地修改的文件提交到远程仓个人分支
```
发起merge，从远程仓个人分支merge到远程仓主干分支

# 二、Fork个人仓
将主干仓Fork到个人仓
```bash
git clone xxx.git #将个人仓clone到本地
cd #进入代码目录
git remote -v #查看远程分支列表
git remote add projorigin projxxx.git #增加主库分支到本地
git branch #查看当前分支
git pull origin master #更新当前分支
git fetch projorigin #fetch主库分支的最新版本到本地
git merge projorigin/master #merge主库分支到本地
git status #查看本地修改的文件
git add -A . #将本地修改的文件add到本地仓
git commit -m "xxx" #将本地修改的文件提交到本地仓
git push origin branchname #将本地修改的文件提交到远程个人仓
```
发起merge，从远程个人仓merge到远程主干仓

END
