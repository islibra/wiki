# Git

## 0x00_配置认证

### 生成SSH密钥对

```sh
$ ssh-keygen -t rsa -C "islibra@xxx.com"
Generating public/private rsa key pair.
Enter file in which to save the key (/c/Users/xxx/.ssh/id_rsa): id_rsa_github
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in id_rsa_github
Your public key has been saved in id_rsa_github.pub
```

### 将 id_rsa_github.pub 内容添加到 github

### 配置映射 /c/Users/xxx/.ssh/config

```
Host github.com
HostName github.com
User islibra@xxx.com
PreferredAuthentications publickey
IdentityFile C:\Users\xxx\.ssh\id_rsa_github
```

### 把私钥文件添加到SSH-Agent中

```sh
$ eval $(ssh-agent)
$ ssh-add id_rsa_github
```

### 测试连通性

```sh
$ ssh -T git@github.com
```

!!! quote "[一台电脑如何同时玩转GitHub和公司Git服务器？](https://baijiahao.baidu.com/s?id=1667080409461835667&wfr=spider&for=pc)"

## 0x00_配置git代理

```bash
git config --global http.https://github.com.sslVerify false  # 不进行ssl检查，因为公司上外网是通过代理，ssl是代理发的，不是github发的，git不认。
git config --global http.https://github.com.proxy "http://l0025xxxx:pass%40word@proxyhk.hxxx.com:8080"  # %40代表@
git config --global https.https://github.com.proxy "https://l0025xxxx:pass%40word@proxyhk.hxxx.com:8080"
git config --global credential.helper store
git config --global push.default matching
git config --global http.postBuffer 2M
git config --global --list  # 查看配置
git clone https://github.com/xxx/xxx.git  # 使用HTTPS方式clone
```


## 2. 通过分支 Merge

```bash
# 将要提交代码仓路径 clone 到本地
$ git clone xxx.git
# 进入代码目录
$ cd xxx
# 更新服务端的所有分支到本地
$ git fetch --all
# 查看本地所有分支
$ git branch --all
# 更新本地 master 分支
$ git pull origin master
# 新建个人分支
$ git checkout -b newbranch
# 合入修改代码
# ...
# 查看本地修改的文件
$ git status
# 将本地修改的文件 add 到本地仓个人分支
$ git add -A .
# 将本地修改的文件提交到本地仓个人分支
$ git commit -m "xxx"
# 将本地修改的文件提交到远程仓个人分支
$ git push origin newbranch
# 发起 merge，从远程仓个人分支 merge 到远程仓 master 分支
# ...
# 删除本地个人分支
$ git branch -D newbranch
# 删除服务端的个人分支
$ git push origin :newbranch
```


## 0x02_Fork个人仓

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


## 0x03_拉取子目录

```bash
[root@vm_test backup]# mkdir devops
[root@vm_test backup]# cd devops/
[root@vm_test devops]# git init    #初始化空库
Initialized empty Git repository in /backup/devops/.git/
[root@vm_test devops]# git remote add -f origin http://laijingli@192.168.1.1:90/scm/beeper/yunxxx_ops.git   #拉取remote的all objects信息
Updating origin
remote: Counting objects: 70, done.
remote: Compressing objects: 100% (66/66), done.
remote: Total 70 (delta 15), reused 0 (delta 0)
Unpacking objects: 100% (70/70), done.
From http://192.168.1.1:90/scm/beeper/yunxxx_ops
 * [new branch]      master     -> origin/master
[root@vm_test devops]# git config core.sparsecheckout true   #开启sparse clone
[root@vm_test devops]# echo "devops" >> .git/info/sparse-checkout   #设置需要pull的目录，*表示所有，!表示匹配相反的
[root@vm_test devops]# more .git/info/sparse-checkout
devops
[root@vm_test devops]# git pull origin master  #更新
From http://192.168.1.1:90/scm/beeper/yunxxx_ops
 * branch            master     -> FETCH_HEAD
[root@vm_test devops]# ls
devops
[root@vm_test devops]# cd devops/
[root@vm_test devops]# ls
monitor_in_web  test.1
```

## I. 操作命令

- 添加 **单个文件** 到暂存区: `git add {file}`
- 添加 **新增/修改文件** 到暂存区: `git add .`
- 添加 **修改/删除文件** 到暂存区: `git add -u`
- 添加 **所有文件** 到暂存区: `git add -A`

- 撤销并丢弃本地修改：`git checkout .`
- 撤销 add: `$ git reset HEAD [filename]`
- 撤销 commit: `$ git reset --soft HEAD~1`, 1 代表 commit 次数

!!! quote "[Git 基础 - 撤消操作](https://git-scm.com/book/zh/v2/Git-%E5%9F%BA%E7%A1%80-%E6%92%A4%E6%B6%88%E6%93%8D%E4%BD%9C)"
