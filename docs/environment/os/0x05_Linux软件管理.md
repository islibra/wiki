# 0x05_Linux软件管理

## Ubuntu

### 修改apt源

1. `/etc/apt/sources.list`
1. `apt-get update`
1. `apt-get install -y xxx`


## mount

```bash
# 挂载iso文件
# 先在/mnt/下新建一个名为cdrom的文件夹
# -o 逗号分隔的选项列表
mount -o loop /xxx/xxx.iso /mnt/cdrom
umount /mnt/cdrom
```


## rhel

```bash
#Redhat查询软件是否安装
rpm -qa xxx
#Redhat安装软件
rpm -ivh xxx.rpm
```


## Ubuntu下安装deb包命令

```bash
#Ubuntu配置国内镜像站点/etc/apt/sources.list
deb http://mirrors.163.com/ubuntu/ trusty main restricted universe multiverse
deb http://mirrors.163.com/ubuntu/ trusty-security main restricted universe multiverse
deb http://mirrors.163.com/ubuntu/ trusty-updates main restricted universe multiverse
deb http://mirrors.163.com/ubuntu/ trusty-proposed main restricted universe multiverse
deb http://mirrors.163.com/ubuntu/ trusty-backports main restricted universe multiverse
deb-src http://mirrors.163.com/ubuntu/ trusty main restricted universe multiverse
deb-src http://mirrors.163.com/ubuntu/ trusty-security main restricted universe multiverse
deb-src http://mirrors.163.com/ubuntu/ trusty-updates main restricted universe multiverse
deb-src http://mirrors.163.com/ubuntu/ trusty-proposed main restricted universe multiverse
deb-src http://mirrors.163.com/ubuntu/ trusty-backports main restricted universe multiverse

#Ubuntu安装软件
sudo apt-get install xxx

#Ubuntu更新安装包
apt update

dpkg -l | grep xxx  #查看已安装的软件
dpkg -L | grep xxx  #查看已安装的软件路径
dpkg -i package.deb  #安装
dpkg -c package.deb  #查看deb包中的内容
dpkg -L package  #列出deb包安装的所有文件清单
dpkg -I package.deb  #从deb包中提取信息
dpkg -s package  #显示已安装包的信息
dpkg -r package  #移除已安装的deb包
dpkg -P package  #彻底删除已安装的deb包和配置文件
dpkg-reconfigure package  #重新配置已安装的包
```


## 压缩解压文件

### 1. tar

```bash
$ tar xvf FileName.tar  #解包
$ tar cvf FileName.tar DirName  #打包（注：tar是打包，不是压缩！）

# 解压到指定目录
# 0. 已存在文件
$ cat /etc/hackpasswd
important file
# 1. 创建文件
root@SZX1000451827:/home/hacker# vim hackpasswd
you are hacked!
# 2. 将文件打包
root@SZX1000451827:/home/hacker# tar -cvf hack.tar hackpasswd
hackpasswd
# 3. 解压到指定目录
root@SZX1000451827:/home/hacker# tar -C /etc -xvf hack.tar
hackpasswd
# 4. 查看原文件已被替换
root@SZX1000451827:/home/hacker# cat /etc/hackpasswd
you are hacked!
```

### 2. gz

```bash
$ gunzip FileName.gz  #解压1
$ gzip -d FileName.gz  #解压2
$ gzip FileName  #压缩
```

### 3. tar.gz

```bash
# 解压到当前目录
$ tar -zxvf file.tar.gz
# 解压到指定目录
$ tar -zxvf /tmp/file.tar.gz -C /tmp/
# 压缩
$ tar -zcvf file.tar.gz dir
```

### 4. bz2

```bash
$ bzip2 -d FileName.bz2  #解压1
$ bunzip2 FileName.bz2  #解压2
$ bzip2 -z FileName  #压缩
```

### 5. tar.bz2

```bash
$ tar -jxvf FileName.tar.bz2  #解压1
$ bzip2 -d file.tar.bz2 & tar -xvf file.tar  #解压2
$ tar jcvf FileName.tar.bz2 DirName  #压缩
```

### 6. bz

```bash
$ bzip2 -d FileName.bz  #解压1
$ bunzip2 FileName.bz  #解压2
```

### 7. tar.bz

```bash
$ tar jxvf FileName.tar.bz  #解压
```

### 8. Z

```bash
$ uncompress FileName.Z  #解压
$ compress FileName  #压缩
```

### 9. tar.Z

```bash
$ tar Zxvf FileName.tar.Z  #解压
$ tar Zcvf FileName.tar.Z DirName  #压缩
```

### 10. tgz

```bash
$ tar zxvf FileName.tgz  #解压
```

### 11. tar.tgz

```bash
$ tar zxvf FileName.tar.tgz  #解压
$ tar zcvf FileName.tar.tgz FileName  #压缩
```

### 12. zip

```bash
$ unzip FileName.zip  #解压
$ zip FileName.zip -r DirName  #压缩

# 将当前目录下的文件压缩并设置密码
$ ll
total 30208
drwxr-xr-x  2 root root     4096 Aug 28 11:50 ./
drwxr-xr-x 10 root root     4096 Aug 28 11:48 ../
-rw-r--r--  1 root root 30883840 Aug 28 11:50 br.tar
-rw-r--r--  1 root root      876 Aug 28 11:49 run.sh
$ zip scan.zip -re ./*
Enter password:
Verify password:
  adding: br.tar (deflated 92%)
  adding: run.sh (deflated 52%)
$ ll
total 32536
drwxr-xr-x  2 root root     4096 Aug 28 13:49 ./
drwxr-xr-x 10 root root     4096 Aug 28 11:48 ../
-rw-r--r--  1 root root 30883840 Aug 28 11:50 br.tar
-rw-r--r--  1 root root      876 Aug 28 11:49 run.sh
-rw-r--r--  1 root root  2379589 Aug 28 13:49 scan.zip
$ vim scan.zip
" zip.vim version v27
" Browsing zipfile /home/islibra/scan.zip
" Select a file with cursor and press ENTER

br.tar
run.sh
```

### 13. lha

```bash
$ lha -e FileName.lha  #解压
$ lha -a FileName.lha FileName  #压缩
```

### 14. rar

```bash
$ rar a FileName.rar  #解压
$ rar e FileName.rar  #压缩
```

> rar需下载，解压后将`rar_static`拷贝到`/usr/bin`目录（其他由$PATH环境变量指定的目录也行）

```bash
$ cp rar_static /usr/bin/rar
```


---
以下未整理
---


## Ubuntu

- 查询软件有哪些版本可用：`sudo apt-cache madison <<packagename>>`, `sudo apt-cache policy <<packagename>>`
- 安装指定版本：`sudo apt-get install xxx=version`


# 安装JDK的步骤

1. 下载linux版的jdk
1. 解压jdk安装包，`tar -xzvf jdk-7u17-linux-x64.tar.gz`
1. 将解压后的 jdk-7u17-linux-x64 目录下的所有文件移动到`/usr/local/java`
1. 设置环境变量，`sudo vim /etc/profile`，写入如下内容：
```
export JAVA_HOME=/usr/local/java
export JRE_HOME=/usr/local/java/jre　
export CLASSPATH=.:$JAVA_HOME/lib:$JRE_HOME/lib:$CLASSPATH
export PATH=$JAVA_HOME/bin:$JRE_HOME/bin:$PATH
```
1. 执行`source /etc/profile`，使环境变量生效
1. 输入`java -version`命令查看java是否安装成功
