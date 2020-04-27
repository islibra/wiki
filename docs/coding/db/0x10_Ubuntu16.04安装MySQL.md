# 0x10_Ubuntu16.04安装MySQL

# 下载安装包和依赖包

## mysql

下载地址: [https://dev.mysql.com/downloads/mysql/](https://dev.mysql.com/downloads/mysql/)
点击`Looking for the latest GA version?`

> Select Version: `5.7.23`
> Select Operating System: `Ubuntu Linux`
> Select OS Version: `Ubuntu Linux 16.04 (x86, 64-bit)`

选择`DEB Bundle (mysql-server_5.7.23-1ubuntu16.04_amd64.deb-bundle.tar)`，点击`Download`。
或直接使用下载地址：[https://dev.mysql.com/get/Downloads/MySQL-5.7/mysql-server_5.7.23-1ubuntu16.04_amd64.deb-bundle.tar](https://dev.mysql.com/get/Downloads/MySQL-5.7/mysql-server_5.7.23-1ubuntu16.04_amd64.deb-bundle.tar)


## 依赖库

[libnuma1_2.0.10-1_amd64.deb](http://ftp.br.debian.org/debian/pool/main/n/numactl/libnuma1_2.0.10-1_amd64.deb)
[libaio1_0.3.110-1_amd64.deb](http://ftp.br.debian.org/debian/pool/main/liba/libaio/libaio1_0.3.110-1_amd64.deb)
[libmecab2_0.996-3.1_amd64.deb](http://ftp.br.debian.org/debian/pool/main/m/mecab/libmecab2_0.996-3.1_amd64.deb)
[psmisc_22.21-2_amd64.deb](http://ftp.br.debian.org/debian/pool/main/p/psmisc/psmisc_22.21-2_amd64.deb)
[其他版本](http://ftp.br.debian.org/debian/pool/main/)


# 安装mysql

```bash
mkdir mysql
tar -xv -C mysql -f mysql-server_5.7.23-1ubuntu16.04_amd64.deb-bundle.tar  #将下载的安装包解包到mysql文件夹

dpkg -i mysql-common_5.7.23-1ubuntu16.04_amd64.deb  #安装公共组件
dpkg -i libmysqlclient20_5.7.23-1ubuntu16.04_amd64.deb  #安装客户端依赖库

dpkg -i libnuma1_2.0.10-1_amd64.deb  #安装客户端依赖库
dpkg -i libaio1_0.3.110-1_amd64.deb

dpkg -i mysql-community-client_5.7.23-1ubuntu16.04_amd64.deb  #安装客户端

dpkg -i libmecab2_0.996-3.1_amd64.deb
dpkg -i mysql-client_5.7.23-1ubuntu16.04_amd64.deb

dpkg -i psmisc_22.21-2_amd64.deb
dpkg -i mysql-community-server_5.7.23-1ubuntu16.04_amd64.deb  #安装服务端
```


# 查看数据库运行状态

```bash
systemctl status mysql.service
mysql -u root -p
show databases;
use mysql;
#配置远程连接权限，其中*.*代表所有库所有表，root为用户名，%表示所有IP地址，password为密码
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY 'password' WITH GRANT OPTION;
flush privileges;
#或
update user set host = '%' where user = 'root';
```


# 相关文件目录

+ 配置文件：`/etc/mysql/my.cnf`
+ 数据库主目录：`/var/lib/mysql`
+ 配置文件目录：`/usr/share/mysql`
+ 日志文件目录：`/var/log/mysql`
