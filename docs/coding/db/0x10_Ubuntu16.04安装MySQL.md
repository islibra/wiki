# 0x10_Ubuntu16.04安装MySQL

## 下载安装包和依赖包

下载地址: https://dev.mysql.com/downloads/mysql/

> 点击`Looking for the latest GA version?`

1. Select Operating System: `Ubuntu Linux`
2. Select OS Version: `Ubuntu Linux 16.04 (x86, 64-bit)`
3. 选择`DEB Bundle (mysql-server_x.x.xx-1ubuntu16.04_amd64.deb-bundle.tar)`，点击`Download`。或直接使用下载地址：
    - https://dev.mysql.com/get/Downloads/MySQL-8.0/mysql-server_8.0.19-1ubuntu16.04_amd64.deb-bundle.tar
    - https://dev.mysql.com/get/Downloads/MySQL-5.7/mysql-server_5.7.23-1ubuntu16.04_amd64.deb-bundle.tar

## 解压安装

```bash
$ mkdir mysql
# 将下载的安装包解压到mysql文件夹
$ tar -xv -C mysql -f mysql-server_5.7.23-1ubuntu16.04_amd64.deb-bundle.tar

libmysqlclient21_8.0.19-1ubuntu16.04_amd64.deb
libmysqlclient-dev_8.0.19-1ubuntu16.04_amd64.deb
mysql-client_8.0.19-1ubuntu16.04_amd64.deb
mysql-common_8.0.19-1ubuntu16.04_amd64.deb
mysql-community-client_8.0.19-1ubuntu16.04_amd64.deb
mysql-community-client-core_8.0.19-1ubuntu16.04_amd64.deb
mysql-community-server_8.0.19-1ubuntu16.04_amd64.deb
mysql-community-server-core_8.0.19-1ubuntu16.04_amd64.deb
mysql-community-server-debug_8.0.19-1ubuntu16.04_amd64.deb
mysql-community-test_8.0.19-1ubuntu16.04_amd64.deb
mysql-community-test-debug_8.0.19-1ubuntu16.04_amd64.deb
mysql-server_8.0.19-1ubuntu16.04_amd64.deb
mysql-testsuite_8.0.19-1ubuntu16.04_amd64.deb

# 1.安装公共组件
dpkg -i mysql-common_5.7.23-1ubuntu16.04_amd64.deb

# 2.安装客户端依赖库
dpkg -i libmysqlclient20_5.7.23-1ubuntu16.04_amd64.deb
# 3.安装客户端
dpkg -i mysql-community-client-core_8.0.19-1ubuntu16.04_amd64.deb
dpkg -i mysql-community-client_5.7.23-1ubuntu16.04_amd64.deb
dpkg -i mysql-client_5.7.23-1ubuntu16.04_amd64.deb

# 4.安装服务端
dpkg -i mysql-community-server-core_8.0.19-1ubuntu16.04_amd64.deb
dpkg -i mysql-community-server_5.7.23-1ubuntu16.04_amd64.deb
```

### 依赖库

- [libnuma1_2.0.10-1_amd64.deb](http://ftp.br.debian.org/debian/pool/main/n/numactl/libnuma1_2.0.10-1_amd64.deb)
- [libaio1_0.3.110-1_amd64.deb](http://ftp.br.debian.org/debian/pool/main/liba/libaio/libaio1_0.3.110-1_amd64.deb)
- [libmecab2_0.996-3.1_amd64.deb](http://ftp.br.debian.org/debian/pool/main/m/mecab/libmecab2_0.996-3.1_amd64.deb)
- [psmisc_22.21-2_amd64.deb](http://ftp.br.debian.org/debian/pool/main/p/psmisc/psmisc_22.21-2_amd64.deb)
- [其他版本](http://ftp.br.debian.org/debian/pool/main/)


## 查看数据库运行状态

```bash
$ systemctl status mysql.service / service mysql status
$ mysql -u root -p
show databases;
use mysql;
# 配置远程连接权限，其中*.*代表所有库所有表，root为用户名，%表示所有IP地址，password为密码
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY 'password' WITH GRANT OPTION;
flush privileges;
# 或
update user set host = '%' where user = 'root';
```


## 相关文件目录

+ 配置文件：`/etc/mysql/my.cnf`
+ 配置文件目录：`/usr/share/mysql`
+ 数据库主目录：`/var/lib/mysql`
+ 日志文件目录：`/var/log/mysql`


## [HeidiSQL](https://www.heidisql.com/)

免费, 支持MariaDB, MySQL, Microsoft SQL, PostgreSQL, SQLite
