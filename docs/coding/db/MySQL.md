# MySQL

## 术语

schema：数据库，例如查询所有数据库名称和默认编码：

```sql
mysql> select schema_name, default_character_set_name from information_schema.schemata;

+--------------------+----------------------------+
| schema_name        | default_character_set_name |
+--------------------+----------------------------+
| information_schema | utf8                       |
| db_6922_0000       | latin1                     |
| mysql              | latin1                     |
| performance_schema | utf8                       |
| sys                | utf8                       |
+--------------------+----------------------------+
12 rows in set (0.02 sec)
```


## 注释

```sql
/* ... */
```

???+ tip
    - `/*! ... */` 仅在MySQL中执行。如：`/*! select * from user*/;`
    - `/*!50001 select * from user*/;` 仅在5.00.01以上的MySQL版本中执行。


## information_schema数据库

### 字符集

+ CHARACTER_SETS: 字符集

```sql
/*查看支持的字符集*/
SHOW CHARACTER SET;
select * from information_schema.CHARACTER_SETS;
SHOW CHARACTER SET where charset='utf8';
SHOW CHARACTER SET like 'utf8%';
```

+ COLLATIONS: 字符集排序规则

```sql
/*查看支持的字符序*/
SHOW COLLATION;
SHOW COLLATION where charset='utf8';
select * from information_schema.COLLATIONS where CHARACTER_SET_NAME='utf8';
```


#### 设置级别

##### server

创建数据库时未指定字符集，字符序，默认使用server字符集，字符序。

```sql
/*查看server字符集，字符序*/
show variables like 'character_set_server';
show variables like 'collation_server';
```

- 启动服务时指定：

```bash
mysqld --character-set-server=latin1 \
       --collation-server=latin1_swedish_ci
```

- 配置文件指定，`/etc/my.cnf`：

```properties
[client]
default-character-set=utf8

[mysql]
default-character-set=utf8

[mysqld]
character-set-server=utf8
collation-server=utf8_unicode_ci
#指定客户端连接使用的字符集，相当于运行时执行：SET NAMES 'utf8';
#SET character_set_client = utf8; SET character_set_results = utf8; SET character_set_connection = utf8;
init-connect='SET NAMES utf8'
```

- 运行时修改

```sql
set character_set_server=utf8;  /*重启后生效*/
```


##### database

```sql
/*查看数据库字符集，字符序*/
select @@character_set_database, @@collation_database;
select * from information_schema.SCHEMATA where SCHEMA_NAME='xxx';
SHOW CREATE DATABASE xxx;
/*创建数据库时设置字符集*/
CREATE DATABASE test_schema CHARACTER SET utf8;
/*修改数据库字符集*/
ALTER DATABASE test_schema default character set=gb2312;
```

##### table

```sql
/*创建表时指定字符集*/
CREATE TABLE Persons
(
PersonID int,
PName varchar(255)
) DEFAULT CHARACTER SET=utf8;
/*修改表字符集*/
ALTER TABLE Persons default character set=utf8;
/*查看表字符集*/
SHOW TABLE STATUS FROM test_schema;
select * from information_schema.TABLES where TABLE_SCHEMA='test_schema' and TABLE_NAME='Persons';
SHOW CREATE TABLE Persons;
```

##### column

类型为CHAR, VARCHAR, TEXT的列，可以指定字符集，字符序。

```sql
/*新增列时指定字符集*/
ALTER TABLE Persons ADD COLUMN Addr VARCHAR(25) CHARACTER SET utf8;
/*查看列字符集*/
select * from information_schema.COLUMNS where TABLE_SCHEMA='test_schema' and TABLE_NAME='Persons';
```


???+ quote "参考链接"
    [Character Sets, Collations, Unicode](https://dev.mysql.com/doc/refman/5.7/en/charset.html)


### 权限

+ SCHEMA_PRIVILEGES 数据库相关权限，mysql.db
+ TABLE_PRIVILEGES 表相关权限，mysql.tables_priv
+ COLUMN_PRIVILEGES 表授权的用户对象
+ USER_PRIVILEGES 用户相关权限，mysql.user
    + Select_priv
    + Insert_priv
    + Update_priv
    + Delete_priv

```sql
/* 新增用户，限制登录ip为10.155.123.%，%为通配符 */
INSERT INTO mysql.user(Host,User,Password) VALUES("10.155.123.%","kaka",PASSWORD("kaka123"));
flush privileges;  /* 刷新系统权限相关表 */
service mysqld restart  /* 重启生效 */
```

#### 权限分配

`GRANT 权限 ON 数据库.* TO 用户名@'登录主机' IDENTIFIED BY '密码'`

+ 权限：`ALL,ALTER,CREATE,DROP,SELECT,UPDATE,DELETE`
+ 数据库：`*.*  表示所有库的所有表`
+ 用户名：`MySQL的账户名`
+ 登陆主机：`'%'表示所有ip`
+ 密码：`MySQL的账户名对应的登陆密码`

```sql
GRANT SELECT ON test.user TO kaka@'10.155.123.55' IDENTIFIED BY '123456';
show Grants for 'kaka'@'10.155.123.55';
```

### 实体对象

+ COLUMNS 表字段
+ SCHEMATA 所有数据库及默认字符集


## MySQL协议

### 基本数据类型

#### Integers

##### Fixed-length integers

定长，例 int<3>
`01 00 00`


##### Length-encoded integers

用第一个字节代表存储长度。例：

`fa`       -- 250
`fc fb 00` -- 251

+ <0xfb 1字节
+ 0xfc 2字节
+ 0xfd 3字节
+ 0xfe 8字节


#### Strings

##### FixedLengthString

定长，例 `string<fix>`


##### NulTerminatedString

`string<NUL>` ，以 `00` 结尾。


##### VariableLengthString

`string<var>`


##### LengthEncodedString

`string<lenenc>`


##### RestOfPacketString

`string<EOF>`


### Packets

MySQL协议包被切分为最多2^24-1字节，每个分片携带包头。

#### Payload

| Type	| Name	| Description |
| --- | --- | --- |
| int<3>	| payload_length	| payload长度 |
| int<1>	| sequence_id	| 报文序列号 |
| string<var>	| payload	| payload |

例，`COM_QUIT`：

`01 00 00 00 01`

* length: 0x01
* sequence_id: 0x00
* payload: 0x01

`COM_QUERY`：

`13 00 00 00 03 53 ...`

* length: 0x13
* sequence_id: 0x00
* 命令类型：0x03
* 命令：0x53 ...


## 日志

- error log: MySQL启停, 运行过程中的错误信息.
- general log: 查询日志, 建立的客户端连接和执行的语句.
- slow log: 执行时间超过long_query_time的查询和不使用索引的查询.
- bin log: 所有更改数据的语句, 默认 **未启用**.
    - ^^事务commit的时候, 1. 写入缓存中的日志^^, 记录与提交顺序有关.
    - 先于redo log被记录.
- relay log: 主从复制时使用的日志.

???+ quote "参考链接"
    [详细分析MySQL的日志(一)](https://www.cnblogs.com/f-ck-need-u/p/9001061.html)


## InnoDB, 数据库引擎

### 事务日志

> 都是用来恢复数据.

- redo log, 前滚, 记录数据库中每 **物理页** 的修改.
    - ^^事务commit的时候, 2. 向缓存中写入redo log^^, 再执行提交动作.
    - 多个事务并发写入.
- undo log, 回滚

???+ example "控制参数 innodb_flush_log_at_trx_commit"
    - 1: 事务每次提交都会将log buffer中的日志写入os buffer并系统调用fsync()刷到log file on disk中.
    - 0: 每秒将log buffer中的日志写入os buffer并系统调用fsync()刷到log file on disk中.
    - 2: 每次提交将log buffer中的日志写入os buffer, 每秒系统调用fsync()刷到log file on disk中.

???+ example "日志刷盘规则"
    - commit
    - 每秒
    - log buffer已使用内存超过一半
    - **checkpoint**: 会将buffer中的 **脏数据页** 和脏日志都刷到磁盘.

### LSN(log sequence number)

8 Bytes, 存在于redo log和data page中, 通过两者比较, 恢复丢失数据.

1. 修改data page buffer, 记录data_in_buffer_lsn
1. 修改redo log buffer, 记录redo_log_in_buffer_lsn
1. redo log file on disk, 记录redo_log_on_disk_lsn
1. checkpoint脏页刷盘, 记录checkpoint_lsn, data_page_on_disk_lsn

???+ quote "参考链接"
    [详细分析MySQL事务日志(redo log和undo log)](https://juejin.im/entry/5ba0a254e51d450e735e4a1f)


### 文件系统

- datafile, 数据文件，划分为64个 **page**，默认非压缩表的page size为`16KB`，总共1M（一个Extent）。
    - 主系统表空间文件`ibdata`。
    - 用户创建表产生`ibd`文件，归属于独立的表空间tablespace（一般一个表空间一个文件）。

- redo日志，默认以`512Bytes - 4KB`的 **block** 单位写入, `data`目录下`ib_logfile`开头的文件, 默认2个轮着写。
    - log block header: 12 Bytes
    - log block body: 492 Bytes
    - log block tailer: 8 Bytes

- undo tablespace文件。
- 临时表空间ibtmp1。


???+ quote "参考链接"
    [MySQL · 引擎特性 · InnoDB 文件系统之文件物理结构](http://mysql.taobao.org/monthly/2016/02/01/)
