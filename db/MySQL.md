---
title: MySQL
date: 2018-09-08 11:58:45
categories: db
tags:
---

# 术语

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


# 注释

```sql
/* ... */
```

> `/*! ... */` 仅在MySQL中执行。如：`/*! select * from user*/;`
> `/*!50001 select * from user*/;` 仅在5.00.01以上的MySQL版本中执行。


# information_schema数据库

## 字符集

> + CHARACTER_SETS 字符集
> + COLLATIONS 字符集排序规则
> + COLLATION_CHARACTER_SET_APPLICABILITY

## 权限

> + SCHEMA_PRIVILEGES 数据库相关权限，mysql.db
> + TABLE_PRIVILEGES 表相关权限，mysql.tables_priv
> + COLUMN_PRIVILEGES 表授权的用户对象
> + USER_PRIVILEGES 用户相关权限，mysql.user
>   + Select_priv
>   + Insert_priv
>   + Update_priv
>   + Delete_priv

```sql
/* 新增用户，限制登录ip为10.155.123.%，%为通配符 */
INSERT INTO mysql.user(Host,User,Password) VALUES("10.155.123.%","kaka",PASSWORD("kaka123"));
flush privileges;  /* 刷新系统权限相关表 */
service mysqld restart  /* 重启生效 */
```

### 权限分配

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

## 实体对象

> + COLUMNS 表字段
> + SCHEMATA 所有数据库及默认字符集


# MySQL协议

## 基本数据类型

### Integers


#### Fixed-length integers

定长，例 int<3> 
`01 00 00`


#### Length-encoded integers

用第一个字节代表存储长度。例：

`fa`       -- 250
`fc fb 00` -- 251

+ <0xfb 1字节
+ 0xfc 2字节
+ 0xfd 3字节
+ 0xfe 8字节


### Strings

#### FixedLengthString

定长，例 `string<fix>`


#### NulTerminatedString

`string<NUL>` ，以 `00` 结尾。


#### VariableLengthString

`string<var>`


#### LengthEncodedString

`string<lenenc>`


#### RestOfPacketString

`string<EOF>`


## Packets

MySQL协议包被切分为最多2^24-1字节，每个分片携带包头。

### Payload

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
