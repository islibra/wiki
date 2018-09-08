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
