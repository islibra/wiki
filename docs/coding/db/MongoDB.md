# MongoDB

## 命令行

- 启动服务：`./mongod`
- 管理：`./mongo`
- 显示所有数据库：`show dbs`
- 显示当前数据库：`db`
- 连接到数据库：`use xxx`
- 插入数据：`db.xxx.insert({x:10})`
- 查找数据：`db.xxx.find()`
- 删除数据库: `db.dropDatabase()`
- 退出: `exit`

## 使用perl连接

```perl
#!/usr/bin/perl

use MongoDB;
use Data::Dumper;

$hashmongoconn='x.x.x.x';
$hashmongopass='xxx';

my $client = MongoDB::MongoClient->new(
    host => "mongodb://user:$hashmongopass\@$hashmongoconn:27017",
    auth_mechanism => 'SCRAM-SHA-1',
    query_timeout => 10000000000,connect_timeout_ms=>10000000000,wtimeout=>10000
);
my $db = $client->get_database("database_name");
my $collection = $db->get_collection("document");

# 查询第一个
my $row = $collection->find_one;
print Dumper $row;

# 查询所有
my $row = $collection->find;
while (my $r = $row->next) {
    print Dumper $r;
}
```


!!! quote "参考链接"
    - [metacpan](https://metacpan.org/pod/MongoDB::Collection)
    - [perl与MongoDB入门 - 简单的添加和更新操作](https://cn.perlmaven.com/getting-started-with-mongodb-using-perl-insert-and-update)


## SCRAM(Salted Challenge Response Authentication Mechanism)

- SCRAM-SHA-1
- SCRAM-SHA-256, 4.0版本新增, 要求fcv(featureCompatibilityVersion) 4.0

> 可修改迭代次数, 参见: [scramIterationCount](https://docs.mongodb.com/manual/reference/parameters/#param.scramIterationCount)

!!! quote "参考链接: [mongoDB Documentation](https://docs.mongodb.com/manual/core/security-scram/)"


## NoSQL数据库分类

| 类型 | 部分代表 | 特点 |
| --- | --- | --- |
| 列存储 | Hbase, Cassandra, Hypertable | 顾名思义，是按列存储数据的。最大的特点是方便存储结构化和半结构化数据，方便做数据压缩，对针对某一列或者某几列的查询有非常大的IO优势。 |
| 文档存储 | MongoDB, CouchDB | 文档存储一般用类似json的格式存储，存储的内容是文档型的。这样也就有有机会对某些字段建立索引，实现关系数据库的某些功能。 |
| key-value存储 | Tokyo Cabinet / Tyrant, Berkeley DB, MemcacheDB, Redis | 可以通过key快速查询到其value。一般来说，存储不管value的格式，照单全收。（Redis包含了其他功能） |
| 图存储 | Neo4J, FlockDB | 图形关系的最佳存储。使用传统关系数据库来解决的话性能低下，而且设计使用不方便。 |
| 对象存储 | db4o, Versant | 通过类似面向对象语言的语法操作数据库，通过对象的方式存取数据。 |
| xml数据库 | Berkeley DB XML, BaseX | 高效的存储XML数据，并支持XML的内部查询语法，比如XQuery,Xpath。 |


---


## 使用Node.js连接MongoDB

[Quick Start](http://mongodb.github.io/node-mongodb-native/3.1/quick-start/quick-start/)
