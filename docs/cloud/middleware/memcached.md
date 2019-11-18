# memcached

![](https://img.shields.io/badge/language-c-brightgreen.svg)

!!! quote "官方网站: <https://memcached.org/>, 最新版本v1.5.20, 2019-11-11"

分布式对象缓存, key-value, 通过缓存数据库查询结果, 减少数据库访问次数

客户端以Perl, PHP为主

对标产品:

- memcached
- ehcache
- redis


## 运行

```bash
$ /usr/local/memcached/bin/memcached -h
```

### 启动选项

- -m: 分配的内存大小, 单位MB
- -u: 运行用户
- -s: 监听UNIX socket(禁用网络支持)
- -l: 服务器IP地址, 可以多个
- -p: 监听端口

## 连接

```bash
$ telnet HOST PORT
```

## 存储

## 查找

## 统计


!!! warning "缺少认证和安全管制"


## Unix domain sockets

- 在单个主机上执行客户端/服务器通信
- 同一主机不同进程之间传递文件描述符
- 通过`-s`参数指定FIFO管道进行通讯


!!! quote "参考链接"
    - [Unix domain socket和memcached](https://yq.aliyun.com/articles/84999)
    - [juds](https://github.com/mcfunley/juds)


## 使用perl操作memcached进行数据转储

```perl
my $key = 'xxx';
$memd->set($key,{$key=>{itemid=>"$itemid",value=>"$value"}});
my $test = $memd->get($key);
printf("$test->{$key}->{itemid}\n");
print Dumper($test) . "\n";
```

!!! quote "参考链接: [perl操作memcache](https://blog.51cto.com/zoufuxing/1031085)"
