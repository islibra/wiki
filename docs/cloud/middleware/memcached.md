# memcached

![](https://img.shields.io/badge/language-c-brightgreen.svg)

!!! quote "官方网站: <https://memcached.org/>"

分布式对象缓存, key-value, 通过缓存数据库查询结果, 减少数据库访问次数

客户端以Perl, PHP为主

## 运行

```bash
$ /usr/local/memcached/bin/memcached -h
```

### 启动选项

- -m: 分配的内存大小, 单位MB
- -u: 运行用户
- -s: 监听的UNIX socket(禁用网络支持)
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
