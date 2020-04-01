# redis

![](https://img.shields.io/badge/language-C-brightgreen.svg)

- 内存+持久化
- 读110000次/s, 写81000次/s

    > RDS, 16U32G, 纯读40322QPS, 读写21756QPS

    > DDM, 16U16G, 纯读40000QPS, 读写20000QPS

- 原子型操作，支持事务

## 安装启动

启动: `redis-server /data/component/redis/redis-3.2.11/redis.conf`，需要改成daemonize

授权登录:

1. 连接的时候直接指定密码: `redis-cli -h 127.0.0.1 -p 6379 -a 123456`
1. 连接后授权: `redis-cli -h 127.0.0.1 -p 6379`，`auth 123456`

查询所有key: `keys *`, `keys xxx*`

## 数据类型

### String 512M

SET GET MSET MGET SETEX生存时间 SETNX仅不存在时 INCR DECR INCRBY DECRBY

### List

LPUSH key value [value]添加到表头 LPUSHX LPOP RPUSH添加到表尾

### Set

SADD

### SortedSet

ZADD

### Hash

HSET key field value HGET HDEL HEXSITS HGETALL HKEYS HVALUES HLEN HMGET HMSET HINCRBY

### Key

## 事务

1. MULTI: 标记事务块开始
1. EXEC: 执行所有事务块内的命令

    > 如果key被WATCH, 且被改动, 则EXEC事务被打断

1. DISCARD: 取消事务
1. WATCH: 监视key
1. UNWATCH: 取消WATCH

## 持久化

### RDB

dump快照

1. save, 同步操作, 阻塞redis
1. bgsave, 调用Linux fork(), 异步操作
1. 自动保存

### AOF

binlog, 每个请求记录日志

1. always, 每条命令都写入缓冲区, 再fsync()写入硬盘, fsync()大于2秒AOF阻塞
1. everysecond, 每秒进行一次fsync()
1. no, 由操作系统决定什么时候刷新硬盘

AOF重写减小文件体积

- bgrewriteaof(类似bgsave)
- AOF重写配置(类似RDB自动保存)

通过读取服务器当前数据库状态实现

!!! quote "参考链接"
    - [Redis从入门到精通：初级篇](https://mp.weixin.qq.com/s/TrEcIW0DIgncpdQ00hAVSw)
    - [Redis从入门到精通：中级篇](https://mp.weixin.qq.com/s/-qdjcKouRVfa5QtjCAZTMA)
    - [Redis 高性能缓存解密](https://mp.weixin.qq.com/s/ydFktr6TMmY3_BWjt3sIGQ)


Java客户端: [Jedis](https://github.com/xetorthio/jedis)

## Maven依赖

```xml
<dependency>
    <groupId>redis.clients</groupId>
    <artifactId>jedis</artifactId>
    <version>3.2.0</version>
    <type>jar</type>
    <scope>compile</scope>
</dependency>
```

## Java调用

```java
Jedis jedis = new Jedis("localhost");
jedis.set("foo", "bar");
String value = jedis.get("foo");
```

### 认证

```java
import redis.clients.jedis.Jedis;

public class RedisTest {
    public static void main(String[] args) {
        String host = "192.168.0.150";
        int port = 6379;
        String pwd = "passwd";
        Jedis client = new Jedis(host, port);
        client.auth(pwd);
        client.connect();
        // 执行set指令
        String result = client.set("key-string", "Hello, Redis!");
        System.out.println( String.format("set指令执行结果:%s", result) );
        // 执行get指令
        String value = client.get("key-string");
        System.out.println( String.format("get指令执行结果:%s", value) );
    }
}
```

1. 将第三方引用jar包打入代码: `javac -cp /root/project/lib/jedis-2.9.0.jar /root/project/src/RedisTest.java`
1. 运行代码: `java -cp /root/project/lib/jedis-2.9.0.jar:/root/project/src/ RedisTest`

## 集群调用

```java
Set<HostAndPort> jedisClusterNodes = new HashSet<HostAndPort>();
jedisClusterNodes.add(new HostAndPort("127.0.0.1", 7379));
JedisCluster jc = new JedisCluster(jedisClusterNodes);
jc.set("foo", "bar");
String value = jc.get("foo");
```

### 认证

```java
// 密码模式生成连接池配置信息
String ip = "192.168.0.150";   
int port = 6379;   
String pwd = "passwd";   
GenericObjectPoolConfig config = new GenericObjectPoolConfig();   
config.setTestOnBorrow(false);   
config.setTestOnReturn(false);   
config.setMaxTotal(100);   
config.setMaxIdle(100);   
config.setMaxWaitMillis(2000);   
// 在应用初始化的时候生成连接池
JedisPool pool = new JedisPool(config, ip, port, 100000, pwd);
// 在业务操作时，从连接池获取连接
Jedis client = pool.getResource();   
try {   
    // 执行指令
    String result = client.set("key-string", "Hello, I am Redis!");   
    System.out.println( String.format("set指令执行结果:%s", result) );   
    String value = client.get("key-string");   
    System.out.println( String.format("get指令执行结果:%s", value) );   
} catch (Exception e) {   
    // TODO: handle exception  
} finally {   
    // 业务操作完成，将连接返回给连接池
    if (null != client) {   
        pool.returnResource(client);   
    }   
}  // end of try block  
// 应用关闭时，释放连接池资源
pool.destroy();
```

1. `javac -cp /root/project/lib/jedis-2.9.0.jar:/root/project/lib/commons-pool2-2.5.0.jar /root/project/src/RedisPool.java`
1. `java -cp /root/project/lib/jedis-2.9.0.jar:/root/project/lib/commons-pool2-2.5.0.jar:/root/project/src/ RedisPool`

## 高可用(HA)

Redis-Sentinel, 独立进程, 集群部署, 监控Master-Slave集群, 发现Master宕机后自动切换(选举Master, 通知另外一个进程, 如客户端)
