# redis

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
