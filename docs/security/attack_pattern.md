# attack_pattern

## SQL注入

### JDBC

```java tab="错误的做法"
// 拼接SQL语句
String sql = "SELECT * FROM users WHERE name ='" + name + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(sql);
```

```java tab="推荐的做法"
// 使用占位符 ? 和预编译
String sql = "SELECT * FROM users WHERE name= ? ";
PreparedStatement ps = connection.prepareStatement(sql);
// 参数 index 从 1 开始
ps.setString(1, name);
```

???+ warning
    **order by** 不能使用参数绑定，需要通过白名单过滤。


???+ quote "参考链接"
    [彻底干掉恶心的 SQL 注入漏洞， 一网打尽！](https://mp.weixin.qq.com/s/hdOnO-tSGkQp0Wq3wcsIkw)


## 命令注入

### Python格式化字符串漏洞

参见: [格式化字符串](../../coding/python/0x01_datatype/#_3)


## DoS

### zip

1. 使用root制作高压缩比文件：`dd if=/dev/zero count=$((1024*1024)) bs=4096 > big.csv`
1. 压缩：`zip -9 big.zip big.csv`
