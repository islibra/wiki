# adworld

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
