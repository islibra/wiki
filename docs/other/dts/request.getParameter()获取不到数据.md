# request.getParameter()获取不到数据

HTML中的form表单有一个关键属性 {==Content-Type＝application/x-www-form-urlencoded==} 或 {==multipart/form-data==}。

## 0x00. application/x-www-form-urlencoded

`Content-Type="application/x-www-form-urlencoded"`是默认的编码方式，当以这种方式提交数据时，HTTP报文中的内容是：

``` hl_lines="6"
Accept:*/*
Accept-Encoding:gzip, deflate, br
Accept-Language:zh-CN,zh;q=0.9,en;q=0.8
Connection:keep-alive
Content-Length:36
Content-Type:application/x-www-form-urlencoded; charset=UTF-8
Cookie:JSESSIONID=BEFE08D4761E2CED0B93D84CEED8DA73; JSESSIONID=121B641B71B923F88DBA9BCDBC541FA5; XSRF-TOKEN=5f79508e834371a1b14fd13ef5b58ed2
Host:10.64.103.106:8443
Origin:https://10.64.103.106:8443
Referer:https://10.64.103.106:8443/OPMUI/jsp/secospace/index.jsp?lang=zh_CN
User-Agent:Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36
X-Requested-With:XMLHttpRequest
X-XSRF-TOKEN:5f79508e834371a1b14fd13ef5b58ed2
title=test&content=%B3%AC%BC%B6%C5%AE%C9%FA&submit=post+article
```

Servlet的API提供了对这种编码方式解码的支持，只需要调用ServletRequest 类中的getParameter()方法就可以得到表单中提交的数据。


## 0x01. multipart/form-data

在传输大数据量的二进制数据时，必须将编码方式设置成`Content-Type="multipart/form-data"`，当以这种方式提交数据时，HTTP报文中的内容是：

``` hl_lines="7"
Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding:gzip, deflate, br
Accept-Language:zh-CN,zh;q=0.9,en;q=0.8
Cache-Control:max-age=0
Connection:keep-alive
Content-Length:1308
Content-Type:multipart/form-data; boundary=----WebKitFormBoundarybTh8eYefb4cLKAqx
Cookie:JSESSIONID=BEFE08D4761E2CED0B93D84CEED8DA73; JSESSIONID=121B641B71B923F88DBA9BCDBC541FA5; XSRF-TOKEN=5f79508e834371a1b14fd13ef5b58ed2
Host:10.64.103.106:8443
Origin:https://10.64.103.106:8443
Referer:https://10.64.103.106:8443/OPMUI/jsp/secospace/index.jsp?lang=zh_CN
Upgrade-Insecure-Requests:1
User-Agent:Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36

------WebKitFormBoundarybTh8eYefb4cLKAqx
Content-Disposition: form-data; name="vlanPath"

/OPMUI/cxfservices/vlan/vlanPolicyManagerService/accessvlanpools
------WebKitFormBoundarybTh8eYefb4cLKAqx
Content-Disposition: form-data; name="vlanUpload"; filename=""
Content-Type: application/octet-stream

------WebKitFormBoundarybTh8eYefb4cLKAqx
Content-Disposition: form-data; name="vlanUserName"

admin
------WebKitFormBoundarybTh8eYefb4cLKAqx
```

如果以这种方式提交数据就要用 {==request.getInputStream()==} 或 {==request.getReader()==} 来获取提交的数据 ，用request.getParameter()是获取不到提交的数据的。


???+ warning
    request.getParameter()、request.getInputStream()、request.getReader()这三种方法是有冲突的，因为流只能被读一次。

    ???+ example
        - 当form表单内容采用`enctype=application/x-www-form-urlencoded`编码时，先通过调用request.getParameter()方法获取数据后，再调用request.getInputStream()或request.getReader()已经获取不到流中的内容了，因为在调用request.getParameter()时系统可能对表单中提交的数据以流的形式读了一次，反之亦然。
        - 当form表单内容采用`enctype=multipart/form-data`编码时，调用request.getParameter()获取不到数据，即使已经调用了request.getParameter()方法也可以再通过调用request.getInputStream()或request.getReader()获取表单中的数据，但request.getInputStream()和request.getReader()在同一个响应中是不能混合使用的，如果混合使用会抛异常的。
