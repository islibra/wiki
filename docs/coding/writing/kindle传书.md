# kindle传书

## 0x00_usb存放到documents目录

支持格式azw, azw3, pdf, txt, mobi, prc

## 0x01_邮件发送

1. 访问z.cn，我的账户，管理我的内容和设备，将 {==发送邮箱==} 添加到亚马逊个人文档服务的认可列表
1. 以附件发送到 {==kindle邮箱==}，支持doc, docx, html, rtf, jpg, mobi, azw, gif, png, bmp, pdf

## 0x02_保存网页

浏览器插件：send to kindle(by klip.me)，收趣云书签

1. 插件中设置 {==kindle邮箱地址==}
1. 将 {==kindle@klip.me==} 添加信任

## 0x03_保存微信公众号文章

关注：亚马逊Kindle服务号

1. 绑定 {==kindle邮箱==}
1. 添加 {==kindle@eub-inc.com==} 信任

## 0x04_内置浏览器

下载mobi, azw, prc, txt


!!! tip "格式转换"
    cailbre

!!! quote "参考链接"
    [Kindle 除了用数据线传书，还有这 5 个超好用的传书技巧 - 少数派](https://mp.weixin.qq.com/s/Sag8vLmmLbAs47aIVF3rnQ)



pip install requests
import requests
r = request.get("https://xxx")
r = request.post("https://xxx", data={'key':'value'})
get请求参数
payload = {'key1':'value1', 'key2':'value2'}
r = request.get("https://xxx", params=payload)
http://mp.weixin.qq.com/mp/homepage?__biz=MzU2ODYzNTkwMg==&hid=5&sn=1cc7e4fa055c64f12f4a071bb6585d41&scene=18#wechat_redirect
