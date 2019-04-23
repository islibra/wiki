---
title: kali
---

# 渗透过程

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

# 安全维度

## 一、身份验证

### 用户名口令

- 登录，注册，重置密码等页面枚举用户名比较响应时间，intruder爆破，字典爆破口令。
- 使用Hydra进行Authorization: basic base64code=爆破：`hydra -Luser_list.txt -P top25_passwords.txt -u -e ns http-get://192.168.56.11/WebGoat`。

## 二、会话管理

### cookie中的会话标识

### token
