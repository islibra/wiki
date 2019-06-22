# google_ctf_2019

[Google CTF](https://buildyourfuture.withgoogle.com/events/ctf/)

[capturetheflag](https://capturetheflag.withgoogle.com/)

## web

### bnv

<http://bnv.web.ctfcompetition.com/>

共4个资源：

- html: 提交表单调用AjaxFormPost()发送请求
- post.js
    - 将a-z映射为多个数字的字符串
    - 将message转化为数字串
    - 请求URL: `/api/search`
- logo.png
- favicon.ico

#### 解题思路

1. 直接将flag转换成数字串124012301012450，无效
1. 使用`' or 1=1 --`或`' or 1=1 #`进行SQL注入，无效
1. 使用dirsearch扫描是否还有其他文件
