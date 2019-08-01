# curl_wget

## curl

+ -i --include 输出协议头信息
+ -k --insecure 访问SSL网站不校验证书
+ -H --header LINE 自定义header
+ -X --request COMMAND 请求类型POST/GET/PUT/DELETE
+ -d --data DATA HTTP POST body
+ -v --verbose 显示冗余信息


## wget

设置代理:

```bash
$ vim /etc/wgetrc
# You can set the default proxies for Wget to use for http, https, and ftp.
# They will override the value in the environment.
https_proxy = http://l0025xxxx:Pass%40word@proxy.xxx.com:8080
http_proxy = http://l0025xxxx:Pass%40word@proxy.xxx.com:8080
ftp_proxy = http://l0025xxxx:Pass%40word@proxy.xxx.com:8080

# If you do not want to use proxy at all, set this to off.
use_proxy = on
```
