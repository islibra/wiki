# hsts

## 问题现象

使用chrome访问网站页面报错：  
```
您的连接不是私密连接
...
NET::ERR_CERT_COMMON_NAME_INVALID
...
您目前无法访问xxx，因为此网站使用了HSTS。
```

## 解决方法

配置页面：<chrome://net-internals/#hsts>

1. Delete domain security policies  
输入访问有问题的网站域名，然后点击`Delete`。
2. Query HSTS/PKP domain  
输入刚才删除的域名，查询结果返回`Not found`，代表已经删除成功。

Done


!!! quote "参考链接"
    [Chrome HSTS异常导致无法访问HTTPS网页](https://blog.51cto.com/xujpxm/2085695?source=drt)
