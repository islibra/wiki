# 架构

以daemon方式后台运行一个master和多个worker。

# 正向代理

内网请求访问外网服务。  
```
server {
  #指定DNS服务器地址
  resolver 1.1.1.1;
  #指定代理端口
  listen 8080;
  location / {
    #设定代理服务器的协议和地址（固定不变）
    proxy_pass http://$http_host$request_url;
  }
}
```

使用示例：`curl --proxy proxy_server:8080 http://www.taobao.com/`

# 透明代理

拦截内网客户端访问外网的数据和信息。隐藏自己。

# 反向代理

接收外网客户端请求，转发给内网服务器。隐藏内网服务器。可实现通过子域名映射到多个内网服务器端口。  
```
server {
  #监听端口
  listen 80;
  #服务器名称（客户端访问的域名）
  server_name a.xxx.com;
  #nginx日志输出文件
  access_log logs/nginx.access.log main;
  #nginx错误日志输出文件
  error_log logs/nginx.error.log;
  root html;
  index index.html index.htm index.php;
  location / {
    #被代理的服务器地址
    proxy_pass http://localhost:8081;
    #对发送给客户端的URL进行修改操作
    proxy_redirect off;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forward-For $proxy_add_x_forwarded_for;
    proxy_next_upstream error timeout invalid_header http_500 http_502 http_503 http_504;
    proxy_max_temp_file_size 0;
  }
}
```

# 负载均衡

将外网客户端请求按照规则分发给多个内网服务器。

1. 轮询，默认方式  
```
upstream serverList {
  server 1.1.1.1;
  server 1.1.1.2;
  server 1.1.1.3;
}
```
1. ip_hash，解决session问题  
```
upstream serverList {
  ip_hash
  server 1.1.1.1;
  server 1.1.1.2;
  server 1.1.1.3;
}
```
1. url_hash  
```
upstream serverList {
  server 1.1.1.1;
  server 1.1.1.2;
  server 1.1.1.3;
  hash $request_uri;
  hash_methor crc32;
}
```
1. fair, 按后端服务器响应时间短优先分配  
```
upstream serverList {
  ip_hash
  server 1.1.1.1;
  server 1.1.1.2;
  server 1.1.1.3;
  fair;
}
```

server后携带参数：

- down: 不参与负载
- weight: 权重越大，负载量越大
- max_fails: 允许请求失败次数，默认为1
- fail_timeout: max_fails次失败后暂停时间
- backup: 备份机，只有其他所有非backup机器down或忙时才请求backup机

示例配置：  
```
upstream serverList {
  server 1.1.1.1;
  server 1.1.1.2;
  server 1.1.1.3;
}

server {
  #监听端口
  listen 80;
  #服务器名称（客户端访问的域名）
  server_name www.xxx.com;
  root html;
  index index.html index.htm index.php;
  location / {
    #被代理的服务器地址
    proxy_pass http://serverList;
    #对发送给客户端的URL进行修改操作
    proxy_redirect off;
    proxy_set_header Host $host;
  }
}
```

# 静态服务器

```
server {
  listen 80;
  server_name www.xxx.com;
  client_max_body_size 1024M;
  location / {
    root /var/www/xxx_static;
    index index.html;
  }
}
```

# 管理命令

- 查看版本：`nginx -v`
- 启动停止：`/etc/init.d/nginx start, stop`
- 编辑配置文件：`/etc/nginx/nginx.conf`