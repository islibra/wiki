# 10_socket

## 服务端

```python
#!/usr/bin/python

import socket, sys

# 创建套接字
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # family: AF_UNIX, AF_INET,, type: SOCK_STREAM, SOCK_DGRAM,, proto 0

# 获取本地主机名
host = socket.gethostname()

port = 9999

# 绑定端口
serversocket.bind((host, port))  # 使用元组绑定

# 设置最大连接数
serversocket.listen(5)

while True:
  # 监听客户端连接
  clientsocket,addr = serversocket.accept()
  print("Client address: %s" % str(addr))
  msg = "Welcome!\n"
  clientsocket.send(msg.encode('utf-8'))
  clientsocket.close()
```

## 客户端

```python
#!/usr/bin/python

import socket, sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = socket.gethostname()

port = 9999

# 连接到服务器
s.connect((host,port))

# 使用1024字节接收数据
msg = s.recv(1024)

s.close()

print(msg.decode('utf-8'))
```
