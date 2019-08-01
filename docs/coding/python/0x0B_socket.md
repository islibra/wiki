# 0x0B_socket

## 服务端

```python
#!/usr/bin/python

import socket, sys

# 创建套接字
# address family: AF_INET(the default), AF_INET6, AF_UNIX, AF_CAN, AF_PACKET, or AF_RDS.
# type: SOCK_STREAM(the default), SOCK_DGRAM, SOCK_RAW or perhaps one of the other SOCK_ constants.
# proto 0, 如果是AF_CAN, 则为CAN_RAW, CAN_BCM or CAN_ISOTP.
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

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

## 获取本机IP

```python
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.connect(('8.8.8.8', 80))
    # x.x.x.x
    print(s.getsockname()[0])
except Exception as e:
    print("error")
finally:
    s.close()
```
