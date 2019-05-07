# VxLAN

## 网络协议栈

- 应用层：Telnet FTP HTTP SMTP...
- 传输层：TCP UDP
- 网络层：IP ICMP
- 物理链路层：ARP

### 数据包格式

以太网头(源目的MAC) | IP头(源目的IP) | TCP头(源目的端口) | DATA(HTTP应用数据)

## VxLAN(Virtual eXtensible Local Area Network)

VLAN使用12bit标记VLAN ID，最多支持4094；

VXLAN使用24bit标记VNI，最多支持16777216。

VXLAN将二层数据封装成UDP，即 {==MAC-in-UDP==}。

### 数据包格式

{++以太网头(源目的MAC) | IP头(源目的IP) | UDP头(源目的端口) | VXLAN头(8Byte，其中24bitVNI) |++} 以太网头(源目的MAC) | IP头(源目的IP) | TCP头(源目的端口) | DATA(HTTP应用数据)
