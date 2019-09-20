# Linux网络_ip_ifconfig_route_DNS

## ip

```bash
# 显示所有网络接口及IP
$ ip a
# 显示网关, 网段
$ ip r

# 查看网络namespace
$ ip netns
# 进入namespace执行命令
$ ip netns exec {namespace} ip a
```

## ifconfig

/sbin/ifconfig: 查看，配置，启用，禁用网络接口的工具。

!!! warning "通过ifconfig为网卡指定的IP地址，只是用来调试网络用的，不会更改系统关于网卡的配置文件。"

语法：ifconfig 接口 IP hw MAC netmask 掩码 broadcast 广播 [up/down]

```bash
# 查看所有网络接口状态
$ ifconfig -a
# 查看特定网络接口状态
ifconfig eth0
# 启用/禁用网卡
$ ifconfig eth0 up/down
# 配置arp开启/关闭
$ ifconfig eth0 arp/-arp
# 配置IP地址，子网掩码，广播地址
$ ifconfig eth0 192.168.1.56 netmask 255.255.255.0 broadcast 192.168.1.255
# 设置网卡MAC地址
# hw后面所接的是网络接口类型：ether表示以太网，其他如ax25, ARCnet, netrom...
$ ifconfig eth1 hw ether xx:xx:xx:xx:xx:xx
```


!!! quote "参考链接: [Linux-eth0 eth0:1 和eth0.1关系、ifconfig以及虚拟IP实现介绍](https://www.cnblogs.com/JohnABC/p/5951340.html)"


## route

```bash
# Linux查看路由表
$ route
# macOS查看路由表
$ netstat -nr
# 跟踪路由
$ traceroute x.x.x.x
# 添加默认路由
$ route add default gw 192.168.1.1
# 添加到主机的路由
$ route add -host 192.168.1.2 dev eth0:0
$ route add -host 10.20.30.148 gw 10.20.30.40
# 添加到网络的路由
$ route add -net 10.20.30.40 netmask 255.255.255.248 eth0
$ route add -net 10.20.30.48 netmask 255.255.255.248 gw 10.20.30.41
$ route add -net 192.168.1.0/24 eth1
```

- Destination: 目标网段或主机
- Gateway: 网关地址，`*`表示目标是本主机所属网络，不需要路由
- Genmask: 网络掩码
- Flags
    - U 活动路由
    - G 路由指向网关
    - H 主机路由
    - N 网络路由


### 开启路由转发

```bash
$ echo 1 > /proc/sys/net/ipv4/ip_forward
```

或

```bash
# 写入配置文件/etc/sysctl.conf
$ sysctl -w net.ipv4.ip_forward=1
# 查看
$ sysctl net.ipv4.ip_forward
# 从配置文件/etc/sysctl.conf加载内核参数设置
sysctl -p
```


## iptables

```bash
# 查看SNAT规则
$ iptables -t nat -S

# 设置某IP禁止访问
$ iptables -A INPUT -s 10.0.0.1/32 -j DROP  #增加防火墙规则
$ iptables -A OUTPUT -d 10.0.0.1/32 -j DROP
$ iptables -L INPUT -n --line-numbers  #带行号显示防火墙INPUT规则
$ iptables -D INPUT 2  #通过行号删除防火墙规则
$ iptables -D OUTPUT 3
```


## 设置DNS

### 0x00_本地hosts

```bash
$ vim /etc/hosts
x.x.x.x www.xxx.com
```

### 0x01_系统DNS配置

> 添加多条DNS服务器地址

```bash
$ vim /etc/resolv.conf
nameserver x.x.x.x
```

!!! tip "Google提供的免费DNS服务器地址: 8.8.8.8, 8.8.4.4"

### 0x02_网卡配置文件

> 在网卡配置文件配置了DNS，重启网络服务后，会在`/etc/resolv.conf`中自动生成DNS。

```bash tab="Red Hat"
$ vim /etc/sysconfig/network-scripts/ifcfg-eth0
DNS1="x.x.x.x"
DNS2="y.y.y.y"
```

```bash tab="ubuntu"
$ vim /etc/network/interfaces
auto lo
iface lo inet loopback
auto eth0
iface eth0 inet static
address x.x.x.x
netmask 255.255.255.0
gateway x.x.x.1
dns-nameservers x.x.x.x y.y.y.y
```

```bash
# 重启网络服务
service network restart
```

???+ tip "系统解析优先级"
    本地hosts  >  网卡配置  >  系统DNS配置
