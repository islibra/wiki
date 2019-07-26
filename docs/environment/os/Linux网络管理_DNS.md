# Linux网络管理_DNS

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


## 设置某IP禁止访问

```bash
iptables -A INPUT -s 10.0.0.1/32 -j DROP  #增加防火墙规则
iptables -A OUTPUT -d 10.0.0.1/32 -j DROP
iptables -L INPUT -n --line-numbers  #带行号显示防火墙INPUT规则
iptables -D INPUT 2  #通过行号删除防火墙规则
iptables -D OUTPUT 3
```
