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

```bash
# Red Hat
$ vim /etc/sysconfig/network-scripts/ifcfg-eth0
DNS1="x.x.x.x"
DNS2="y.y.y.y"

# ubuntu
$ vim /etc/network/interfaces
auto lo
auto eth0
iface eth0 inet static
```


## 设置某IP禁止访问

```bash
iptables -A INPUT -s 10.0.0.1/32 -j DROP  #增加防火墙规则
iptables -A OUTPUT -d 10.0.0.1/32 -j DROP
iptables -L INPUT -n --line-numbers  #带行号显示防火墙INPUT规则
iptables -D INPUT 2  #通过行号删除防火墙规则
iptables -D OUTPUT 3
```
