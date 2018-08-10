# 设置某IP禁止访问

```bash
iptables -A INPUT -s 10.0.0.1/32 -j DROP  #增加防火墙规则
iptables -A OUTPUT -d 10.0.0.1/32 -j DROP
iptables -L INPUT -n --line-numbers  #带行号显示防火墙INPUT规则
iptables -D INPUT 2  #通过行号删除防火墙规则
iptables -D OUTPUT 3
```
