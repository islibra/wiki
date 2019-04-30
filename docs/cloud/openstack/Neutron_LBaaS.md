# Neutron_LBaaS

Load Banlance as a Service

## Pool Member

提供在4层网络，拥有IP地址和监听端口对外提供服务，如HTTP Server。

## Pool

一组Pool Member提供同一类服务。

## Virtual IP

定义在load balancer上的IP。

!!! tip
    OpenStack Neutron通过HAProxy实现LBaaS。


!!! quote "参考链接"
    - [理解 Neutron LBaaS - 每天5分钟玩转 OpenStack（120）](https://www.cnblogs.com/CloudMan6/p/6123853.html)
