# lvs_keepalived

## 安装

1. ipvsadm
1. keepalived

## keepalived配置文件

```
global_defs {
   router_id LVS_$prio  # 节点唯一标识，通常为hostname
}

local_address_group laddr_g1 {
    ${lvs_node}  # 本机IP
}

vrrp_instance VI_1 {
    state $role  # 节点的初始状态MASTER或BACKUP，但启动后还是通过竞选由优先级来确定
    interface eth0  # 节点固有IP（非VIP）的网卡，用来发VRRP包。
    virtual_router_id 51  # 取值在0-255之间，用来区分多个instance的VRRP组播。
    priority $prio  # 用来选举MASTER的，要成为MASTER，那么这个选项的值最好高于其他机器50个点，该项取值范围是1-255（在此范围之外会被识别成默认值100）。
    advert_int 1  # 发VRRP包的时间间隔，即多久进行一次MASTER选举（可以认为是健康查检时间间隔）。
    nopreempt  # 非抢占式，当成为BACKUP后，允许另一个priority比较低的节点作为MASTER。
    authentication {
        auth_type PASS
        auth_pass 1111
    }
    virtual_ipaddress {  # 浮动IP，随着state的变化而增加/删除，当state为master的时候就在该节点添加，当为backup时删除。
        $lvs_floating_ip
    }
}

virtual_server $lvs_floating_ip 8443 {  # 设置一个virtual server: VIP:Vport
    delay_loop 6  # 服务轮询的时间间隔（单位秒）。
    lb_algo rr  # LVS调度算法，支持rr|wrr|lc|wlc|lblc|sh|dh
    lb_kind FNAT  # LVS调度类型NAT/DR/TUN/FNAT。
    persistence_timeout 50
    protocol TCP  # 健康检查用的是TCP还是UDP
    syn_proxy
    laddr_group_name laddr_g1

    real_server $node1 8443 {  # 后端真实节点主机，其端口必须与Vport的端口一致
        weight 1  # 该实节点权重
        TCP_CHECK {  # 健康检查方式
        connect_timeout 8  # 连接超时时间
        nb_get_retry 3  # 重连次数
        delay_before_retry 3  # 重连间隔
        connect_port 8443  # 检查的端口
        }
    }

    real_server $node2 8443 {
        weight 1              
        TCP_CHECK {
        connect_timeout 8       
        nb_get_retry 3
        delay_before_retry 3
        connect_port 8443
        }
    }
}
```

!!! quote "更多配置项说明参考"
    <http://outofmemory.cn/wiki/keepalived-configuration>

## 常用命令

1. 启动keepalived：`service keepalived start`或`systemctl start keepalived.service`
1. 查看转发结果：`ipvsadm -ln`
1. 查看进程状态：`ps -ef | grep keepalived`

!!! quote "更多命令参考"
    [LVS转发问题抓包定位](../LVS转发问题抓包定位)
