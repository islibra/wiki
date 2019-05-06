# 路由Routing

跨subnet连通。

VM通过bridge与host的虚拟VLAN网卡连通，host通过交换机与路由连通，路由上配置多个VLAN的网关地址。

## KVM实现 - L3 agent

在控制节点或网络节点运行虚拟router。

配置文件：`/etc/neutron/l3_agent.ini`

!!! example
    - bridge: `interface_driver = neutron.agent.linux.interface.BridgeInterfaceDriver`
    - open vswitch: `interface_driver = neutron.agent.linux.interface.OVSInterfaceDriver`

查看agent列表：`neutron agent-list`

实现原理：在bridge上增加TAP设备连接router的网关。

- 查看router列表：`neutron router-list`
- 查看namespace: `ip netns`  
    qrouter-routerid
- 查看router中的veth interface配置：`ip netns exec qrouter-routerid ip a`
- 查看router中的路由表：`ip netns exec qrouter-routrtid kernel IP routing table`

## 常用网络命令

- ip a
- ping x
- route
- traceroute
