# neutron

- 二层交换Switching：Linux Bridge, Open vSwitch(OVS)，创建VLAN, 创建基于隧道的Overlay网络VxLAN和GRE
- 三层路由Routing: 通过IP forwarding, iptables实现路由和NAT，使不同网段的instance之间，以及与外部网络通信。
- 负载均衡Load balancing(LBaaS): 将负载分发到多个instance
- 防火墙Firewalling
    - security group: 通过iptables限制instance网络数据包
    - FWaaS: 通过iptables限制路由包

## 网络资源

### network

二层广播域，在project下创建多个network。

- local: 单机lo
- flat: 无VLAN tagging
- VLAN: 具有802.1q tagging
- VxLAN: 唯一标识segmentation ID(VNI)，二层数据包封装成UDP包在三层传输
- GRE: 使用IP包封装

### subnet

IP地址池，一个network有多个subnet。

### port

虚拟交换机上的端口，定义IP和MAC。instance的虚拟网卡VIF(Virtual Interface)绑定到port时分配IP和MAC。一个subnet有多个port。

!!! abstract "映射关系"
    project 1:n network 1:n subnet 1:n port 1:1 VIF n:1 instance
