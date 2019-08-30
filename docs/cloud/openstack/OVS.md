# OVS

Open vSwitch

??? note "名词解释"
    - NIC: 网卡
    - TAP/TUN: Linux内核实现的一对虚拟网络设备, TAP工作在二层, TUN工作在三层。虚拟机的vNIC与TAP相连, 相当于物理机NIC连接eth。

        > 当一个TAP设备被创建时, 在Linux设备文件目录下会生成一个对应的字符设备文件, 用户程序可以像打开普通文件一样对这个文件进行读写。

    - OpenFlow: 流表协议, 用于控制面和数据面通信

## 架构

!!! todo "图先欠着(2)"

![](assets/markdown-img-paste-20190830201849722.png)

![](assets/markdown-img-paste-20190830201914743.png)

![](assets/markdown-img-paste-20190830201937207.png)

![](assets/markdown-img-paste-20190830201948286.png)

- 控制面: OpenFlow controller, 管理OVS中的流表, 通过向OVS下发流表规则控制数据流向
- 数据面(转发模块):
    - 用户态: 守护进程ovs-vswitchd, 轻量级数据库服务ovsdb-server
    - 内核态: datapath, 从物理网卡NIC或VM的虚拟网卡vNIC收到包, 第一次交由ovs-vswitchd决定丢弃或从哪个口传出, 并缓存动作

## 组件

- ovs-ofctl: 基于OpenFlow协议对OVS进行监控和管理

    ```bash
    # 输出端口信息
    $ ovs-ofctl show br-xxx
    ```

- ovs-vsctl: 查询和更新ovs-vswitchd的配置

    ```bash
    # 显示主机上已有的网桥和端口信息
    $ ovs-vsctl show
    ```


!!! quote "参考链接"
    - [从 Bridge 到 OVS，探索虚拟交换机](https://mp.weixin.qq.com/s/2KaHYOxyvZw1B6PhmjN_vw)
    - [OVS 总体架构、源码结构及数据流程全面解析](https://mp.weixin.qq.com/s/p-_ygYnOwSbFSx3fsD7iTQ)
