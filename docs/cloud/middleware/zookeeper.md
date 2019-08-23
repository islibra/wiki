# zookeeper

!!! abstract "官方网站: <https://zookeeper.apache.org/>"

分布式协调服务，在分布式系统中共享配置，协调锁资源，提供命名服务。

## 数据存储方式

以目录方式存储数据，数据结点叫做znode。

数据保存在内存中。

!!! example "Znode"
    - data
    - child
    - ACL
    - stat元数据

!!! warning
    适用于读多写少的场景，只用来存储少量状态和配置信息，不适合大规模业务数据。每个结点数据最大1M。

## API

- create
- delete
- exists
- getData
- setData
- getChildren

!!! tip "提示"
    在读操作上可以设置watch，在znode上注册触发器，当数据改变时触发事件，异步通知。

客户端与zookeeper集群服务器建立TCP连接。

## 集群架构

主从结构

- 写：主结点，同步到从结点
- 读：任意从结点

ZAB(ZooKeeper Atomic Broadcast)协议保证一致性，类似Paxos和Raft，单调一致性，依靠事务ID和版本号保证读写有序

- 崩溃恢复
    1. 选举：所有节点处于Looking状态，投票(ID, ZXID)，如果别人ZXID大，重新投给它。得票半数以上成为准Leader，转换为leading状态，其他成为following状态。
    2. 发现：所有从节点将最新的ZXID和事务日志发送给Leader，Leader将最大的epoch+1发给各follower，follower返回ACK和历史事务日志。
    3. 同步：将最新的历史事务日志同步给所有follower，半数以上同步成功。
- 主从数据同步
    - 客户端写请求发送给follower --> 转发给leader --> 广播propose消息给follower --> follower写日志并返回ACK --> Leader收到半数以上ACK，返回成功给客户端 --> 广播commit

!!! note "结点状态"
    - looking选举状态
    - following从结点
    - leading主结点

!!! note "最大ZXID"
    - 结点本地最新事务编号
        - epoch
        - 计数

## 应用

- 分布式锁，类似还有
    - memcached add
    - redis setnx
    - Chubby paxos算法
- 服务注册和发现，如阿里的RPC框架Dubbo
- 共享配置和状态信息，如Redis, Kafka, HBase, Hadoop

### zookeeper实现分布式锁

#### 结点类型

- 持久结点persistant
- 持久结点顺序结点persistant_sequential，根据创建时间给结点编号
- 临时结点ephemeral，创建结点的客户端断开后结点自动删除
- 临时顺序结点

#### 分布式锁

1. 获取锁：创建持久结点parentlock，创建临时顺序结点lock1，判断是第一个，获得锁，否，watch前一个结点。
1. 释放锁：
    - 删除lock1。
    - 断开自动删除

!!! quote "框架实现"
    apache curator

### redis实现分布式锁

1. 加锁：`setnx(key, 1)` --> `set(key, 1, 30, NX)` --> `threadid = Thread.currentThread.getid(); set(key, threadid, 30, NX)`删除前判断是否自己的线程ID防止误删（使用lua脚本实现原子性）
1. 解锁：`del(key)`
1. 锁超时：`expire(key, 30)`，{>>获得锁后，可以另外启动守护线程自动续期<<}
