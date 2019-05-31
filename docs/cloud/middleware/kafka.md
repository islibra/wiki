# kafka

对标产品：

- kafka
- rabbitmq
- activemq

## 概念

- topic消息的分类
- producer主动push消息到topic(broker)
- broker, kafka集群，保存消息
- consumer订阅topic，从broker主动pull消息进行消费

!!! tip
    消息持久化到本地磁盘。

## zookeeper在kafka中的应用

- zk记录各结点IP端口
- producer和consumer都配置为zkclient

## 业务流程

1. 启动zk
1. 启动kafka
1. producer通过zk找到kafka结点，push消息
1. consumer通过zk找到broker，消费

## 使用场景

- 日志收集，收集各服务，并提供给各消费者
- 性能监控
- 解耦生产者和消费者，缓存消息
- 用户活动跟踪，监控分析数据挖掘
