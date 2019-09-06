# kafka

!!! abstract "官方网站: <http://kafka.apache.org/>"

对标产品：

- kafka
- rabbitmq
- activemq

## Quickstart

1. 下载地址: <https://www.apache.org/dyn/closer.cgi?path=/kafka/2.3.0/kafka_2.12-2.3.0.tgz>, <http://ftp.cuhk.edu.hk/pub/packages/apache.org/kafka/2.3.0/kafka_2.12-2.3.0.tgz>
1. 解压: `$ tar -zxvf kafka_2.12-2.3.0.tgz`
1. 启动zookeeper: `$ bin/zookeeper-server-start.sh config/zookeeper.properties`, 端口号2181
1. 启动kafka: `$ bin/kafka-server-start.sh config/server.properties`, 端口号9092
1. 创建topic: `$ bin/kafka-topics.sh --create --bootstrap-server localhost:9092 --replication-factor 1 --partitions 1 --topic hellokafka`
1. 查询topic:

    ```bash
    $ bin/kafka-topics.sh --list --bootstrap-server localhost:9092
    hellokafka
    ```

1. 发送消息:

    ```bash
    $ bin/kafka-console-producer.sh --broker-list localhost:9092 --topic hellokafka
    >the first msg
    >the second msg
    ```

1. 消费消息:

    ```bash
    $ bin/kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic hellokafka --from-beginning
    the first msg
    the second msg
    ```

1. 部署多个broker:

    ```bash
    $ cp config/server.properties config/server-1.properties
    $ cp config/server.properties config/server-2.properties

    $ vim config/server-1.properties
    broker.id=1
    listeners=PLAINTEXT://:9093
    log.dirs=/tmp/kafka-logs-1

    $ vim config/server-2.properties
    broker.id=2
    listeners=PLAINTEXT://:9094
    log.dirs=/tmp/kafka-logs-2

    $ bin/kafka-server-start.sh config/server-1.properties &
    $ bin/kafka-server-start.sh config/server-2.properties &
    ```

1. 创建多副本topic:

    ```bash
    $ bin/kafka-topics.sh --create --bootstrap-server localhost:9092 --replication-factor 3 --partitions 1 --topic multikafka

    $ bin/kafka-topics.sh --describe --bootstrap-server localhost:9092 --topic multikafka
    Topic:multikafka        PartitionCount:1        ReplicationFactor:3     Configs:segment.bytes=1073741824
        # 每行显示一个Partition, Leader随机选取, 可读写, Isr为当前alive的Replicas
        Topic: multikafka       Partition: 0    Leader: 1       Replicas: 1,2,0 Isr: 1,2,0
    ```

1. 发送消息:

    ```bash
    $ bin/kafka-console-producer.sh --broker-list localhost:9092 --topic multikafka
    >my first msg
    >my sec msg
    ```

1. 消费消息:

    ```bash
    $ bin/kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic multikafka --from-beginning
    my first msg
    my sec msg
    ```

    > 使用`Ctrl + C`退出

1. 故障演练:

    ```bash
    $ ps aux | grep server-1.properties
    $ kill -9 3019

    $ bin/kafka-topics.sh --describe --bootstrap-server localhost:9092 --topic multikafka
    Topic:multikafka        PartitionCount:1        ReplicationFactor:3     Configs:segment.bytes=1073741824
        Topic: multikafka       Partition: 0    Leader: 2       Replicas: 1,2,0 Isr: 2,0
    ```

1. 使用Kafka Connect导入导出数据:

    ```bash
    $ echo -e "foo\nbar" > data.txt
    $ cat data.txt
    foo
    bar

    # 以standalone模式创建两个connector
    # connect-standalone.properties指定kafka服务器和序列化格式
    # connect-file-source.properties指定源文件和topic
    # connect-file-sink.properties指定目的文件和topic
    $ bin/connect-standalone.sh config/connect-standalone.properties config/connect-file-source.properties config/connect-file-sink.properties

    $ cat test.sink.txt
    foo
    bar

    $ bin/kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic connect-test --from-beginning
    {"schema":{"type":"string","optional":false},"payload":"foo"}
    {"schema":{"type":"string","optional":false},"payload":"bar"}

    $ echo another msg >> data.txt
    $ cat data.txt
    foo
    bar
    another msg
    $ cat test.sink.txt
    foo
    bar
    another msg
    $ bin/kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic connect-test --from-beginning
    {"schema":{"type":"string","optional":false},"payload":"foo"}
    {"schema":{"type":"string","optional":false},"payload":"bar"}
    {"schema":{"type":"string","optional":false},"payload":"another msg"}
    ```

1. 使用Kafka Streams构建应用: <http://kafka.apache.org/23/documentation/streams/quickstart>


!!! quote "参考链接"
    <http://kafka.apache.org/quickstart>


## 安全特性

1. 使用 {==SSL==} 或 {==SASL==} 进行clients(producers, consumers), other brokers, tools到brokers连接的认证
    - SASL/GSSAPI(Kerberos)
    - SASL/PLAIN
    - SASL/SCRAM-SHA-256, SASL/SCRAM-SHA-512
    - SASL/OAUTHBEARER

1. brokers到ZooKeeper之间的认证
1. 使用 {==SSL==} 对brokers到clients, other brokers, tools之间的传输通道加密
1. clients读写操作授权
1. 外部授权服务通过插件方式集成

### 客户端配置SSL

```bash tab="配置"
$ vim client-ssl.properties
security.protocol=SASL_SSL
sasl.mechanism=PLAIN
ssl.truststore.location=/var/private/ssl/client.truststore.jks
ssl.truststore.password=test1234
# 可选参数
ssl.provider
ssl.cipher.suites
ssl.enabled.protocols=TLSv1.2,TLSv1.1,TLSv1
ssl.truststore.type=JKS
ssl.keystore.type=JKS
```

```bash tab="使用"
$ kafka-console-producer.sh --broker-list localhost:9093 --topic test --producer.config client-ssl.properties
$ kafka-console-consumer.sh --bootstrap-server localhost:9093 --topic test --consumer.config client-ssl.properties
```

### SASL

#### JAAS(Java Authentication and Authorization Service)

##### 客户端配置JAAS

1. sasl.jaas.config

    ```bash
    $ vim client-ssl.properties
    sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="alice" password="alice-secret";
    ```

1. static JAAS config file, java.security.auth.login.config

    ```bash
    $ vim /etc/kafka/kafka_client_jaas.conf
    KafkaClient {
        com.sun.security.auth.module.Krb5LoginModule required
        useKeyTab=true
        storeKey=true
        keyTab="/etc/security/keytabs/kafka_client.keytab"
        principal="kafka-client-1@EXAMPLE.COM";
    };
    ```

    增加JVM参数: `-Djava.security.auth.login.config=/etc/kafka/kafka_client_jaas.conf`


!!! quote "参考链接"
    <https://kafka.apache.org/documentation/#security>


### Java实现

```java
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.StringSerializer;

import java.util.Properties;
import java.util.concurrent.ExecutionException;

public class KafkaPublisher {

    public static void main(String args[])
    {
        System.out.println("Start");

        Properties props = new Properties();
        props.put("bootstrap.servers", "127.0.0.1:9092,127.0.0.1:9093,127.0.0.1:9094");
        props.put("acks", "all");
        props.put("retries", 0);
        props.put("linger.ms", 1);
        props.put("transaction.timeout.ms", 15000);
        props.put("request.timeout.ms", 15000);
        props.put("key.serializer", StringSerializer.class);
        props.put("value.serializer", StringSerializer.class);
        props.put("security.protocol", "SASL_SSL");
        props.put("sasl.mechanism", "PLAIN");
        props.put("ssl.truststore.location", "/home/xxx/client.truststore.jks");
        props.put("ssl.truststore.password", "xxx");
        props.put("sasl.jaas.config", "org.apache.kafka.common.security.plain.PlainLoginModule required username=\"alice\" password=\"alice-secret\";");
        props.put("ssl.endpoint.identification.algorithm", "");

        Producer<String, String> producer = new KafkaProducer(props);
        String msg = "hello";
        try {
            producer.send(new ProducerRecord("mytopic", msg)).get();
        } catch (InterruptedException e) {
            System.out.println(e);
        } catch (ExecutionException e) {
            System.out.println(e);
        }
        producer.flush();

        System.out.println("End");
    }
}
```


## 概念

- topic消息的分类
- producer主动push消息到topic(broker)
- broker, kafka集群，保存消息
- consumer订阅topic，从broker主动pull消息进行消费

!!! tip "消息持久化到本地磁盘。"

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
