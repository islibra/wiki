# kafka

!!! quote "官方网站: <http://kafka.apache.org/>"

对标产品：

- rocketmq
- rabbitmq
- activemq


## I. 主打特色

### II. 核心能力

- 高吞吐: 低至 2ms 时延
- 可扩展: {==1k brokers，百千 partition，万亿(trillion)消息单日，petabytes 级数据==}
- 持久化存储
- 高可用: 支持跨 region, 跨 avilability zone

### II. 周边生态

- STREAM: 通过 join aggregation filter transformation 等方式进行流处理
- CONNECT: 对接 Postgres JMS Elasticsearch AWS S3 等多种事件源
- 多语言客户端库: Java Scala Go Python C/C++ REST API
- 开源工具

### II. 可信易用

- 对于关键任务, 保证消息顺序，0 丢失, 单次处理
- 数千组织, 超 500 万下载
- 社区 top 5
- 丰富的线上资源: 文档，在线教程

## I. 关键能力(streams of events)

1. publish(write), subscribe to(read), import/export
1. store
1. process, occur or retrospectively

## I. 概念

- **server**(broker/Connect) 和 **client**(app/microservice) 使用 **TCP** 协议通信
    - broker, kafka集群，保存消息

- **event**
    - optional metadata header
    - Event key: "Alice"
    - Event value: "Made a payment of $200 to Bob"
    - Event timestamp: "Jun. 25, 2020 at 2:06 p.m."

- **producer** publish 消息到 topic(broker)
- **consumer** 订阅 topic，从 broker 主动 pull 消息进行消费
- **topic**: 消息的分类, {==用户可按照 topic 自定义消息保留时间，kafka 的性能与保留的数据量大小无关。==}
- **partition** 使得对 topic 读写可以并行。同一个 event key 的消息被写入同一个 partition，分区内有序。
- **replica** 保证高可用


## I. Quickstart

1. 下载地址: <https://www.apache.org/dyn/closer.cgi?path=/kafka/2.3.0/kafka_2.12-2.3.0.tgz>, <http://ftp.cuhk.edu.hk/pub/packages/apache.org/kafka/2.3.0/kafka_2.12-2.3.0.tgz>
1. 解压: `$ tar -zxvf kafka_2.12-2.3.0.tgz`
1. 启动zookeeper: `$ bin/zookeeper-server-start.sh config/zookeeper.properties`

    > 端口号, clientPort=2181  
    > 监听IP, clientPortAddress=x.x.x.x

1. 启动kafka: `$ bin/kafka-server-start.sh config/server.properties`, 端口号9092

### II. 配置

#### III. 日志保留策略

- 日志保留时间: log.retention.hours=168, 默认 7 天
- 日志保留大小: log.retention.bytes=1073741824
- 单个日志文件大小: log.segment.bytes=1073741824
- 保留策略检查周期: log.retention.check.interval.ms=300000
- 清理策略: log.cleanup.policy=delete|compact

### II. Topic

1. 创建 topic 时指定分区和副本数

    ```sh
    bin/kafka-topics.sh --bootstrap-server localhost:9092 --create --replication-factor 1 --partitions 1 --topic hellokafka
    ```

    !!! tip "副本数不能多于 broker 数"

1. 创建 topic 时指定阈值策略

    ```sh
    bin/kafka-topics.sh --bootstrap-server localhost:9092 --create --topic deltp --config cleanup.policy=delete,retention.ms=259200000
    ```

1. 查询 topic 列表

    ```bash
    bin/kafka-topics.sh --bootstrap-server localhost:9092 --list
    ```

1. 查看 topic 配置

    ```sh
    bin/kafka-topics.sh --bootstrap-server localhost:9092 --topic klient --describe
    Topic: klient   PartitionCount: 3       ReplicationFactor: 1    Configs: cleanup.policy=delete,segment.bytes=1073741824,retention.ms=259200000
            Topic: klient   Partition: 0    Leader: 0       Replicas: 0     Isr: 0
            Topic: klient   Partition: 1    Leader: 0       Replicas: 0     Isr: 0
            Topic: klient   Partition: 2    Leader: 0       Replicas: 0     Isr: 0
    ```

    ```sh
    bin/kafka-configs.sh --bootstrap-server localhost:9092 --describe --entity-name hellokafka --entity-type topics
    Dynamic configs for topic hellokafka are:
      cleanup.policy=delete sensitive=false synonyms={DYNAMIC_TOPIC_CONFIG:cleanup.policy=delete, DEFAULT_CONFIG:log.cleanup.policy=delete}
      retention.ms=86400000 sensitive=false synonyms={DYNAMIC_TOPIC_CONFIG:retention.ms=86400000}
    ```

1. 修改 topic 分区数

    ```sh
    bin/kafka-topics.sh --bootstrap-server localhost:9092 --alter --topic klient --partitions 6
    ```

    !!! tip "分区数只能增加不能减小"

    !!! tip "副本数只能通过 json 方式增加, 参见 <https://kafka.apache.org/21/documentation.html#basic_ops_increase_replication_factor>"

1. 修改 topic 保留策略 1 天

    ```sh
    bin/kafka-configs.sh --bootstrap-server localhost:9092 --alter --entity-name hellokafka --entity-type topics --add-config retention.ms=86400000,cleanup.policy=delete|compact
    ```

### II. 消息

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


## I. 集群配置

1. 复制 server.properties
1. 修改 broker.id=0
1. 修改 listeners=PLAINTEXT://:9092
1. 修改 log.dirs=/tmp/kafka-logs
1. 修改 zookeeper.connect=localhost:2181

!!! quote "[【消息队列 MQ 专栏】消息队列之 Kafka](https://mp.weixin.qq.com/s/eyXr9Df6GcfvdYHpy_qyZg)"


## I. zookeeper 在 kafka 中的应用

- producer和consumer都配置为zkclient

1. 记录 broker 连接信息: `[zk: 127.0.0.1:2181(CONNECTED) 9] get /brokers/ids/0`

    ```json
    {
      "listener_security_protocol_map": {
        "PLAINTEXT": "PLAINTEXT"
      },
      "endpoints": [
        "PLAINTEXT://DESKTOP-22OLCTA.china.huawei.com:9092"
      ],
      "jmx_port": -1,
      "host": "DESKTOP-22OLCTA.china.huawei.com",
      "timestamp": "1599207237743",
      "port": 9092,
      "version": 4
    }
    ```

1. 记录 topic 信息
    - /brokers
        - /topics
            - /hellokafka

                ```json
                {
                  "version": 2,
                  "partitions": {
                    "0": [
                      0
                    ]
                  },
                  "adding_replicas": {},
                  "removing_replicas": {}
                }
                ```

                - /partitions
                    - /0
                        - /state

                            ```json
                            {
                              "controller_epoch": 1,
                              "leader": 0,
                              "version": 1,
                              "leader_epoch": 0,
                              "isr": [
                                0
                              ]
                            }
                            ```

1. 记录 topic 配置信息
    - /config
        - /topics
            - /hellokafka

                ```json
                {
                  "version": 1,
                  "config": {
                    "cleanup.policy": "delete",
                    "retention.ms": "86400000"
                  }
                }
                ```


## I. 架构

- 一个 **topic** 划分为多个 **partition**, 单个 partition 内保证消息有序
- partition(**leader**) 均匀的分布在多个 **broker**
- 每个 partition(leader) 设置多个 **replica**, 分布在另外的 broker
- consumer 可以按照 **group** 接收消费消息, 一个 group 中只有随机一个 consumer 可以消费一次消息

!!! quote "[震惊了！原来这才是 Kafka！（多图+深入）](https://mp.weixin.qq.com/s/d9KIz0xvp5I9rqnDAlZvXw)"


## I. 安全特性

1. 使用 {==SSL==} 或 {==SASL==} 进行 clients(producers, consumers), other brokers, tools 到 **brokers** 连接的 **认证**
    - SASL/GSSAPI(Kerberos), {>>starting at version 0.9.0.0<<}
    - SASL/PLAIN, {>>starting at version 0.10.0.0<<}
    - SASL/SCRAM-SHA-256, SASL/SCRAM-SHA-512, {>>starting at version 0.10.2.0<<}
    - SASL/OAUTHBEARER, {>>starting at version 2.0<<}

1. brokers 到 ZooKeeper 之间的 **认证**
1. 使用 {==SSL==} 对 **brokers** 到 clients, other brokers, tools 之间的传输 **通道加密**
1. clients 读写操作 **授权**
1. 外部授权服务通过插件方式集成

### II. 使用 SSL 进行加密和认证

#### III. 创建 CA

1. 使用 **openssl** 创建 CA

    ```sh hl_lines="2"
    # 使用 AES256CBC 加密生成 RSA4096 私钥
    openssl genrsa -out ca.key -aes256 -passout pass:xxx 4096

    # 使用私钥直接创建 CA 证书
    openssl req -new -x509 -days 3650 -key ca.key -out ca.cer
    Country Name (2 letter code) [XX]:CN
    State or Province Name (full name) []:GuangDong
    Locality Name (eg, city) [Default City]:ShenZhen
    Organization Name (eg, company) [Default Company Ltd]:XXX
    Organizational Unit Name (eg, section) []:CLOUD
    Common Name (eg, your name or your servers hostname) []:OSC
    Email Address []:
    ```

- 使用 **keytool** 将 CA 添加到 client 的 truststore

    ```sh hl_lines="2"
    keytool -import -file ca.cer -keystore client.truststore.jks -alias caroot
    Enter keystore password:
    Re-enter new password:
    Trust this certificate? [no]:  yes
    Certificate was added to keystore
    ```

    > 如果在 broker 中配置了认证客户端: `ssl.client.auth=requested/required`, 则需要生成 server.truststore.jks

#### III. 生成 broker 私钥和证书

1. 使用 **keytool** 为 broker 生成私钥和证书, 并存入 jks

    ```sh hl_lines="8"
    # -genkeypair: 生成密钥对
    # -validity: 证书有效期(天)
    # -sigalg: 签名算法
    # -keystore server.keystore.jks: keystore 文件名称
    # -alias: 保存在 keystore 中的别名
    # -ext SAN=DNS:{FQDN}: 添加 Host Name 校验字段
    keytool -genkeypair -keyalg RSA -keysize 4096 -validity 3650 -sigalg SHA256withRSA -keystore server.keystore.jks -alias server -ext SAN=DNS:{FQDN}
    Enter keystore password:
    Re-enter new password:
    What is your first and last name?
      [Unknown]:  OSC
    What is the name of your organizational unit?
      [Unknown]:  CLOUD
    What is the name of your organization?
      [Unknown]:  XXX
    What is the name of your City or Locality?
      [Unknown]:  ShenZhen
    What is the name of your State or Province?
      [Unknown]:  GuangDong
    What is the two-letter country code for this unit?
      [Unknown]:  CN
    Is CN=OSC, OU=CLOUD, O=XXX, L=ShenZhen, ST=GuangDong, C=CN correct?
      [no]:  yes

    # 也可以直接使用
    keytool -genkeypair -keyalg RSA -keysize 4096 -validity 3650 -sigalg SHA256withRSA -keystore server.keystore.jks -alias server -dname "CN=OSC, OU=CLOUD, O=XXX, L=ShenZhen, ST=GuangDong, C=CN" -storepass 123456
    ```

1. 验证生成的证书

    ```sh
    keytool -list -v -keystore server.keystore.jks
    ```

#### III. 签名证书

1. 从 keystore 中导出证书请求

    ```sh
    keytool -certreq -file server.csr -keystore server.keystore.jks -alias server
    ```

1. 使用 CA 对证书签名

    ```sh
    openssl x509 -req -extfile /etc/pki/tls/openssl.cnf -extensions v3_req -days 3650 -sha256 -CAkey ca.key -CA ca.cer -in server.csr -out server.cer -CAcreateserial [-passin pass:{ca.key.password}]
    ```

1. 将 CA 和已签名的证书导入 keystore

    ```sh
    keytool -import -file ca.cer -keystore server.keystore.jks -alias caroot
    keytool -import -file server.cer -keystore server.keystore.jks -alias server
    ```

#### III. 配置 broker server.properties

``` hl_lines="1"
# 如果 inter-broker 未开启 SSL, 则需要同时指定 PLAINTEXT 和 SSL
listeners=PLAINTEXT://host.name:port,SSL://host.name:port

# 开启 broker 之间 SSL
security.inter.broker.protocol=SSL
ssl.keystore.location=/var/private/ssl/server.keystore.jks
ssl.keystore.password=test1234
ssl.key.password=test1234
ssl.truststore.location=/var/private/ssl/server.truststore.jks
ssl.truststore.password=test1234
# 安全的随机数发生器
# SHA1PRNG 支持单 broker 50MB/sec 生产消息 + 副本流量
ssl.secure.random.implementation=SHA1PRNG

# 可选配置
# 认证客户端
# required: 推荐
# requested: 请求客户端证书, 但无证书仍然可以连接
ssl.client.auth=none
# 加密套件
ssl.cipher.suites=
# 协议
ssl.enabled.protocols=TLSv1.2,TLSv1.1,TLSv1
ssl.keystore.type=JKS
ssl.truststore.type=JKS
# 关闭 Host Name 校验(新版本默认开启 ssl.endpoint.identification.algorithm=HTTPS)
ssl.endpoint.identification.algorithm=
```

> 对于动态配置的 broker listeners 关闭 Host Name 校验: `bin/kafka-configs.sh --bootstrap-server localhost:9093 --entity-type brokers --entity-name 0 --alter --add-config "listener.name.internal.ssl.endpoint.identification.algorithm="`

开启 Host Name 校验后客户端校验 fully qualified domain name (FQDN)

- Common Name (CN)
- Subject Alternative Name (SAN): 推荐, 允许声明多个 DNS

检查 SSL 配置是否正确: `openssl s_client -debug -connect localhost:9093 -tls1`, 可显示证书信息

#### III. 配置 client

```bash
$ vim client-ssl.properties
security.protocol=SSL
ssl.truststore.location=/var/private/ssl/client.truststore.jks
ssl.truststore.password=test1234

# 如果配置了认证客户端
ssl.keystore.location=/var/private/ssl/client.keystore.jks
ssl.keystore.password=test1234
ssl.key.password=test1234

# 可选参数
ssl.provider
ssl.cipher.suites
ssl.enabled.protocols=TLSv1.2,TLSv1.1,TLSv1
ssl.truststore.type=JKS
ssl.keystore.type=JKS
ssl.endpoint.identification.algorithm=

# 验证连接
$ bin/kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic test --consumer.config config/consumer.properties
$ bin/kafka-console-producer.sh --bootstrap-server localhost:9092 --topic test --producer.config config/producer.properties
```


#### III. FAQ

- General SSLEngine problem

    ??? faq "展开详细"
        ```sh
        [2020-07-15 07:36:43,599] ERROR [KafkaServer id=9] Fatal error during KafkaServer startup. Prepare to shutdown (kafka.server.KafkaServer)
        org.apache.kafka.common.KafkaException: org.apache.kafka.common.config.ConfigException: Invalid value javax.net.ssl.SSLHandshakeException: General SSLEngine problem for configuration A client SSLEngine created with the provided settings can't connect to a server SSLEngine created with those settings.
                at org.apache.kafka.common.network.SslChannelBuilder.configure(SslChannelBuilder.java:74)
                at org.apache.kafka.common.network.ChannelBuilders.create(ChannelBuilders.java:157)
                at org.apache.kafka.common.network.ChannelBuilders.serverChannelBuilder(ChannelBuilders.java:97)
                at kafka.network.Processor.<init>(SocketServer.scala:724)
                at kafka.network.SocketServer.newProcessor(SocketServer.scala:367)
                at kafka.network.SocketServer.$anonfun$addDataPlaneProcessors$1(SocketServer.scala:252)
                at kafka.network.SocketServer.addDataPlaneProcessors(SocketServer.scala:251)
                at kafka.network.SocketServer.$anonfun$createDataPlaneAcceptorsAndProcessors$1(SocketServer.scala:214)
                at kafka.network.SocketServer.$anonfun$createDataPlaneAcceptorsAndProcessors$1$adapted(SocketServer.scala:211)
                at scala.collection.mutable.ResizableArray.foreach(ResizableArray.scala:62)
                at scala.collection.mutable.ResizableArray.foreach$(ResizableArray.scala:55)
                at scala.collection.mutable.ArrayBuffer.foreach(ArrayBuffer.scala:49)
                at kafka.network.SocketServer.createDataPlaneAcceptorsAndProcessors(SocketServer.scala:211)
                at kafka.network.SocketServer.startup(SocketServer.scala:122)
                at kafka.server.KafkaServer.startup(KafkaServer.scala:266)
                at kafka.server.KafkaServerStartable.startup(KafkaServerStartable.scala:44)
                at kafka.Kafka$.main(Kafka.scala:82)
                at kafka.Kafka.main(Kafka.scala)
        Caused by: org.apache.kafka.common.config.ConfigException: Invalid value javax.net.ssl.SSLHandshakeException: General SSLEngine problem for configuration A client SSLEngine created with the provided settings can't connect to a server SSLEngine created with those settings.
                at org.apache.kafka.common.security.ssl.SslFactory.configure(SslFactory.java:100)
                at org.apache.kafka.common.network.SslChannelBuilder.configure(SslChannelBuilder.java:72)
                ... 17 more
        ```

    1. 由 openssl 生成的私钥未导入 keystore
    1. 生成 CA 证书的时候, 未指定 IsCA: true


### II. 代码梳理

- kafka/
    - core/src/main/scala/kafka/
        - Kafka.scala.main()
        - server/
            - kafkaServerStartable.startup()
            - KafkaServer.scala.startup()

        - network
            - SocketServer.startup()
                - createDataPlaneAcceptorsAndProcessors()
                    - addDataPlaneProcessors()
                        - newProcessor()

    - clients/src/main/java/org.apache.kafka/common/
        - network/ChannelBuilders.java.serverChannelBuilder()
            - create()
                - SslChannelBuilder.configure()

        - security/ssl/
            - SslFactory.java.configure()
            - SslEngineBuilder.java, 在构造方法中创建 keystore, truststore, sslContext
                - createKeystore()
                - createTruststore()
                - createSSLContext()
                    - SecurityStore.load()
                        - java.security.KeyStore.load(), 加载 keystore


### II. ZooKeeper 认证

从 ZooKeeper 3.5.x/Kafka 2.5 版本开始支持 SASL/mTLS 认证

### 使用 SASL 进行认证

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


## I. 性能测试

### II. Kafka 性能测试脚本

- $KAFKA_HOME/bin/kafka-producer-perf-test.sh: 测试 **producer** 性能
    - 总共发送消息量(MB)
    - 每秒发送消息量(MB/second)
    - 总共发送消息数(records)
    - 每秒发送消息数(records/second)

    参数 | 说明
    --- | ---
    broker-list | kafka 服务器 ip:port
    topics | 生产消息的 topic
    messages | 总共发送消息数
    message-size | 每条消息大小
    batch-size | 每次批量发送的消息数
    threads | 线程数
    request-timeout-ms | 一个消息请求发送超时时间
    producer-num-retries | 一个消息失败发送重试次数

- $KAFKA_HOME/bin/kafka-consumer-perf-test.sh: 测试 **consumer** 性能

    参数 | 说明
    --- | ---
    zookeeper | zookeeper 端口配置
    topic | 消费的 topic
    group | 消费者组名称
    messages | 总共消费消息数
    fetch-size | 每次向 kafka broker 请求消费大小
    threads | 线程数
    socket-buffer-sizesocket | 缓冲大小
    consumer.timeout.ms | 超时时间

### II. Yammer Metrics

Kafka 使用 Yammer Metrics 在服务端进行指标上报。

#### III. 收集

1. Meters
1. Gauges
1. Counters
1. Histograms
1. Timers
1. Health Checks

#### III. 报告

1. Console Reporter
1. JMX Reporter
1. HTTP Reporter
1. CSV Reporter
1. SLF4J Reporter
1. Ganglia Reporter
1. Graphite Reporter

!!! quote "参考链接"
    - [Metrics](https://metrics.dropwizard.io/)
    - [dropwizard/metrics](https://github.com/dropwizard/metrics)

### II. JConsole(Java自带) 查看单台服务器 Metrics

启用 Kafka 的 JMX Reporter: `export JMX_PORT=19797`

### II. Kafka Manager(Yahoo开源) 查看整个集群的 Metrics

通过 ZooKeeper 地址和 Kafka 版本添加集群

### II. 性能测试

- 吞吐率
    - MB/second
    - records/seccond
    - 100Byte/Payload

- 单 Broker CPU 和内存使用情况

### II. 影响因子

- 创建 topic: `bin/kafka-topics.sh --zookeeper localhost:2181/kafka --create --topic test-rep-one --partitions 6 --replication-factor 1`
- 随 **producer 数量** 线性增长, 单 producer 1280 K x 100Byte = 128MB
- 随 **线程数量** 增长
    - 1个线程: `bin/kafka-producer-perf-test.sh --broker-list m103:9092,m105:9092 --topics test-rep-one --messages 50000000 --threads 1`

- **批处理大小** 具有峰值
- 随 **Message Size** 越大,  MB/second 越大, records/second 越小
- **异步** 大于同步
    - 同步: `bin/kafka-producer-perf-test.sh --broker-list m103:9092,m105:9092 --topics test-rep-two_2 --messages 50000000 --threads 2 --sync`
    - 异步: `bin/kafka-producer-perf-test.sh --broker-list m103:9092,m105:9092 --topics test-rep-two_2 --messages 50000000 --threads 2 --batch-size 5000 --request-timeout-ms 100000`

- 当 **Partition 数量** 小于 **Broker 个数** 时, 随 Partition 数量线性增长; Partition 数量大于 Broker 个数时, 总吞吐量并未提升, 整数倍性能最佳(均匀分布)
    - `bin/kafka-producer-perf-test.sh  --broker-list m103:9092,m105:9092 --topics test-rep-one-part --messages 50000000 --threads 1 --request-timeout-ms 10000`

- 随 **Replica** 数量增加, 吞吐率下降, 但下降速度减缓(并行复制)
- 随 **consumer 数量** 线性增长, 单 consumer 3060 K x 100Byte = 306MB, 多 consumer 以 Partition 为分配单位
- **一对 producer/consumer** 1,215,613 records/second x 100Byte = 121MB

!!! quote "参考链接"
    - [Kafka设计解析（五）Kafka性能测试方法及Benchmark报告](http://www.jasongj.com/2015/12/31/KafkaColumn5_kafka_benchmark/)
    - [kafka性能基准测试](https://www.cnblogs.com/xiaodf/p/6023531.html)


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
