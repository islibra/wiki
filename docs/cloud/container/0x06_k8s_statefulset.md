# 0x06_k8s_statefulset

!!! tip "short: sts"

## I. 部署 nginx

```yaml
# 1.创建 Service
apiVersion: v1
kind: Service
metadata:
  name: nginx
  labels:
    app: nginx
spec:
  clusterIP: None
  ports:
  - port: 80
    name: web
  # 选择标签
  selector:
    app: nginx
---
# 2.创建 StatefulSet
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: web
spec:
  # 指定使用的 Service
  serviceName: "nginx"
  # 指定存储 PVC
  volumeClaimTemplates:
  - metadata:
      name: www
      # annotations:
        # volume.beta.kubernetes.io/storage-class: anything
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 1Gi
      storageClassName: "manual"
  # 指定副本数量
  replicas: 3
  # 选择标签
  selector:
    matchLabels:
      app: nginx  # has to match spec.template.metadata.labels
  # 指定 Pod
  template:
    metadata:
      labels:
        app: nginx  # has to match spec.selector.matchLabels
    spec:
      terminationGracePeriodSeconds: 10
      # 指定容器
      containers:
      - name: nginx
        image: nginx
        ports:
        - containerPort: 80
          name: web
        volumeMounts:
        - name: www
          mountPath: /usr/share/nginx/html
```

!!! quote "参考链接"
    - [StatefulSets - Kubernetes官方](https://kubernetes.io/zh/docs/concepts/workloads/controllers/statefulset/)
    - [kubernetes-handbook](https://jimmysong.io/kubernetes-handbook/concepts/statefulset.html)

### III. terminationGracePeriodSeconds

K8s 滚动升级的步骤:

1. K8s 首先启动新的 Pod
1. K8s 等待新的 Pod 进入 Ready 状态
1. K8s 创建 Endpoint，将新的 Pod 纳入负载均衡
1. K8s 移除与老 Pod 相关的 Endpoint，并且将老 Pod 状态设置为 Terminating，此时将不会有新的请求到达老 Pod
1. 同时 K8s 会给老 Pod 发送 SIGTERM 信号，并且等待 terminationGracePeriodSeconds 时间。(默认为30秒)
1. 超过 terminationGracePeriodSeconds 等待时间后， K8s 会强制结束老 Pod

!!! quote "[如何利用terminationGracePeriodSeconds 优雅地关闭你的服务？](https://damoshushu.github.io/2019/01/12/k8s-terminationGracePeriodSeconds/)"


## I. 部署 ZooKeeper

> 手动准备三个 1 GiB 的 PV。

### II. 准备 Docker 镜像

- Ubuntu/BusyBox/Alpine
- OpenJDK
- ZooKeeper

> 非 root 运行, zookeeper

> 安装目录: /opt/zookeeper

> 配置目录: /usr/etc/zookeeper

> 二进制目录: /usr/bin

> 数据目录: /var/lib/zookeeper

- zkGenConfig.sh: 生成 ZK 配置文件
    - /opt/kafka/conf/zoo.cfg
    - /opt/kafka/conf/log4j.properties
    - /opt/kafka/conf/java.env
    - /var/lib/zookeeper/data/myid

- zkOk.sh: 健康检查
- zkMetrics.sh

### II. 创建 ZooKeeper StatefulSet

```yaml
# 1.创建 Headless Service
apiVersion: v1
kind: Service
metadata:
  name: zk-hs
  labels:
    app: zk
spec:
  clusterIP: None
  ports:
  # follow leader 的 event log
  - port: 2888
    name: server
  # leader 选举
  - port: 3888
    name: leader-election
  selector:
    app: zk
---
# 2.创建 Service
apiVersion: v1
kind: Service
metadata:
  name: zk-cs
  labels:
    app: zk
spec:
  ports:
  - port: 2181
    name: client
  selector:
    app: zk
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: zk-cm
data:
  jvm.heap: "1G"
  tick: "2000"
  init: "10"
  sync: "5"
  client.cnxns: "60"
  snap.retain: "3"
  purge.interval: "0"
---
# 确保应用高可用, 了解 Pod 中断类型, 自动升级和扩缩容
apiVersion: policy/v1beta1
kind: PodDisruptionBudget
metadata:
  name: zk-pdb
spec:
  maxUnavailable: 1
  selector:
    matchLabels:
      app: zk
---
# 3.创建 StatefulSet
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: zk
spec:
  # 指定使用的 Service
  serviceName: zk-hs
  # 指定存储 PVC
  volumeClaimTemplates:
  - metadata:
      name: datadir
    spec:
      accessModes: [ "ReadWriteMany" ]
      resources:
        requests:
          storage: 1Gi
      storageClassName: "manual"
  # 指定副本数量
  replicas: 3
  updateStrategy:
    type: RollingUpdate
  podManagementPolicy: OrderedReady
  # 选择标签
  selector:
    matchLabels:
      app: zk
  # 指定 Pod
  template:
    metadata:
      labels:
        app: zk
    spec:
      # 反亲和
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchExpressions:
                  - key: "app"
                    operator: In
                    values:
                    - zk
              topologyKey: "kubernetes.io/hostname"
      # 安全上下文
      securityContext:
        runAsUser: 1001
        fsGroup: 1001
      # 指定容器
      containers:
      - name: kubernetes-zookeeper
        image: "k8s.gcr.io/kubernetes-zookeeper:1.0-3.4.10"
        imagePullPolicy: IfNotPresent
        resources:
          requests:
            memory: "1Gi"
            cpu: "0.5"
        ports:
        - containerPort: 2181
          name: client
        - containerPort: 2888
          name: server
        - containerPort: 3888
          name: leader-election
        volumeMounts:
        - name: datadir
          mountPath: /var/lib/zookeeper
        env:
        - name : ZK_REPLICAS
          value: "3"
        - name : ZK_ENSEMBLE
          value: "zk-0;zk-1;zk-2"
        - name: ZK_CLIENT_PORT
          value: "2181"
        - name: ZK_SERVER_PORT
          value: "2888"
        - name: ZK_ELECTION_PORT
          value: "3888"
        - name : ZK_HEAP_SIZE
          valueFrom:
            configMapKeyRef:
                name: zk-cm
                key: jvm.heap
        - name : ZK_TICK_TIME
          valueFrom:
            configMapKeyRef:
                name: zk-cm
                key: tick
        - name : ZK_INIT_LIMIT
          valueFrom:
            configMapKeyRef:
                name: zk-cm
                key: init
        - name : ZK_SYNC_LIMIT
          valueFrom:
            configMapKeyRef:
                name: zk-cm
                key: tick
        - name : ZK_MAX_CLIENT_CNXNS
          valueFrom:
            configMapKeyRef:
                name: zk-cm
                key: client.cnxns
        - name: ZK_SNAP_RETAIN_COUNT
          valueFrom:
            configMapKeyRef:
                name: zk-cm
                key: snap.retain
        - name: ZK_PURGE_INTERVAL
          valueFrom:
            configMapKeyRef:
                name: zk-cm
                key: purge.interval
        command:
        - sh
        - -c
        - zkGenConfig.sh && zookeeper-server-start.sh start-foreground
        readinessProbe:
          exec:
            command:
            - sh
            - -c
            - "zkOk.sh"
          initialDelaySeconds: 15
          timeoutSeconds: 5
        livenessProbe:
          exec:
            command:
            - sh
            - -c
            - "zkOk.sh"
          initialDelaySeconds: 15
          timeoutSeconds: 5
```

### II. 验证

```sh
$ kubectl exec zk-0 zkMetrics.sh
$ kubectl exec zk-0 zkCli.sh create /hello world
$ kubectl exec zk-1 zkCli.sh get /hello

# 唯一的 hostname
$ for i in 0 1 2; do kubectl exec zk-$i -- hostname; done
zk-0
zk-1
zk-2

# 唯一的 server ID
$ for i in 0 1 2; do echo "myid zk-$i";kubectl exec zk-$i -- cat /var/lib/zookeeper/data/myid; done
myid zk-0
1
myid zk-1
2
myid zk-2
3

# 唯一的 Fully Qualified Domain Name (FQDN)
# Pod 名称.Service 名称.Namespace.svc.cluster.local
$ for i in 0 1 2; do kubectl exec zk-$i -- hostname -f; done
zk-0.zk-hs.default.svc.cluster.local
zk-1.zk-hs.default.svc.cluster.local
zk-2.zk-hs.default.svc.cluster.local

# 查看 server 配置
# 以 myid 作为 server 的后缀
$ kubectl exec zk-0 -- cat /opt/zookeeper/conf/zoo.cfg
#This file was autogenerated DO NOT EDIT
clientPort=2181
dataDir=/var/lib/zookeeper/data
dataLogDir=/var/lib/zookeeper/data/log
tickTime=2000
initLimit=10
syncLimit=5
maxClientCnxns=60
minSessionTimeout=4000
maxSessionTimeout=40000
autopurge.snapRetainCount=3
autopurge.purgeInteval=12
server.1=zk-0.zk-hs.default.svc.cluster.local:2888:3888
server.2=zk-1.zk-hs.default.svc.cluster.local:2888:3888
server.3=zk-2.zk-hs.default.svc.cluster.local:2888:3888
```

!!! quote "[运行 ZooKeeper， 一个 CP 分布式系统 - Kubernetes官方](https://kubernetes.io/zh/docs/tutorials/stateful-application/zookeeper/)"
    中文版未更新及时, 查看英文版: [Running ZooKeeper, A Distributed System Coordinator]((https://kubernetes.io/zh/docs/tutorials/stateful-application/zookeeper/))


## I. 部署 Kafka

```yaml
# 1.创建 Headless Service
apiVersion: v1
kind: Service
metadata:
  name: kafka-svc
  labels:
    app: kafka
spec:
  clusterIP: None
  ports:
  - port: 9092
    name: server
  selector:
    app: kafka
---
# 2.创建 StatefulSet
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: kafka
spec:
  # 指定使用的 Service
  serviceName: kafka-svc
  # 指定存储 PVC
  volumeClaimTemplates:
  - metadata:
      name: datadir
    spec:
      accessModes: [ "ReadWriteMany" ]
      resources:
        requests:
          storage: 1Gi
      storageClassName: "manual"
  # 指定副本数量
  replicas: 3
  # 选择标签
  selector:
    matchLabels:
      app: kafka
  # 指定 Pod
  template:
    metadata:
      labels:
        app: kafka
    spec:
      # 反亲和
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchExpressions:
                  - key: "app"
                    operator: In
                    values:
                    - kafka
              topologyKey: "kubernetes.io/hostname"
        podAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
             - weight: 1
               podAffinityTerm:
                 labelSelector:
                    matchExpressions:
                      - key: "app"
                        operator: In
                        values:
                        - zk
                 topologyKey: "kubernetes.io/hostname"
      # 安全上下文
      securityContext:
        runAsUser: 1001
        fsGroup: 1001
      # 关闭服务
      terminationGracePeriodSeconds: 300
      # 指定容器
      containers:
      - name: kubernetes-kafka
        image: kafka:v1.0
        imagePullPolicy: IfNotPresent
        resources:
          requests:
            memory: "1Gi"
            cpu: 500m
        ports:
        - containerPort: 9092
          name: server
        volumeMounts:
        - name: datadir
          mountPath: /var/lib/kafka
        command:
        - sh
        - -c
        - "bin/kafka-server-start.sh config/server.properties \
          --override broker.id=${HOSTNAME##*-} \
          --override zookeeper.connect=10.97.205.89:2181"
        env:
        - name: KAFKA_HEAP_OPTS
          value : "-Xmx512M -Xms512M"
        - name: KAFKA_OPTS
          value: "-Dlogging.level=INFO"
```
