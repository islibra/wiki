# 0x04_k8s_rolling_update_healthcheck

## rolling_update

指定保留最近几个revision：

```yaml
spec:
    revisionHistoryLimit: 10
```

部署并更新应用：`kubectl apply -f httpd.v1.yml --record`

查看revision历史记录：`kubectl rollout history depolyment httpd`

回滚到版本：`kubectl rollout undo deployment httpd --to-revision=1`

## healthcheck

默认的健康检查：通过Dockfile的ENTRYPOINT或CMD指定的命令返回非零，则认为容器故障，根据restartPolicy重启容器。

### 存活探针Liveness

???+ tip
    **kubelet** 使用liveness probe确定应用程序处于 **运行状态** 但无法进一步操作。  
    决定是否 {==重启Pod==}。

```yaml tab="通过命令探测" hl_lines="17"
apiVersion: v1
kind: Pod
metadata:
  labels:
    test: liveness
  name: liveness-exec
spec:
  restartPolicy: OnFailure
  containers:
  - name: liveness
    image: k8s.gcr.io/busybox
    args:
    - /bin/sh
    - -c
    # 创建文件/tmp/healthy，30秒后删除
    - touch /tmp/healthy; sleep 30; rm -rf /tmp/healthy; sleep 600
    livenessProbe:
      exec:
        command:  # 检查/tmp/healthy文件是否存在，命令执行成功返回0
        - cat
        - /tmp/healthy
      initialDelaySeconds: 5  # 容器启动5秒后开始探测
      periodSeconds: 5  # 探测周期5秒，默认10秒，最小1秒
      timeoutSeconds: x  # 探测超时时间，默认1秒，最小1秒
      successThreshold: x  # 成功阈值，默认1，最小1，liveness固定1
      failureThreshold: x  # 如果探测3次失败，kill并重启容器，默认3，最小1
```

```yaml tab="通过GET请求探测" hl_lines="14"
apiVersion: v1
kind: Pod
metadata:
  labels:
    test: liveness
  name: liveness-http
spec:
  containers:
  - name: liveness
    image: k8s.gcr.io/liveness
    args:
    - /server
    livenessProbe:
      httpGet:  # [200, 400)的错误码为成功
        scheme: xxx  # 默认http
        host: xxx  # 主机名，默认pod IP
        port: 8080
        path: /healthz
        httpHeaders:
        - name: X-Custom-Header
          value: Awesome
      initialDelaySeconds: 3
      periodSeconds: 3
```

```yaml tab="TCP Socket探测" hl_lines="13 18"
apiVersion: v1
kind: Pod
metadata:
  name: goproxy
  labels:
    app: goproxy
spec:
  containers:
  - name: goproxy
    image: k8s.gcr.io/goproxy:0.1
    ports:
    - containerPort: 8080
    readinessProbe:
      tcpSocket:
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 10
    livenessProbe:
      tcpSocket:
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 20
```


### 可读性（就绪）探针Readiness

???+ tip
    **kubelet** 使用readiness probe确定容器是否已经就绪可以接受 **流量**。  
    控制哪些Pod作为 **service** 的 {==endpoint==}。

将`livenessProbe`替换为`readinessProbe`，通知Kubernetes将容器加入到Service负载均衡池中，对外提供服务。

探测成功将Pod READY设为可用，失败设为不可用。

可与Liveness同时使用。

!!! faq "Pod READY 0/1 STATUS Running"
    readinessProbe 检测失败, 参考: [pod应用生命周期（init容器，容器探针）](https://blog.csdn.net/weixin_44791884/article/details/105639917)


### 在Scale Up中的应用：

```yaml
readinessProbe:
    httpGet:  //请求返回的代码在200-400之间认为成功
        scheme: HTTP
        path: /healthy  //http://<container_ip>:8080/healthy
        port: 8080
    initalDelaySeconds: 10
    periodSeconds: 5
```

自定义判断逻辑：略


### 在Rolling Update中的应用：

```yaml
kind: Depolyment
metadata:
    name: app
spec:
    strategy:
        rollingUpdate:
            maxSurge: 25%  //滚动更新过程中副本总数超过DESIRED的上限，整数或百分比向上取整
            maxUnavailable: 25%  //滚动更新过程中不可用的副本总数或占DESIRED的最大比例，整数或百分比向下取整
    replicas: 10
    template:
```


???+ quote "参考链接"
    [配置Liveness和Readiness探针](https://k8smeetup.github.io/docs/tasks/configure-pod-container/configure-liveness-readiness-probes/)
