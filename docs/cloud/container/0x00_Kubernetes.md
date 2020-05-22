# 0x00_Kubernetes

## 重要概念

- Cluster
    - Master：调度
    - Node：运行容器，监控并汇报容器状态，管理容器生命周期
- Pod：包含一个或多个容器，作为整体调度
- Controller：k8s通过Controller管理Pod，运行容器。
- Deployment：
    - ReplicaSet：多副本管理。使用Deployment时自动创建ReplicaSet。
    - DaemonSet：Node只运行一个Pod副本。
    - StatefuleSet：保证Pod的每个副本名称不变，按顺序启动、更新、删除。
- Job：运行结束就删除的应用。
- Service：访问容器，提供IP和端口，负载均衡。
- Namespace：将物理Cluster划分为多个虚拟Cluster。k8s默认创建两个：kubectl get namespace
    - default：
    - kube-system：k8s自己创建的系统资源。

!!! quote "[架构图](https://kubernetes.io/docs/concepts/overview/components/)"

## Master

- API Server：提供管理接口
- Scheduler：调度
- Controller Manager：
    - replication controller：Deployment StatefulSet DaemonSet
    - endpoints controller：
    - namespace controller：
    - serviceaccounts controller：
- etcd：保存Cluster的配置信息和各种资源的状态。
- Pod网络：

## Node

- kubelet：Schedule将Pod的配置（image volume等）发送给kubelet，kubelet启动容器并向Master报告运行状态。

!!! tip
    唯一不以容器形式运行的Kubernetes组件，在Ubuntu中通过Systemd运行，如：`sudo systemctl status kubelet.service`

- kube-proxy：将访问service的TCP/UDP数据流转发给容器。实现负载均衡。
- Pod网络：

## 组件协作

kubectl --> API Server --> Controller Manager --> Scheduler --> kubelet


## 使用 K8s API 访问集群

```bash
# 查看版本
$ kubectl version
# 查看集群位置和认证凭据
$ kubectl config view
# 使用 kubectl 作为代理访问 K8s REST API
$ kubectl proxy --port=8080 &
$ curl http://localhost:8080/api/
```

> 不使用 kubectl 作为代理直接访问参考: https://kubernetes.io/zh/docs/tasks/administer-cluster/access-cluster-api/#%E4%B8%8D%E4%BD%BF%E7%94%A8-kubectl-%E4%BB%A3%E7%90%86

### [Go 客户端](../0x90_client-go)

```sh
# 获取库
$ go get k8s.io/client-go/<version number>/kubernetes
```

```go
import (
   "fmt"
   "k8s.io/client-go/1.4/kubernetes"
   "k8s.io/client-go/1.4/pkg/api/v1"
   "k8s.io/client-go/1.4/tools/clientcmd"
)
...
   // uses the current context in kubeconfig
   config, _ := clientcmd.BuildConfigFromFlags("", "path to kubeconfig")
   // creates the clientset
   clientset, _:= kubernetes.NewForConfig(config)
   // access the API to list pods
   pods, _:= clientset.CoreV1().Pods("").List(v1.ListOptions{})
   fmt.Printf("There are %d pods in the cluster\n", len(pods.Items))
...
```

### Python 客户端

!!! quote "参考链接: [使用 Kubernetes API 访问集群](https://kubernetes.io/zh/docs/tasks/administer-cluster/access-cluster-api/)"

```bash
kubectl get namespace/ns  #查看namespace
kubectl get node -nmynamespace  #查看指定namespace节点状态
kubectl get node --all-namespaces  #查看所有namespace节点状态
kubectl create -f xxx.yaml [-nkube-system]  #根据yaml创建资源
kubectl get ingress xxx  #查看ingress信息
kubectl describe ingress xxx-ingress [-nkube-system]  #查看详细ingress信息
#更新ingress
kubectl edit ingress xxx
kubectl replace -f xxx.yaml
kubectl get deployment [-nxxx]  #查看deployment信息
#查看deployment的yaml文件
kubectl get deployment xxx -nxxx -oyaml
kubectl edit deployment xxx -nxxx
kubectl get pod -nxxx -owide | grep aaa  #查看POD
kubectl get pod -nxxx -owide -oyaml aaa | grep hostIP   #获取POD所在节点IP
kubectl get svc -nxxx  #查看service信息
```
