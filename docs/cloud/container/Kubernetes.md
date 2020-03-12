# Kubernetes

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

![架构图](../assets/markdown-img-paste-20190618201301319.png)

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


## 常用命令

```bash
# 查看版本
$ kubectl version

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
