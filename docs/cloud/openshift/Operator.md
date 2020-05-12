# Operator

> 使用[minikube](https://github.com/kubernetes/minikube) v0.25.0+ 用作本地 Kubernetes 集群，[Quay.io](https://quay.io/) 用于公共 registry。

## [安装并设置 kubectl](https://kubernetes.io/zh/docs/tasks/tools/install-kubectl/)

1. `curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl`
1. `chmod +x ./kubectl`
1. `mv ./kubectl /usr/local/bin/kubectl`

## [安装 Hypervisor - VirtualBox](https://www.virtualbox.org/wiki/Downloads)

> 如果主机已安装[Docker](https://www.docker.com/products/docker-desktop), 使用`--vm-driver=none`使K8s运行在主机中

## [安装 Minikube](https://kubernetes.io/zh/docs/tasks/tools/install-minikube/)

> 检查是否支持虚拟化: `sysctl -a |grep -E --color 'machdep.cpu.features|VMX'`

- macOS安装Minikube:
    1. `brew install minikube`
    1. `minikube start --vm-driver=virtualbox --registry-mirror=https://registry.docker-cn.com --image-mirror-country=cn --image-repository=registry.cn-hangzhou.aliyuncs.com/google_containers`, [driver_name](https://kubernetes.io/docs/setup/learning-environment/minikube/#specifying-the-vm-driver)
    1. `kubectl cluster-info`

- [GitHub Releases](https://github.com/kubernetes/minikube/releases), Latest release minikube_1.9.2-0_amd64.deb
    1. `dpkg -i minikube_1.9.2-0_amd64.deb`
    1. `minikube version`
    1. `minikube start --vm-driver=none`
    1. `minikube status`
    1. 停止集群: `minikube stop`
    1. 清理集群: `minikube delete`

## 安装[Operator Lifecycle Manager(OLM)](https://github.com/operator-framework/operator-lifecycle-manager/blob/master/doc/install/install.md)

`curl -sL https://github.com/operator-framework/operator-lifecycle-manager/releases/download/0.14.1/install.sh | bash -s 0.14.1`

- 创建`olm`和`operators` namespace
- 在`olm` namespace创建deployment `olm-operator`, `catalog-operator`, `packageserver`

## 在集群中安装Operator

1. 在`operators namespace`创建 **Subscription**, 指定olm namespace中的operatorhubio-catalog中的operator名称和channel, **所有namespace可用**

```yaml
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: my-cassandra-operator
  namespace: operators
spec:
  channel: alpha
  name: cassandra-operator
  source: operatorhubio-catalog
  sourceNamespace: olm
```

1. 创建 **CatalogSource**: OperatorHub.io中所有Operators的catalog, 包含Operator的下载地址
2. 创建 **Subscription**: 实际要部署的Operator

如果指定Operator仅运行在指定namespace:

1. 创建独立的namespace, 如: `my-<operator-name>`
1. 创建 **OperatorGroup**: 使用`spec.targetNamespace`配置Operator仅watch所在namespace的CustomResourceDefinitions

## 查看在operator namespace中创建的CSV, 使用其依赖的CRD

- `kubectl get csv -n operators -w`
- `kubectl get pod -n operators`

## Operator SDK

### 安装 [Operator SDK CLI](https://github.com/operator-framework/operator-sdk/releases/download/v0.17.0/operator-sdk-v0.17.0-x86_64-linux-gnu)

```bash
$ curl -OJL https://github.com/operator-framework/operator-sdk/releases/download/v0.17.0/operator-sdk-v0.17.0-x86_64-apple-darwin
$ chmod +x operator-sdk-${RELEASE_VERSION}-x86_64-linux-gnu
$ sudo cp operator-sdk-${RELEASE_VERSION}-x86_64-linux-gnu /usr/local/bin/operator-sdk
$ rm operator-sdk-${RELEASE_VERSION}-x86_64-linux-gnu
$ operator-sdk version
```

### 使用 Operator SDK 来构建基于 Go 的 Operator


### 架构

- operator-sdk CLI工具
- controller-runtime库API

> 支持Prometheus

### 工作流

1. 使用 Operator SDK 命令行界面 (CLI) 新建一个 **Operator 项目**。
1. 通过添加 **自定义资源定义 (CRD)** 来定义新的资源 **API**。
1. 使用 Operator SDK API 来指定要 **监视** 的资源。
1. 在指定的处理程序中定义 Operator **协调逻辑**，并使用 Operator SDK API 与 **资源交互**。
1. 使用 Operator SDK CLI 来构建和生成 Operator 部署清单 **manifest**。

### Operator项目

- cmd/manager/main.go: 管理器自动注册 **CR**, 并运行 **控制器**, 限制控制器监视资源的 **namespace**
- pkg
    - apis: 定义自定义资源(CR)
    - controller: 控制器
