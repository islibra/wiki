# Operator

## Operator SDK

> 使用[minikube](https://github.com/kubernetes/minikube) v0.25.0+ 用作本地 Kubernetes 集群，[Quay.io](https://quay.io/) 用于公共 registry。

### [安装并设置 kubectl](https://kubernetes.io/zh/docs/tasks/tools/install-kubectl/)

### [安装 Hypervisor - VirtualBox](https://www.virtualbox.org/wiki/Downloads)

### [安装 Minikube](https://kubernetes.io/zh/docs/tasks/tools/install-minikube/)

1. 检查是否支持虚拟化: `sysctl -a |grep -E --color 'machdep.cpu.features|VMX'`
1. 安装Minikube: `brew install minikube`

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

- cmd/manager/main.go: 管理器自动注册CR, 并运行控制器, 限制控制器监视资源的namespace
- pkg
    - apis: 定义自定义资源(CR)
    - controller: 控制器
