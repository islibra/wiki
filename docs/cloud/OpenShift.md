# OpenShift

- 启动 minikube: `minikube start --vm-driver=virtualbox --registry-mirror=https://registry.docker-cn.com --image-mirror-country=cn --image-repository=registry.cn-hangzhou.aliyuncs.com/google_containers`
- 在 host 上使用 Docker: `eval $(minikube docker-env)`
- 安装 Operator SDK CLI: `$ brew install operator-sdk`
- 查看 CLI 版本: `$ operator-sdk version`
