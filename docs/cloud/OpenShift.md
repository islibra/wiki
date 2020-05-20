# OpenShift

- 启动minikube: `minikube start --vm-driver=virtualbox --registry-mirror=https://registry.docker-cn.com --image-mirror-country=cn --image-repository=registry.cn-hangzhou.aliyuncs.com/google_containers`
- 在host上使用Docker: `eval $(minikube docker-env)`
