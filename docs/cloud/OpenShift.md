# OpenShift

- 启动minikube: `minikube start --vm-driver=virtualbox --registry-mirror=https://registry.docker-cn.com --image-mirror-country=cn --image-repository=registry.cn-hangzhou.aliyuncs.com/google_containers`
- 在host上使用Docker: `eval $(minikube docker-env)`

通过OpenShift Web控制台 - OperatorHub, 查找和安装Operator, 单击一次, 从非集群源拉取Operator, 并安装订阅到集群

安装 Operator SDK CLI
$ brew install operator-sdk
查看 CLI 版本
$ operator-sdk version

INFO[0000] Created go.mod                               
INFO[0000] Created tools.go                             
INFO[0000] Created cmd/manager/main.go                  
INFO[0000] Created build/Dockerfile                     
INFO[0000] Created build/bin/entrypoint                 
INFO[0000] Created build/bin/user_setup                 
INFO[0000] Created deploy/service_account.yaml          
INFO[0000] Created deploy/role.yaml                     
INFO[0000] Created deploy/role_binding.yaml             
INFO[0000] Created deploy/operator.yaml                 
INFO[0000] Created pkg/apis/apis.go                     
INFO[0000] Created pkg/controller/controller.go         
INFO[0000] Created version/version.go

INFO[0000] Created pkg/apis/cache/group.go              
INFO[0146] Created pkg/apis/cache/v1alpha1/memcached_types.go
INFO[0146] Created pkg/apis/addtoscheme_cache_v1alpha1.go
INFO[0146] Created pkg/apis/cache/v1alpha1/register.go  
INFO[0146] Created pkg/apis/cache/v1alpha1/doc.go       
INFO[0146] Created deploy/crds/cache.example.com_v1alpha1_memcached_cr.yaml

INFO[0000] Created pkg/controller/memcached/memcached_controller.go
INFO[0000] Created pkg/controller/add_memcached.go
