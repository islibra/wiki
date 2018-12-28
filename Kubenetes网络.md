假设创建Deployment的yaml为：

```yaml
kind: Deployment
metadata:
    name: httpd
spec:
    replicas: 3
    template:
        metadata:
            labels:  //设置应用的label
                run: httpd
```

# 定义Service httpd-svc.yaml：

```yaml
apiVersion: v1  //Service的apiVersion
kind: Service  //资源类型为Service
metadata:
    name: httpd-svc  //Service的名称
spec:
    clusterIP: 10.250.45.217  //可选
    selector:  //选择Pod的label为run: httpd
        run: httpd
    ports:
        - protocol: TCP  //将Service的TCP端口8080映射到Pod的80端口
        port: 8080
        targetPort: 80
```

创建Service：`kubectl apply -f httpd-svc.yaml`  
查看Service：`kubectl get service`，Cluster通过kubernetes Service访问API Server。  
查看Service详细：`kubectl describe service httpd-svc`，包含三个Endpoints（Pod的IP和端口）。  
通过Service的IP访问Pod：`curl {Service Cluster IP}:8080`，流量会被路由到Endpoint。

> Service会被分配一个Cluster IP，Service Cluster IP是一个虚拟IP，由iptables管理：允许Pod访问httpd-svc；其他地址访问httpd-svc，跳转到规则（1/3概率跳转到规则1（将请求转发到Pod）,1/3概率跳转到规则2,1/3概率跳转到规则3），查看iptables规则：`iptables-save`，Cluster每个节点都配置了相同的iptables。
> Service的selector持续检查并通知同名Endpoints，修改为正确的Pod IP和端口。

# 自定义Endpoint，访问其他namespace的service或非kubenetes的backend：

```yaml
kind: Service
apiVersion: v1
metadata:
  name: my-service
spec:  //不定义selector
  ports:
  - protocol: TCP
    port: 80
    targetPort: 9376

---

kind: Endpoints
apiVersion: v1
metadata:
  name: my-service
subsets:
  - addresses:
      - ip: 1.2.3.4
    ports:
      - port: 9376
```

> **Tips:** 多个资源在同一个YAML文件中以---分割。

# 定义多个端口映射

```yaml
kind: Service
apiVersion: v1
metadata:
  name: my-service
spec:
    selector:
      app: MyApp
    ports:
      - name: http  //给出端口名称
        protocol: TCP
        port: 80
        targetPort: 9376
      - name: https
        protocol: TCP
        port: 443
        targetPort: 9377
```

# DNS访问Service

kubeadm部署时默认安装kube-dns：`kubectl get deployment --namespace=kube-system`，监视创建Service时，自动添加DNS记录。  
DNS服务器在kube-system中部署一个Service，域名访问`kube-dns.kube-system.svc.cluster.local`。  
查看namespace：`kubectl get namespace`。

httpd-svc的完整域名是`httpd-svc.default.svc.cluster.local`，在Pod中访问：  
```bash
kubectl run busybox --rm -ti --image=busybox /bin/sh
wget httpd-svc.default:8080  //<SERVICE_NAME>.<NAMESPACE_NAME>
```

在Pod中直接查找DNS信息：`nslookup httpd-svc`。  

# NodePort对非Kubenetes提供服务

```yaml
apiVersion: v1
kind: Service
metadata:
    name: httpd-svc
spec:
    type: NodePort  //默认是ClusterIP，只能Cluster内的节点和Pod访问
    selector:
        run: httpd
    ports:
    - protocol: TCP
    nodePort: 30000  //可指定节点端口
    port: 8080
    targetPort: 80
```

查看Service：`kubectl get service httpd-svc`，将Service的8080端口映射到 **每个Node的30000-32767端口。**

# 外部IP

```yaml
kind: Service
apiVersion: v1
metadata:
  name: my-service
spec:
  selector:
    app: MyApp
  ports:
    - name: http
      protocol: TCP
      port: 80
      targetPort: 9376
  externalIPs: 
    - 80.11.12.10  //可以通过80.11.12.10:80访问该Service
```


参考：
[https://kubernetes.io/zh/docs/concepts/services-networking/service/](https://kubernetes.io/zh/docs/concepts/services-networking/service/)  
[https://kubernetes.io/docs/concepts/services-networking/service/](https://kubernetes.io/docs/concepts/services-networking/service/)  


# Ingress

提供集群外部访问service。

创建Ingress：

```yaml
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: test-ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  rules:
  - http:
      paths:
      - path: /testpath
        backend:
          serviceName: test
          servicePort: 80
```


参考：  
[https://kubernetes.io/docs/concepts/services-networking/ingress/](https://kubernetes.io/docs/concepts/services-networking/ingress/)  
