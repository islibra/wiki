# LoadBalancer通过外部负载均衡访问该Service

```yaml
kind: Service
apiVersion: v1
metadata:
  name: my-service
  annotations:
        service.beta.kubernetes.io/openstack-internal-load-balancer: "true"  #区分内部流量和外部流量
spec:
  selector:
    app: MyApp
  ports:
  - protocol: TCP
    port: 80
    targetPort: 9376
  clusterIP: 10.0.171.239
  loadBalancerIP: 78.11.24.19  #指定LB IP
  type: LoadBalancer  #负载均衡方式
status:
  loadBalancer:
    ingress:
    - ip: 146.148.47.155  #LB真实IP
```

# ExternalName指定外部域名

```yaml
kind: Service
apiVersion: v1
metadata:
  name: my-service
  namespace: prod
spec:
  type: ExternalName
  externalName: my.database.example.com
```


# Ingress

提供集群外部访问service的URLs，使用GCE或nginx做负载均衡，还可提供SSL/TLS加密通道，虚拟host等功能。  
需节点上单独启动/home/paas/ingress-controller进程，可部署多个，通过添加annotations: ingress-class指定默认使用的ingress-controller。  

## 创建Single Service Ingress：

```yaml
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: test-ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  rules:  #流量路由通过Ingress中的rules定义。Service是通过iptables四层路由，Ingress是通过HTTP/HTTPS七层路由。
  - http:
      paths:
      - path: /testpath
        backend:
          serviceName: test
          servicePort: 80
```

查看ingress信息：

```bash
$ kubectl get ingress -nxxx -owide | grep aaa
NAME                         HOSTS     ADDRESS          PORTS     AGE
aaa-ingress     *         127.0.0.1,172.16.35.53      80, 443   11h
```

ADDRESS为ingress controller为ingress分配的IP地址。  

## Simple fanout

根据HTTP请求的URL，将流量从单个IP路由到多个service。

```yaml
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: simple-fanout-example
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  rules:
  - host: foo.bar.com
    http:
      paths:
      - path: /foo
        backend:
          serviceName: service1
          servicePort: 4200
      - path: /bar
        backend:
          serviceName: service2
          servicePort: 8080
```

## Name based virtual hosting

根据域名分别路由到不同的service。

```yaml
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: name-virtual-host-ingress
spec:
  rules:
  - host: first.bar.com
    http:
      paths:
      - backend:
          serviceName: service1
          servicePort: 80
  - host: second.foo.com
    http:
      paths:
      - backend:
          serviceName: service2
          servicePort: 80
  - http:  #未指定host默认路由到service3
      paths:
      - backend:
          serviceName: service3
          servicePort: 80
```

## TLS

创建一个包含TLS私钥和证书的secret。

```yaml
apiVersion: v1
data:
  tls.crt: base64 encoded cert
  tls.key: base64 encoded key
kind: Secret
metadata:
  name: testsecret-tls
  namespace: default
type: Opaque
```

创建ingress并指定secret。

```yaml
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: tls-example-ingress
spec:
  tls:  #指定secret
  - hosts:
    - sslexample.foo.com
    secretName: testsecret-tls
  rules:
    - host: sslexample.foo.com
      http:
        paths:
        - path: /
          backend:
            serviceName: service1
            servicePort: 80
```
