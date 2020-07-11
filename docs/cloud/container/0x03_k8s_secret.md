# 0x03_k8s_secret

!!! abstract "存放 {==密码、token、ssh密钥==} 等敏感数据，而不需要暴露到 容器镜像 或 Pod Spec 中"

## I. 内置 secret 类型

1. Opaque: 数据使用 {==BASE64编码==}
1. kubernetes.io/dockerconfigjson: 存储私有 docker registry 的认证信息
1. kubernetes.io/service-account-token: 由 service account 自动创建

    > 默认token: default-token-xxxxx


## I. 创建 secret

### 方式1

```bash
# generic对应创建Opaque类型
$ kubectl create secret generic mysecret --from-literal=username=admin --from-literal=password=123456

# 如果密码中包含特殊字符, 应使用如下命令
shell kubectl create secret generic dev-db-secret --from-literal=username=devuser --from-literal=password='S!B\*d$zDsb='
```

### II. 通过本地文件创建

```bash
echo -n 'admin' > ./username.txt
echo -n '1f2d1e2e67df' > ./password.txt
# 默认的 key 是文件名, 可以省略
kubectl create secret generic db-user-pass --from-file[=username]=./username.txt --from-file[=password]=./password.txt
```

> 可以为指定证书和私钥文件创建 secret, 如:

```sh
kubectl create secret generic xxx-tls --from-file=key.pem --from-file=cert.pem
```


### 方式3

```bash
$ cat > env.txt << EOF
username=admin
password=123456
EOF
$ kubectl create secret generic mysecret --from-env-file=env.txt
```

### II. 通过 yaml 创建

#### III. 使用 BASE64 之后的数据

```sh
# 将数据 BASE64
# YWRtaW4=
echo -n 'admin' | base64
# MWYyZDFlMmU2N2Rm
echo -n '1f2d1e2e67df' | base64
```

> 应使用 `base64 -w 0` 或 `base64 | tr -d '\n'` 去掉换行

```yaml
# filename: secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: mysecret
type: Opaque
data:
  username: YWRtaW4=  # BASE64编码
  password: MWYyZDFlMmU2N2Rm
```

#### III. 直接使用原始字符串

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mysecret
type: Opaque
# 优先级高于 data
stringData:
  config.properties: |-
    apiUrl: "https://my.api.com/api/v1"
    username: admin
    password: 'S!B\*d$zDsb='
```

```bash
$ kubectl create -f ./secret.yaml
```

#### III. 通过 secretGenerator 创建

Since Kubernetes v1.14

```sh
cat <<EOF >./kustomization.yaml
secretGenerator:
- name: db-user-pass
  files:
  - username.txt
  - password.txt
EOF

kubectl apply -k .
```

```sh
cat <<EOF >./kustomization.yaml
secretGenerator:
- name: db-user-pass
  literals:
  - username=admin
  - password=secret
EOF

kubectl apply -k .
```

!!! quote "[Secrets](https://kubernetes.io/docs/concepts/configuration/secret/), from kubernetes"


### 创建dockerconfigjson

```bash
# docker-registry对应创建dockerconfigjson类型
$ kubectl create secret docker-registry myregistrykey --docker-server=DOCKER_REGISTRY_SERVER --docker-username=DOCKER_USER --docker-password=DOCKER_PASSWORD --docker-email=DOCKER_EMAIL
```

## I. 使用方式

### II. 作为容器的环境变量

```yaml
# filename: demo_deployment.yml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: wordpress-deployment
spec:  # 定义deployment: 副本数量, 升级策略
  replicas: 2
  strategy:
      type: RollingUpdate
  template:
    metadata:
      labels:
        app: wordpress
        visualize: "true"
    spec:  # 定义POD: 容器镜像
      containers:
      - name: "wordpress"
        image: "wordpress"
        ports:
        - containerPort: 80
        env:  # 定义环境变量
        - name: WORDPRESS_DB_USER
          valueFrom:
            secretKeyRef:  # 引用secret中的key
              name: mysecret
              key: username
        - name: WORDPRESS_DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: mysecret
              key: password
```

### II. 通过 volume 以文件方式挂载到一个或多个容器

```yaml
# filename: demo_pod.yml
apiVersion: v1
kind: Pod
metadata:
  labels:
    name: db
  name: db
spec:
  volumes:
  - name: secrets  # 定义Volume
    secret:
      secretName: mysecret  # 指定为secret
  containers:
  - image: registry.martin.com:5000/my_project_id/pg:v1
    name: db
    volumeMounts:  # 挂载Volume
    - name: secrets
      mountPath: "/etc/secrets"  # 挂载到容器内路径
      readOnly: true
    ports:
    - name: cp
      containerPort: 5432
      hostPort: 5432
```

!!! tip "注意挂载到POD之后的文件已是反BASE64之后的值"

### 3. 挂载Volume中指定key

```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    name: db
  name: db
spec:
  volumes:
  - name: secrets
    secret:
      secretName: mysecret
      items:  # 指定key
      - key: password
        mode: 511
        path: tst/psd
      - key: username
        mode: 511
        path: tst/usr
  containers:
  - image: nginx
    name: db
    volumeMounts:
    - name: secrets
      mountPath: "/etc/secrets"
      readOnly: true
    ports:
    - name: cp
      containerPort: 80
      hostPort: 5432
```

### 4. 拉取镜像

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: foo
spec:
  containers:
    - name: foo
      image: janedoe/awesomeapp:v1
  imagePullSecrets:  # 指定拉取镜像时使用的鉴权信息
    - name: myregistrykey
```

## 加密secret

### 加密配置

```yaml
kind: EncryptionConfiguration
apiVersion: apiserver.config.k8s.io/v1
resources:
  - resources:
    - secrets  # 要加密的Kubernetes资源名称
    providers:  # 指定加密方式: 第一个用于加密, 按顺序解密
    - identity: {}
    - aesgcm:
        keys:  # 支持多个密钥: 第一个用于加密, 按顺序解密
        - name: key1
          secret: c2VjcmV0IGlzIHNlY3VyZQ==
        - name: key2
          secret: dGhpcyBpcyBwYXNzd29yZA==
    - aescbc:
        keys:
        - name: key1
          secret: c2VjcmV0IGlzIHNlY3VyZQ==
        - name: key2
          secret: dGhpcyBpcyBwYXNzd29yZA==
    - secretbox:
        keys:
        - name: key1
          secret: YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
```

名称 | 加密类型 | 强度 | 速度 | 密钥长度 | 其它事项
--- | --- | --- | --- | --- | ---
identity | 无 | N/A | N/A | N/A | 不加密写入的资源。当设置为第一个 provider 时，资源将在新值写入时被解密。
aescbc | 填充 PKCS#7 的 AES-CBC | 最强 | 快 | 32字节 | 建议使用的加密项，但可能比 secretbox 稍微慢一些。
secretbox | XSalsa20 和 Poly1305 | 强 | 更快 | 32字节 | 较新的标准，在需要高度评审的环境中可能不被接受。
aesgcm | 带有随机数的 AES-GCM | 必须每 200k 写入一次 | 最快 | 16, 24, 或者 32字节 | 建议不要使用，除非实施了自动密钥循环方案。
kms | 使用信封加密方案：数据使用带有 PKCS#7 填充的 AES-CBC 通过 data encryption keys（DEK）加密，DEK 根据 Key Management Service（KMS）中的配置通过 key encryption keys（KEK）加密 | 最强 | 快 | 32字节 | 建议使用第三方工具进行密钥管理。为每个加密生成新的 DEK，并由用户控制 KEK 轮换来简化密钥轮换。配置 KMS 提供程序

### 加密步骤

#### 1. 创建一个新的加密配置文件

```yaml
kind: EncryptionConfiguration
apiVersion: apiserver.config.k8s.io/v1
resources:
  - resources:
    - secrets
    providers:
    - aescbc:
        keys:
        - name: key1
          secret: <BASE 64 ENCODED SECRET>  # 生成一个32字节的随机密钥并进行BASE64编码, 如: head -c 32 /dev/urandom | base64
    - identity: {}
```

!!! warning "注意正确设置配置文件权限"

#### 2. 设置 kube-apiserver 的 --experimental-encryption-provider-config 参数，将其指定到配置文件所在位置。

#### 3. 重启 API server

#### 4. 验证数据加密

1. 创建secret

    ```bash
    $ kubectl create secret generic mysecret -n default --from-literal=mykey=mydata
    ```

1. 从etcd中读取secret

    ```bash
    ETCDCTL_API=3 etcdctl get /registry/secrets/default/mysecret [连接etcd服务的参数...] | hexdump -C
    ```

    > 数据以`k8s:enc:aescbc:v1:`为前缀, 使用aescbc加密

1. API读取时 **已解密**

    ```bash
    $ kubectl describe secret mysecret -n default
    ```

#### 5. 对所有secret更新以进行全量加密

```bash
$ kubectl get secrets --all-namespaces -o json | kubectl replace -f -
```

#### 6. 解密所有数据

1. 修改配置

    ```yaml
    kind: EncryptionConfiguration
    apiVersion: apiserver.config.k8s.io/v1
    resources:
      - resources:
        - secrets
        providers:
        - identity: {}  # 将identity作为第一个provider
        - aescbc:
            keys:
            - name: key1
              secret: <BASE 64 ENCODED SECRET>
    ```

1. 重启所有 kube-apiserver 进程
1. 强制解密所有 secret

    ```bash
    $ kubectl get secrets --all-namespaces -o json | kubectl replace -f -
    ```

!!! quote "参考链接"
    - [kubernetes之secret](https://www.leiyawu.com/2018/11/14/kubernetes%E4%B9%8Bsecret/)
    - [Secret](https://kubernetes.io/zh/docs/concepts/configuration/secret/)
    - [静态加密 Secret 数据](https://kubernetes.io/zh/docs/tasks/administer-cluster/encrypt-data/)
