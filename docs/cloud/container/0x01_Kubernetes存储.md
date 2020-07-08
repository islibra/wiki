# 0x01_Kubernetes存储

## emptyDir

生命周期与POD一致，在Host上创建 **临时目录**。

```yaml
apiVersion: v1
kind: Pod
metadata:
    name: producer-customer
spec:
    containers:
    - image: busybox
        name: producer
        volumeMounts:
        - mountPath: /producer_dir  # mount到容器目录
            name: shared-volume
        args:
        - /bin/sh
        - -c
        - echo "helloword" > /producer_dir/hello; sleep 30000
    - image: busybox
        name: consumer
        volumeMounts:
        - mountPath: /consumer_dir  # mount到容器目录
            name: shared-volume
        args:
        - /bin/sh
        - -c
        - cat /consumer_dir/hello; sleep 30000
    volumes:
    - name: shared-volume  # 定义emptyDir类型的Volume
        emptyDir: {}
```

查看容器输出：`kubectl log producer-consumer consumer`

## hostPath Volume

将Host中 **已存在** 的目录mount给Pod。如kube-apiserver、kube-controller-manager。

查看YAML配置：`kubectl edit pod kube-apiserver-k8s-master --namespace=kube-system`

```yaml
volumeMounts:
- mountPath: /etc/kubernetes
    name: k8s
    readOnly: true
- mountPath: /etc/ssl/certs
    name: certs
- mountPath: /etc/pki
    name: pki
volumes:
- hostPath:
    path: /etc/kubernetes
    name: k8s
- hostPath:
    path: /etc/ssl/certs
    name: certs
- hostPath:
    path: /etc/pki
    name: pki
```

## I. PV

### II. PersistentVolume

```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
    name: mypv1
    annotations:
        # 访问控制: 使用 group ID(GID) 配置的存储仅允许 Pod 使用相同的 GID 进行写入。
        pv.beta.kubernetes.io/gid: "1234"
spec:
    capacity:
        storage: 1Gi  # 指定PV容量
    accessModes:
        # 访问模式：
        # ReadWriteOnce以读写模式mount到单个节点；
        # ReadOnlyMany以只读模式mount到多个节点；
        # ReadWriteMany以读写模式mount到多个节点。
        - ReadWriteOnce
    # 回收策略：
    # Retain管理员手工回收。PV的STATUS保持Released无法被其他PVC申请，需要删除并重新创建PV；
    # Recycle清除PV中的数据，相当于rm -rf /thevolume/*。自动启动一个Pod删除PV中的数据，删除后PV的STATUS恢复为Available；
    # Delete删除存储资源。
    persistentVolumeReclaimPolicy: Recycle
    storageClassName: nfs  # PV分类
    nfs:
        path: /nfsdata/pv1
        server: 192.168.56.105
```

### II. PersistentVolumeClaim

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
    name: mypvc1
spec:
    accessModes:
        - ReadWriteOnce  # 指定访问模式
    resources:
        requests:
            storage: 1Gi  # 指定容量
    storageClassName: nfs  # 指定PV分类
```

#### III. 使用 PVC

```yaml
volumes:
    - name: mydata
        persistentVolumeClaim:
            claimName: mypvc1  # 指定使用PVC

volumeMounts:
- mountPath: "/mydata"
    name: mydata
```

- 删除PVC：`kubectl delete pvc mypvc1`
- 删除PV：`kubectl delete pv mypv1`


### II. Demo - 使用本地 hostPath 创建一个 PV

!!! tip "仅适用于单节点, 在生产环境中需使用 nfs"

#### III. 准备本地卷

```sh
$ mkdir -p /home/islibra/data
$ echo 'Hello from Kubernetes storage' > /home/islibra/data/index.html
```

#### III. 创建 PV

```sh
$ vim /home/islibra/kubernetes/pods/storage/pv-volume.yaml
```

```yaml
# filename: pv-volume.yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: task-pv-volume
  labels:
    type: local
spec:
  capacity:
    storage: 10Gi
  accessModes:
    - ReadWriteOnce
  storageClassName: manual
  hostPath:
    path: "/home/islibra/data"
```

```sh
$ kubectl create -f /home/islibra/kubernetes/pods/storage/pv-volume.yaml
```

#### III. 创建 PVC

```sh
$ vim pv-claim.yaml
```

```yaml
# filename: pv-claim.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: task-pv-claim
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 3Gi
  storageClassName: manual
```

```sh
$ kubectl create -f /home/islibra/kubernetes/pods/storage/pv-claim.yaml
```

#### III. 创建 Pod

```sh
$ vim pv-pod.yaml
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: task-pv-pod
spec:
  volumes:
    - name: task-pv-storage
      persistentVolumeClaim:
        claimName: task-pv-claim
  containers:
    - name: task-pv-container
      image: nginx
      ports:
        - containerPort: 80
          name: "http-server"
      volumeMounts:
        - mountPath: "/usr/share/nginx/html"
          name: task-pv-storage
```

```sh
$ kubectl create -f /home/islibra/kubernetes/pods/storage/pv-pod.yaml
```

#### III. 验证

```sh
$ kubectl exec -it task-pv-pod -- /bin/bash
$ cat /usr/share/nginx/html/index.html
```

!!! quote "[配置 Pod 以使用 PersistentVolume 作为存储 - Kubernetes官方](https://kubernetes.io/zh/docs/tasks/configure-pod-container/configure-persistent-volume-storage/)"


### PV动态供给

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass  # 实现动态供给
metadata:
    name: standard
provisioner: kubernetes.io/aws-ebs
parameters:
    type: gp2
reclaimPolicy: Retain  # 默认是Delete
```

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
    name: slow
provisioner: kubernetes.io/aws-ebs
parameters:
    type: io1
    zones: us-east-1d, us-east-1c
    iopsPerGB: "10"
```

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
    name: mypvc1
spec:
    accessModes:
        - ReadWriteOnce
    resources:
        requests:
            storage: 1Gi
    storageClassName: standard  # 指定StorageClass
```

## AWS

```yaml
volumeMounts:
- mountPath: /test-ebs
    name: ebs-volume
volumes:
- name: ebs-volume
    awsElasticBlockStore:
        volumeID: <volume-id>  # 在AWS中创建，并通过volume-id引用。
        fsType: ext4
```

## Ceph

```yaml
volumeMounts:
- name: ceph-volume
    mountPath: /test-ceph
volumes:
- name: ceph-volume
    cephfs:
        path: /some/path/inside/cephfs
        monitors: "ip:port"
        secretFile: "/etc/ceph/admin.secret"
```


!!! quote "参考链接: [Volumes](https://kubernetes.io/zh/docs/concepts/storage/)"
