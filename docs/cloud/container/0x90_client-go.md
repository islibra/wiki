# [0x90_client-go](https://github.com/kubernetes/client-go)

Kubernetes官方Go语言客户端, 可以用来调用K8s的RESTful API, 去apiserver list/watch(**informer**)资源

!!! note "以下内容摘抄自章骏的[如何用 client-go 拓展 Kubernetes 的 API](https://mp.weixin.qq.com/s/0krB2qF4Y0tgyvQrS4YKIQ)"
    ![](assets/markdown-img-paste-20200520094528222.png)

    1. Controller 使用 {==informer==} 来 {==list/watch==} apiserver，然后将资源存储于本地的 cache 中。
    2. 如果 {==informer==} 监听到了资源的变化(**创建/更新/删除**)，就会调用事先注册的 {==ResourceEventHandler==} 回调函数。
    3. 在 {==ResourceEventHandler==} 回调函数中，其实只是做了一些很简单的过滤，然后将关心变更的 Object 放到 {==workqueue==} 里面。
    4. Controller 从 {==workqueue==} 里面取出 Object，启动一个 {==worker==} 来执行自己的业务逻辑，业务逻辑通常是计算目前集群的状态和用户希望达到的状态有多大的区别，然后孜孜不倦地让 {==apiserver==} 将状态演化到用户希望达到的状态，比如为 deployment 创建新的 pods，或者是扩容/缩容 deployment。
    5. 在 {==worker==} 中就可以使用 {==lister==} 来获取 {==resource==}，而不用频繁的访问 apiserver，因为 apiserver 中 resource 的变更都会反映到本地的 cache 中。

## Clients

### Clientset

根据group, version, resource name获取K8s原生资源, 如Pods, Nodes, Deployments

### Dynamic Client

同时处理K8s所有资源, 返回map[string]interface{}, 常用在namespace controller或CustomResourceDefinition

### RESTClient

- Get()
- Post()
- Put()
- Delete()

## Informer

调用[SharedInformerFactory](https://github.com/kubernetes/client-go/blob/v3.0.0/informers/factory.go)构建 {==SharedInformer==}

## Workqueue

允许一个正在被处理的 item 再次加入队列, 使用 RateLimitingQueue 限制加入次数, 防止 hot loop

## Lister

在 worker 中访问本地 cache

## 流程图

1. 创建 workqueue
2. 创建 informer, 并添加callback
3. 创建 lister
4. 启动 informer
5. 等待 cache sync 完成后, 启动 workers
6. 触发变更事件, 检查 Object, 生成 object key(namespace/name), 放入 workqueue
7. 从 workqueue 获取 item, 通过 lister 从本地 cache 获取 object
8. 执行业务逻辑
