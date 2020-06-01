# 0x12_本地Registry

不使用 [Docker Hub](https://hub.docker.com/), 搭建本地 Registry

## 拉取运行 Docker 开源的 Registry 镜像

```sh
$ docker run -d -p 5000:5000 -v /myregistry:/var/lib/registry --name registry registry:2
```

- -d 后台启动容器
- -p 将容器的 5000 端口映射到 Host 的 5000 端口
- -v 将容器的 `/var/lib/registry` 目录映射到 Host 的 `/myregistry`
- --name registry 指定容器运行名称

## 给本地已存在的镜像打 Tag

```sh
$ docker image tag ubuntu:v1 localhost:5000/myfirstimage:v1
```

!!! tip "镜像名称由 repository 和 tag 组成, 完整格式为: [registry-host]:[port]/[username]/xxx:tag, {==只有 Docker Hub 上的镜像可以省略==} [registry-host]:[port]"

## 上传镜像

```sh
$ docker push localhost:5000/myfirstimage:v1
```

## 下载镜像

```sh
$ docker pull localhost:5000/myfirstimage:v1
```

## 删除本地 Registry

```sh
$ docker container stop registry && docker container rm -v registry
```

!!! quote "参考链接"
    - [Docker Registry](https://docs.docker.com/registry/)
    - [搭建本地 Registry - 每天5分钟玩转 Docker 容器技术（20）](https://mp.weixin.qq.com/s?__biz=MzIwMTM5MjUwMg==&mid=2653587627&idx=1&sn=b85416005be844a921c146883ac0e6b8&chksm=8d3080b2ba4709a42459bd4eb977e225e2847c7bc39888c3f6f3e2d903eaf54556518683fa57&scene=21#wechat_redirect)
