# docker

![language](https://img.shields.io/badge/language-Go-brightgreen.svg)

!!! tip "Docker版本"
    Docker官方版本从 {==1.13.x==} 开始，一跃到 {==17.03==}。  
    之后每月发布一个edge版本，如17.03, 17.04, 17.05...，每三个月发布一个stable版本，如17.03, 17.06, 17.09...

!!! info
    - Docker Daemon以 {==root==} 权限运行。
    - 相比于VM需要在hostOS上安装hypervisor和guestOS，Docker Engine直接运行在hostOS上，其上跑APP。
    - 存在未namespaces隔离资源，如`/proc, /sys, top, free, root, /dev, 内核...`
    - 所有运行的容器 {==共享==} host内核，通过容器内系统崩溃 --> 内核崩溃 --> 其他容器崩溃。


```bash
docker cp file.xxx ced60ce33136:/opt/xxx  #将host上的文件拷贝到容器

docker images  #查看已存在的镜像
docker save b0f6bcd0a2a0 > file.tar  #将镜像导出为文件
docker rmi b0f6bcd0a2a0  #删除已存在的镜像
docker load < file.tar  #镜像导入
docker tag b0f6bcd0a2a0 euleros:2.2.5  #为导入的镜像打标签

docker ps  #查看正在运行的容器
docker export b91d9ad83efa > file.tar  #将容器导出
docker import file.tar  #将容器导入
```
