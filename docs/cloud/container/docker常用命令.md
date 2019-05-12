# docker常用命令

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
