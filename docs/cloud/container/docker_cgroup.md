# docker_cgroup

Linux Control Group, Linux内核功能，限制 ==进程组== 的资源（CPU，内存，磁盘IO）。

## 查询挂载点

```bash
# -t 指定挂载类型，源路径，挂载点
mount -t cgroup
```

在`/sys/fs/cgroup`下挂载`cpu, cpuset, memory, ...`，目录中包含`cpu.shares...`，  
如果创建子目录，自动包含`cpu.shares...`。

!!! example
    ``` hl_lines="2 5 6 9 13 19 22 24"
    /sys/fs/cgroup
        /cpu
            /docker
                /{ID}
                    /tasks  # 进程ID列表
                    /cpu.cfs_quota_us  # 限制CPU使用百分比，如20000 = 20%
                    /cpu.shares
                    /...
        /memory
            /docker
                /{ID}
                    /tasks  # 进程ID列表
                    /memory.limit_in_bytes  # 限制内存上限，如1073741824 = 1G
        /blkio
            /docker
                /{ID}
                    /tasks  # 进程ID列表
                    /blkio.throttle.read_bps_device  # 限制磁盘读速率，如1048576 = 1M/s
        /pids  # 限制fork()或clone()出来的进程数量
            /docker
                /{ID}
                    /cgroup.procs  # 进程ID列表，$$代表所有进程
                    /tasks  # 进程ID列表
                    /pids.max  # max代表无限制
    ```


## 添加挂载

```bash
mkdir -p /sys/fs/cgroup/pids
mount -t cgroup -o pids none /sys/fs/cgroup/pids
```


## 容器操作

### 启动容器

`docker run --name c-dos -d -p 8080:8080 c-dos:latest`

### 释放所有容器

`` docker stop `docker ps -a -q`;docker rm `docker ps -a -q` ``

### 限制CPU

1. 设置容器使用CPU的相对权重`-c`或`--cpu-shares`，默认1024，如：`docker run -c 512 ubuntu`
1. 限制容器的CPU完全公平调度周期`--cpu-period`，默认100000，即100毫秒。
1. 限制容器在完全公平调度周期内的使用时长`--cpu-quota`，默认-1，即无限制。

    !!! example "举例说明"
        一个周期为100毫秒，最多有50毫秒跑这个容器。

        - "CpuPeriod": 100000
        - "CpuQuota": 50000 {==n核情况下乘以n==}
            - 在`/sys/fs/cgroup/cpu/foo/cpu.cfs_quota_us`中写入`50000`，限制`foo`控制组
            - 在`/sys/fs/group/cpu/foo/tasks`中写入进程ID

1. 限制CPU核心数 {==Docker 1.13版本支持==}，如`docker run --name c-dos --cpus 0.5 -p 8080:8080 c-dos:latest`
1. 限制可以使用的CPU核心和内存节点`--cpuset-cpus`, `--cpuset-mems`


### 限制内存

`docker run --name c-dos -m 1000M -p 8080:8080 c-dos:latest`

### 限制内存+swap

`docker run --name c-dos -m 1000M --memory-swap 1000M -p 8080:8080 c-dos:latest`

### 限制进程数量

- 限制UID用户最大进程数之和`--ulimit type=soft limit[:hard limit]`，如`--ulimit nproc=100`。{==无法对超级用户限制，forkbomb无效==}
- 限制容器的进程pid数量`--pids-limit 1000`, `-1`表示无限制。{==linux >= 4.3==}
- 限制？保护？内核内存`--kernel-memory 1000M`。{==linux >= 4.0==}

### 限制打开文件数量

- 限制UID用户打开文件数量`--ulimit nofile=1024:2048`
- 在容器中无法修改为比nofile更大的值。

!!! example
    - `ulimit -n unlimited`
    - `ulimit -n 2048`，将当前shell的当前用户所有进程能打开的最大文件数量设置为2048。  
        非root只能设置的越来越小，重新登录后被重置为limits.conf中的值，默认1024。

#### 限制登录用户

`/etc/security/limits.conf`

- domain, 用户/用户组
- type, soft <= hard
- item, cpu, nofile...
- value


### 其他限制

限制容器打开文件数量`--files-limit`
限制大文件`--hugetlb-limit [size:]limit`，如`--hugetlb 2MB:32MB`
限制软内存`--memory-reservation`


## 监控状态

### 查看CPU

```
top

%Cpu(s): xx us, xx sy, ..., xx id

PID USER PR NI VIRT RES SHR S %CPU %MEM TIME+ COMMAND
```

### 查看内存

- `free -m`
- `top`查看`KiB Mem: xx total, xx free, xx used`, `KiB Swap: xx total, xx free, xx used`

### 查看磁盘IO速率

```
iotop

TID PRIO USER DISK READ DISK WRITE SWAPIN IO COMMAND
```

### 查看进程数量

- `ps -ef | grep java/sh | wc -l`
- `docker top containerID | grep java | wc -l`

### 查看进程打开的文件数量

`lsof -p pid | grep c-dos | wc -l`

### 查看硬盘大小

- `fdisk -l`
- `df -h`
