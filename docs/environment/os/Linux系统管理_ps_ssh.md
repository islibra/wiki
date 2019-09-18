# Linux系统管理_ps_ssh

## ps

### 选项

- `--help all`, 查看所有帮助
- `--no-headers`, 不显示标题
- `-e`, 查询所有进程
- `-f`, 输出所有信息，包含UID, PID, PPID, C, STIME, 命令行CMD
- `-o {format}`, 指定输出格式，如：`ps -o pid,args`, `ps -ew -o pid,ppid,user,cmd`
- `-w`, 不限制输出宽度
- -p {PID1} {PID2}, 查询指定进程ID
- -u {UID1},{UID2} 查询指定用户


## 重启服务

```bash
# 方式一
systemctl restart xxx.service
# 方式二
service xxx restart
# 开机启动
systemctl enable xxx
```


## 关机

```bash
shutdown -h now  # 将系统服务停掉后立刻关机
```


## ssh

### Ubuntu安装ssh

```bash
$ sudo apt-get install openssh-server
```

### Ubuntu允许root通过ssh直接登录

```bash
#修改/etc/ssh/sshd_config
PermitRootLogin yes
#重启ssh服务
ssh stop/waiting
ssh start/running, process 27639
```

### 设置ssh连接不超时

#### 修改sshd_config

配置文件路径: `/etc/ssh/sshd_config`

> ClientAliveInterval 300  #服务器向客户端请求消息的时间间隔, 设置成3600秒或更长.
> ClientAliveCountMax 0  #服务器发出请求后客户端没有响应的最大次数, 超过自动断开. 默认客户端不会响应. 设置成3或更大.

重新载入配置文件

```bash
service sshd reload
```

#### 修改TMOUT环境变量

配置文件路径: `/etc/profile`

> export TMOUT=300  #设置为3600或更长.

重新载入配置文件

```bash
source profile
echo $TMOUT  #查看是否生效
```

参考：[https://www.cnblogs.com/enjoycode/p/5022607.html](https://www.cnblogs.com/enjoycode/p/5022607.html)
