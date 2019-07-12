# Linux系统管理_ps

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
service xxx restart
# 方式二
systemctl restart xxx.service
```


## 关机

```bash
shutdown -h now  # 将系统服务停掉后立刻关机
```


## Ubuntu允许root通过ssh直接登录

```bash
#修改/etc/ssh/sshd_config
PermitRootLogin yes
#重启ssh服务
ssh stop/waiting
ssh start/running, process 27639
```
