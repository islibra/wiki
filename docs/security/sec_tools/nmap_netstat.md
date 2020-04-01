# nmap_netstat

## nmap

### 0x00_主机发现

#### 数据包

- ICMP echo request <-> reply
- TCP SYN 443
- TCP ACK 80
- ICMP timestamp request

#### 选项

- -sn 只进行主机发现，不进行端口扫描
- -Pn 跳过主机发现
- -PE 使用ICMP echo请求包发现主机
- -PS 使用TCP SYN请求包
- -PU 使用UDP请求包
- -n 不进行DNS解析
- -R 总是进行DNS解析

!!! example
    - 探测主机是否在线：`nmap -sn -PE -PS80,135 -PU53 ipaddr`
    - 探测局域网内活动的主机：`nmap -sn 1.1.1.1-9`, `nmap -sn 172.17.0.0/16`


### 0x01_端口扫描

#### 端口状态

- open
- closed
- filtered 被防火墙屏蔽
- unfiltered 没有被屏蔽，需要进一步确定
- open|filtered 开放或屏蔽
- closed|filtered 关闭或屏蔽

#### 扫描方式

- TCP SYN 半开放扫描，隐蔽 <-> ACK开放/RST关闭/未收到回复屏蔽
- TCP connect 系统网络API，建立完整的TCP连接，慢
- TCP ACK <-> RST未屏蔽，只能用来确定是否被屏蔽
- TCP FIN/Xmas tree（flags中FIN URG PUSH置为1的TCP）/NULL（所有flags为0） 秘密扫描 <-> RST关闭
- UDP <-> ICMP port unreachable关闭
- SCTP INIT/COOKIE-ECHO探测SCTP端口
- IP protocol探测支持的协议类型
- idle scan
- FTP bounce scan

#### 选项

- -sS/sT/sA/sW/sM，TCP SYN/connect/ACK/Window/Maimon scans
- -sU UDP
- -T4 扫描速率
- -p <port ranges>，指定扫描端口范围，如：`-p22`, `-p1-65535`, `-p U:53,111,T:21-25`
- -p- 扫描1-65535所有端口

!!! example
    - 扫描最有可能开放的前300个端口：`nmap -sS -sU -T4 -top-ports 300 ipaddr`


### 0x02_判断端口上运行的程序及版本

#### 选项

- -sV 版本侦测：`nmap -sV 1.1.1.1`
- --version-intensity <level> 强度0-9


### 0x03_OS侦测

#### 选项

- -O OS侦测：`nmap -O 1.1.1.1`


### 典型扫描

- -A 使能脚本
- -v 输出详细信息
- --reason 显示端口处于特殊状态的原因
- -oA {name} 用所有格式输出扫描结果，指定输出文件名称
- --max-scan-delay 探测报文最大时间间隔

!!! example
    - `nmap -sS -A -v --reason -p- -n -Pn -oA tcp ipaddr`
    - `nmap -sU -A -v --reason -p- -n -Pn --max-scan-delay 10 -oA udp ipaddr`
    - `nmap -sO -A -v --reason -n -oA proto ipaddr`

!!! faq "在未安装Nmap的机器上使用IE打开xml报告"
    拷贝Nmap安装目录下的nmap.xsl到未安装Nmap的机器上, 编辑xml报告, 修改xsl路径, 如:

    ```xml
    <?xml-stylesheet href="file:///D:/opt/installer/Nmap/nmap.xsl" type="text/xsl"?>
    ```

### 防火墙和IDS规避

- 数据包变换，分片-f, --mtu <val>
- 时序变换，IP诱骗，IP伪装-D <decoy1, [ME]>，指定源端口-g/--source-port <portnum>，扫描延时

#### 选项

- -F 快速扫描
- -D IP诱骗
- -g 指定源端口

!!! example
    - `nmap -v -F -Pn -D192.168.1.100,192.168.1.102,ME -g 3355 ipaddr`


### NSE脚本引擎

- 内嵌Lua解释器
- NSE library

#### 脚本格式

- description 脚本功能 [[]]
- comment 脚本格式 --
- author
- license
- categories
- rule: 触发条件 prerule, hostrule, portrule, postrule
- action 执行动作

#### 选项

- -sC --script=default 使用默认脚本扫描
- --script=<Lua scripts>: <Lua scripts>

#### 应用场景

- auth处理鉴权证书
- brute暴力破解
- dos

!!! example
    - 通过执行http相关脚本发现根目录无需认证：`nmap -p 80 -T4 --script http* -oX web.xml ipaddr`
    - 禁止sslv2, sslv3, tlsv1: `nmap -sV --script ssl-enum-ciphers -p 8889 172.28.13.196`


### 辅助命令

- `lsof -ni`
- 指定网卡发包：`nmap -e eth0 1.1.1.1`
- 畸形报文攻击，将SYN和FIN都置为1：`nmap -sX --scanflags URGACKPSHRSTSYNFIN 1.1.1.1`
- 加快扫描速度压力测试：`nmap -sX -T5 --scanflags SYNFIN 1.1.1.1`


## netstat

1. Active Internet connections
1. Active UNIX domain sockets，只能用于本机通信

### 参数选项

- -a 显示所有socket（默认只显示已建立的连接）
- -t 只显示tcp
- -u 只显示udp
- -l 显示正在监听的socket
- -n 以数字形式显示地址和端口号
- -p 显示进程ID或名称
- -o 显示timers

### State TCP连接状态

- LISTEN：正在监听端口，可以接受连接。
- SYN_SEND: 已发出建立连接请求SYN。
- SYN_RECEIVED: 收到对方建立连接请求SYN，并发送SYN和ACK给客户端。
- ESTABLISHED: 收到ACK，连接已建立，双方可以进行数据传递。
- FIN_WAIT_1: 客户端主动关闭连接时，已发送FIN报文。
- CLOSE_WAIT: 等待关闭。对方已close SOCKET并发送FIN，自己发送ACK，进入CLOSE_WAIT状态，自己close SOCKET并发送FIN给对方后关闭连接。
- FIN_WAIT_2: 发出FIN后收到服务器回应的ACK。
- LAST_ACK: 被动关闭连接收到FIN并发送ACK后，已发送FIN并等待ACK。
- TIME_WAIT: 准备关闭。收到了被动关闭方的FIN，并已发送ACK。
