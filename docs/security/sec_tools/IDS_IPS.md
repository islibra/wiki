# IDS_IPS

## Suricata

![](https://img.shields.io/badge/feature-IDS_IPS_NSM-brightgreen.svg)

> 替代snort入侵检测系统, 完全兼容snort规则语法和支持lua脚本

- 配置文件位置：/etc/suricata/suricata.yaml
    - HOME_NET
    - EXTERNAL_NET
    - default-rule-path设置规则目录
    - rule-files来选择启用那些规则

### 规则定义/etc/suricata/rules

alert tcp $EXTERNAL_NET $FILE_DATA_PORTS -> $HOME_NET any

规则行为 协议 源ip 源端口 流量方向 目标ip 目标端口

- 规则行为，根据优先级排列：
    - pass 如果匹配到规则后，suricata会停止扫描数据包，并跳到所有规则的末尾
    - drop ips模式使用，如果匹配到之后则立即阻断数据包不会发送任何信息
    - reject 对数据包主动拒绝，接受者与发送中都会收到一个拒绝包
    - alert 记录所有匹配的规则并记录与匹配规则相关的数据包

- 协议：TCP、UDP、ICMP、IP（同时用与TCP与UDP）、http、ftp、smb、dns
- 源ip，目标ip：支持单个ip，cidr，ip组，[96.30.87.36,96.32.45.57]，所有主机any，以及规则文件中配置的ip变量$HOME_NET（受保护的ip段）与$EXTERNAL_NET（其他所有ip）：
- 源端口/目标端口：支持设置单个端口80，端口组[80,8080],端口范围[1024:65535]以及any任意端口,还可以在配置文件中添加端口组，通过！号来进行排除
- 流量方向：
    - -> 单向流量，从源ip到目标ip的单项流量
    - <> 双向流量，2个ip往返之间的流量


### 规则更新

```bash
$ apt install python-pip python-yaml    
$ pip install --pre --upgrade suricata-update
$ suricata-update
```

#### 源

- et/open
- ptresearch/attackdetection
- sslbl/ssl-fp-blacklist

### 规则检测

#### 手工编写规则检测Windows回传信息

#### lua脚本检测ssl自签名

!!! quote "参考链接: [Suricata IDS 入门 — 规则详解](https://www.secpulse.com/archives/71603.html)"


## Snort

![](https://img.shields.io/badge/feature-NIDS_NIPS-brightgreen.svg)

### 目录结构

- /etc/snort/snort.conf
- /etc/snort/rules/xxx.rules

!!! quote "参考链接: [SNORT入侵检测系统](https://wooyun.js.org/drops/SNORT%E5%85%A5%E4%BE%B5%E6%A3%80%E6%B5%8B%E7%B3%BB%E7%BB%9F.html)"
