# vps

## 历史背景

1. 2010.1 google退出中国，伊朗离心机失控 --> 国军筑墙，屁民爬梯
1. DNS污染 --> 改host
1. 封锁IP --> VPN，淘宝买帐号
1. 封锁国外VPN提供商 --> 换地址
1. 监控PPTP明文 --> L2TP加密
1. 干扰L2TP --> OpenVPN使用80, 443做VPN，证书认证握手并加密
1. 切断IPSec协议只剩IPSL国际专线 --> Cisco Anyconnect: linkSYS开源后的WRT54G固件衍生的后代OpenWRT刷到路由器上，再安装ocsv服务
1. 切断80, 443
1. 学习OpenVPN特征包包头要证书 --> SoftEther支持l2top, ipsec, openvpn，特征包学习干扰，伪装成ICMP与DNS 53的UDP协议，但丢包严重
1. shadowsocks: `github.com/clowwindy/shadowsocks`包头加上正常国外网站请求，数据AES256加密  --> 作者被请喝茶，删代码，市场下架
1. SSR加入流量混淆 --> 被人肉

## 云服务供应商

- AWS亚马逊，需严格遵守免费策略，对象存储S3
- Azure微软
- 谷歌云
- 阿里云，入门50/m

!!! note "说明"
    以上云都可以免费用一年

- 腾讯云，入门60/m
- 百度云，入门70/m
- 青云，免费一年30GB对象存储，17/m云主机

## 用途

- wordpress个人博客
- ownCloud个人网盘
- python爬虫
- 部署服务
- 挖矿

## 配置

- 入门1核1G
- 要选KVM系列
- 速度GIA > CN2 > 普通

## VPS

- DigitalOean 1C1G $5/m
    - 官方网站：<https://cloud.digitalocean.com>
    - 推广地址：<https://m.do.co/c/cd10d316fb54>
- 搬瓦工 $19.9/y，美国IT7公司
- Vultr $3.5/m，注册超30天有充值送$50，不推荐科学上网使用
- AWS Lightsail $5/m
- linode，东京新加坡最快，$5/m，新用户送$20，只支持信用

!!! quote "参考连接"
    - [推荐一个比搬瓦工VPS还便宜的云主机 - 云体验师](https://mp.weixin.qq.com/s/rf1OoAQmg5ffAKIaBl2YIQ)
    - [五分钟，开启比特币挖矿之旅！](https://mp.weixin.qq.com/s/BcQFnzujhsLIRkrdwTEOQg)
    - [体验：在Azure上免费创建一台Ubuntu虚拟机 - 云体验师](https://mp.weixin.qq.com/s/FgXYmSRQr-NZZR5mEuSp1g)
    - [【体验】AWS的VPS—Lightsail，平民玩家的首选 - 云体验师](https://mp.weixin.qq.com/s/lepIpZxIU3eA-gAoI_khwQ)
    - [那些年我们爬过的梯子。](https://mp.weixin.qq.com/s/qhWDldp8w6Kza2sjutmBUg)
    - [国外VPS搭建SSR多用户教程【中文一键安装版】](https://mp.weixin.qq.com/s/TI-gPGLBIeRS5JtjXGY4lg)
    - [关于团购VPS的事情报告 - 玄魂工作室](https://mp.weixin.qq.com/s/SHf8M5a11I3P3W-CWmM1dg)
