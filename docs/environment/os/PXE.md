# PXE

网络安装操作系统Pre-boot execution environment

PXE client在网卡的ROM中，引导时由BIOS调入内存执行，显示命令菜单，将远端操作系统通过网络下载到本地运行。

客户机从DHCP获取IP，寻找iPXE服务器 --> tftp获取开机启动文件 --> HTTP/TFTP/FTP加载安装文件 --> 本地安装

!!! quote "参考链接"
  <https://mp.weixin.qq.com/s/jhvzDRn-9i2OEME51yrLUg>
