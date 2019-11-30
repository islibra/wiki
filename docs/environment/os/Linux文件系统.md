# Linux文件系统

| 目录 | 用途 | 备注 |
| --- | --- | --- |
| /bin /usr/bin /usr/local/bin | 最常用的二进制命令 | 如：ls mv cat |
| /sbin /usr/sbin /usr/local/sbin | 系统专用的二进制命令 | root使用，如：fdisk shutdown mount |
| /lib /usr/lib /usr/local/lib | 系统使用的库文件 | 如：/lib/modules |
| /boot | 系统启动时用来引导Linux的文件，建议**单独分区**100M即可 | 如：/boot/vmlinuz为linux内核文件，/boot/grub |
| /dev | 设备文件 | 如：mount /dev/cdrom /mnt/cdrom挂载光驱 |
| /etc | 系统配置文件，修改之前记得备份 | 如：/etc/inittab /etc/fstab /etc/init.d /etc/X11 /etc/sysconfig |
| /home | 各用户的根目录，用~表示，建议**单独分区**，设置较大的磁盘空间 |   |
| /root | root的根目录，用~表示，建议和/放置在同一个分区下 |   |
| /lost+found | 系统异常时丢失的文件 | 挂载硬盘后自动生成，如：mount /dev/dm-0 /xxx，生成/xxx/lost+found |
| /mnt /media | 媒体挂载点 | 如：/mount -o loop xxx.iso /mnt/cdrom |
| /opt | 安装第三方软件目录 |   |
| /proc | CPU、进程、内存、IO、网络数据，内存的映射，虚拟目录，不占用磁盘空间 | 如：/proc/cpuinfo /proc/interrupts /proc/dma /proc/ioports /proc/net/* |
| /sys | 系统信息 |   |
| /tmp | 临时文件目录，一般用户或正在执行的程序都可存放，任何人都可以访问，重要数据不可放置在此目录下 |   |
| /srv | 服务启动后需要访问的数据目录 | 如：/srv/www |
| /usr | 普通用户的应用程序、库文件、文档，建议**单独分区**，设置较大的磁盘空间 | 如：/usr/bin应用程序 /usr/lib库文件 /usr/share共享数据 /usr/local软件升级包 /usr/share/doc系统说明文件 /usr/share/man程序说明文件 |
| /var | 动态变化的文件，建议**单独分区**，设置较大的磁盘空间 | 如：日志/var/log /var/log/message 邮件/var/spool/mail 程序PID/var/run |

## setuid

```bash
$ ll /etc/passwd /usr/bin/passwd
-rw-r--r-- 1 root root  1678 Jul 11 18:24 /etc/passwd
-rwsr-xr-x 1 root root 54256 May 17  2017 /usr/bin/passwd*
```

让执行该命令的用户以该命令拥有者的权限去执行

> 命令必须先具备x权限


!!! quote "参考链接: [setuid与setgid讲解](https://www.jianshu.com/p/70f9ea162ca9)"
