# Tips

## 禁用TrustedInstaller

开始 - 运行 - services.msc - Windows Modules Installer, 停止并禁用。

## 查看文件正在被谁占用

```bash
$ ps -ef | grep vi
root     102779  58731  0 12:37 pts/2    00:00:00 vim /tmp/hsperfdata_paas/log/alarm.log
xxxx     113800 113402  0 12:42 pts/3    00:00:00 grep --color=auto vi

$ who
paas     pts/0        2018-08-13 11:16 (10.65.58.185)
paas     pts/1        2018-08-13 11:29 (10.65.69.168)
paas     pts/2        2018-08-13 15:17 (10.65.74.130)
paas     pts/3        2018-08-14 12:42 (10.74.201.219)
```

## rm: 无法删除"xxxdir": 设备或资源忙

```bash
umount xxxdir
rm -rf xxxdir
```
