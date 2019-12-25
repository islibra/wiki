# iSCSI

## 存储优先级

1. 内置磁盘: 直接存取(Direct Attached Storage)
1. 外接存储: 通过SCSI存取
1. SAN: 通过光纤或iSCSI存取
1. NAS: 通过NAS操作系统建立文件系统, 以NFS方式提供给其他主机挂载使用

## SAN(Storage Area Networks)

提供给局域网内的所有机器进行磁盘存取, 通常使用光纤通信

## SCSI(Small Computer System Interface)

计算机与外部设备之间的接口

## iSCSI(internet SCSI)

将SCSI命令封装在TCP/IP包里

1. iSCSI target: 提供存储
1. iSCSI initiator: 主机访问
