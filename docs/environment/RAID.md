# RAID

Redundant Array of Independent Disks, 磁盘阵列, 利用虚拟化技术把多个硬盘组合起来, 成为一个硬盘阵列组, 提升性能或数据冗余

- RAID0: 2块硬盘合并成一块逻辑盘, 数据分散存储, 无冗余, 一个硬盘异常, 全部硬盘都会异常, 追求最大容量、速度
- RAID1: 2块硬盘互为镜像, 可用容量1, 互为备份, 追求最大安全性
- RAID5: 3块硬盘, 可用容量n-1, 追求最大容量、最小预算
