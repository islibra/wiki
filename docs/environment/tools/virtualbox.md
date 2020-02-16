# virtualbox

## 分辨率

1. 下载<http://download.virtualbox.org/virtualbox/6.0.6/VBoxGuestAdditions_6.0.6.iso>
1. 启动VM, Devices - Insert Guest Additions CD image...
1. CD 驱动器 - VBoxWindowsAdditions.exe, 重启
1. View - Seamless Mode


## 共享文件夹

1. 关闭VM，设置 - 共享文件夹 - 添加
1. 选择HOST要共享的文件夹路径，共享文件夹名称和挂载点，勾选自动挂载和固定分配。
1. 启动VM，执行命令`mount -t vboxsf 共享文件夹名称 挂载点`
