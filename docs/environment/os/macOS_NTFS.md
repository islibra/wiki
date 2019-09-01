# macOS_NTFS

```bash
$ sudo vim /etc/fstab
# 新增, xxx为硬盘名称
LABEL=xxx none ntfs rw,auto,nobrowse
```

重新插入硬盘, 使用磁盘工具, 右键 - 在访达中显示

!!! warning "使用磁盘工具, 右键 - 卸载 - 推出"
