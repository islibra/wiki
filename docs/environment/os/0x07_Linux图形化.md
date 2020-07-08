# 0x07_Linux图形化

1. 在远程 Linux 上安装 X11 client

    ```sh
    $ yum install xorg-x11-xauth xorg-x11-fonts-* xorg-x11-font-utils xorg-x11-fonts-Type1 xclock
    ```

1. 修改 SSH 配置

    ```sh
    $ vim /etc/ssh/sshd_config
    X11Forwarding yes
    X11UseLocalhost no
    $ systemctl restart sshd.service
    ```

1. 测试验证: `xclock`

> 如果使用 Java, 在启动参数添加 `-Djava.awt.headless=true \`
