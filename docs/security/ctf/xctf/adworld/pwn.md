# pwn

## 0x00_get_shell

1. 使用`file`看出文件是64bit

    ```bash
    $ file get_shell
    get_shell: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=6334e8ad1474b290bdb69d75a1b44ed029669888, not stripped
    ```

1. 使用`checksec`

    ???+ note "checksec"
        [checksec](https://github.com/slimm609/checksec.sh)是用来检查可执行文件属性的shell脚本.

    ```bash
    $ ./checksec --file=../../adworld/pwn/get_shell
    RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable  FILE
    Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   68 Symbols     No       0               0       ../../adworld/pwn/get_shell
    ```

1. 运行程序, 表示服务器上运行的程序可以让我们拿到shell!

    ```bash
    $ ./get_shell
    OK,this time we will get a shell.
    sh-4.3# id
    uid=0(root) gid=0(root) groups=0(root)
    ```

1. 使用`nc`正向连接服务器, 查看服务器文件, 获取flag

    ```bash hl_lines="2 10"
    $ nc 111.198.29.45 45955
    ls
    bin
    dev
    flag
    get_shell
    lib
    lib32
    lib64
    cat flag
    cyberpeace{28010e1bfd680641e27335a3b41273d0}
    ```

    ???+ tip
        使用`nc`连接到远程服务器后, 没有任何提示符, 直接使用命令即可.
