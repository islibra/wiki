# 0x00_Linux基本命令_shell

!!! quote "[explainshell](https://explainshell.com/)"

- 显示命令历史记录：`HISTSIZE=1000`
- 往回删除一个单词: `ctrl + w`
- 删除光标以前的字符: `ctrl + u`
- 删除光标以后的字符: `ctrl + k`
- 清屏: `ctrl + l` 或 `clear`
- 设置别名：`alias ll='ls -al'`，添加到`/etc/profile`并执行`source /etc/profile`永久生效。
- 显示文件列表并按时间正序排列：`ll -tr`
- 读取符号链接指向的文件：`readlink xxxlinkfile`
- 查看程序依赖: `ldd xxx`


## I. Shell

### II. set 指令

#### III. set -x

```sh
$ cat setcmd.sh
#!/bin/bash

# 执行指令后，显示该指令及参数。用于脚本调试。
set -x
a=$$
b=$1
$ ./setcmd.sh 123 abc
+ a=96665
+ b=123
```

#### III. set -e

若指令传回值不等于0，则立即退出shell。

!!! quote "[Shell脚本中的set指令，比如set -x 和 set -e](https://www.cnblogs.com/robinunix/p/11635560.html)"


[SHELL输出颜色和闪烁控制](https://www.jianshu.com/p/ba1b8aded634)

```bash
#!/bin/bash

# bash xxx.sh 123 abc
printf "$ with $ is %s\n" "$$"  # 脚本当前运行的进程ID
printf "$ with ! is %s\n" "$!"  # 后台运行的最后一个进程的进程ID
printf "$ with ? is %s\n" "$?"  # 命令退出状态，0表示正常退出
printf "$ with * is %s\n" "$*"  # 所有参数字符串汇总输出
printf "$ with @ is %s\n" "$@"  # 所有参数字符串单个输出
printf "$ with # is %s\n" "$#"  # 参数个数
printf "$ with 0 is %s\n" "$0"  # 脚本名称
printf "$ with 1 is %s\n" "$1"  # 参数列表
printf "$ with 2 is %s\n" "$2"  #

######

$ with $ is 61952
$ with ! is
$ with ? is 0
$ with * is 123 abc
$ with @ is 123
$ with @ is abc
$ with # is 2
$ with 0 is test.sh
$ with 1 is 123
$ with 2 is abc
```

- ${var_name} 变量
- `#` 单行注释
- 单引号字符串中不能包含变量和反转义
- 标准输入0，标准输出1，标准错误2，> 重定向，>> 追加，如：`cmd 1 > file`, `cmd > file 2>&1`
- 命令替换：`USERID=反引号id -u反引号`, `USERID=$(uname -a)`

### II. 条件测试语句

```sh
if [ condition1 ]
then
  command1
elif [ condition2 ]
  command2
else
  commandn
fi
```

#### III. [ condition ]

- [ ! xxx ]: 逻辑非
- [ xxx -a yyy ]: 逻辑与
- [ xxx -o yyy ]: 逻辑或
- [ 'abc'=='xyz' ]: 字符串相等
- [ 'abc'!='xyz' ]: 字符串不等
- [ -z xxx ]: 空串
- [ -n xxx ]: 非空串
- [ a -eq b ]: 数值相等
- [ a -ne b ]: 不等
- [ a -gt b ]: 大于
- [ a -lt b ]: 小于
- [ a -ge b ]: 大于等于
- [ a -le b ]: 小于等于
- [ -d $xxx ]: 存在目录
- [ -f $xxx ]: 文件
- [ -s $xxx ]: 文件非空
- [ -L $xxx ]: 符号链接
- [ -x $xxx ]: 可执行
- [ -r $xxx ]: 可读
- [ -w $xxx ]: 可写

!!! example "`if [ -z "$HOME" -a -d $HOME/$num ]`"

!!! quote "[shell的逻辑与或非](https://www.cnblogs.com/aaronLinux/p/8340281.html)"


```sh
for var in 1 2 ... n
do
  command
done

while condition
do
  command
done
```
- 函数，在脚本中直接调用  
```bash
function_name()
{
  #statements
}
function_name arg1 arg2
```
- 文件包含：`source file.sh`, `. file.sh`


### FAQ: /bin/bash^M: bad interpreter: No such file or directory

使用`./xxx.sh`执行shell脚本时提示该错误, 是因为脚本文件是dos格式, 即换行符为`\r\n`

#### 判断文件格式

- `$ cat -A xxx.sh`, dos格式以`^M$`结尾, unix格式以`$`结尾
- `$ od -t x1 xxx.sh`, dos格式存在`0d 0a`, unix格式只有`0a`
- `$ vim xxx.sh`, `:set ff`, dos格式显示`fileformat=dos`, unix格式显示`fileformat=unix`

#### 修改文件格式

- `$ dos2unix xxx.sh`
- `$ sed -i "s/\r//" xxx.sh`或`$ sed -i "s/^M//" xxx.sh`
- `$ vim xxx.sh`, `:set ff=unix`


## 字符串处理

### 转换大小写

```bash
echo 'hello' | tr 'a-z' 'A-Z'
echo 'HELLO' | tr 'A-Z' 'a-z'
```

## 文件处理

### 远程拷贝

```bash
scp file.xxx user@hostip:/home/user
```

### 显示文件内容

```bash
cat file #查看全部内容
more file, file | more #分页查看
tail file, tail -f file #查看末尾几行
less file #滚动查看
```

### 计算文件值

```bash
$ base64 xxx

$ md5sum xxx
c7c1d76b5c119aae6dc91b7417a46b01 xxx

$ sha1sum xxx
c03f6f6290aff09aa3c4b644dc31167477b8b759  xxx

$ sha256sum xxx
e7a41fef535a329073dfe013711b41cf8b0112f02fbac0e36470c477b66bff9e  xxx
```
