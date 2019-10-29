# find_grep_awk_sed

## find

从指定的起始目录开始，递归地搜索其各个子目录，查找满足寻找条件的文件，并可以对其进行相关的操作。

格式：find [查找目录] [参数] [匹配模型] [[参数] [匹配模型]]

!!! example
    1. `find . -name "*.sh"`, 在当前目录（及子目录）下查找 {==以sh结尾==} 的文件。{>>-iname不区分大小写<<}
    2. `find . -perm 755`, 在当前目录（及子目录）下查找 {==属性为755==} 的文件。
    3. `find . -user root`, 在当前目录（及子目录）下查找 {==属主为root==} 的文件。
    4. `find /var -mtime -5`, 在 {==`/var`==} 下查找 {==更改时间在5天以内==} 的文件。
    5. `find /var -mtime +3`, 在 {==`/var`==} 下查找 {==更改时间在3天以前==} 的文件。
    6. `find /etc -type l`, 在 {==`/etc`==} 下查找文件类型为l的 {==链接文件==}。
    7. `find . -size +1000000c`, 在当前目录（及子目录）下查找文件大小 {==大于1M==} 的文件，1M是1000000个字节。
    8. `find . -perm 700 |xargs chmod 777`, 查找出当前目录（及子目录）下所有权限为700的文件，并把其权限重设为777。
    9. `find . -type f |xargs ls -l`, 查找出文件并查看其详细信息。
    1. {==逻辑与`-a`，逻辑或`-o`==}，`find . -name "xxx" -o -name "yyy"`
    1. {==逻辑非`!`==}, `find /etc/ssh -type f ! -user root -o ! -group root -o ! -perm 400 -name *key`, 查找用户不是root或用户组不是root或权限不是400的key文件。
    1. `find dir -path "dir/ignoredir" [-a] -prune -o -print`, 忽略ignoredir目录，意义为`if -path "test" then -prune else -print`。`find xxx \( -path xxx/iii1 -o -path xxx/iii2 \) -prune -o -print`, 忽略多个文件夹。`find xxx \( -path xxx/iii1 -o -path xxx/iii2 \) -prune -o -name "*.log" -print`, 忽略文件夹查找某类文件。


## grep

在每个file或标准输入中查找pattern

```bash
# 基本用法
cat filename.xxx | grep xxx
grep xxx filename.xxx

# -i --ignore-case 忽略大小写
# -C 显示上下文number行
# 查找多个文件
grep -i 'hello world' -C number first.java second.properties

# 查找多个关键词
cat filename.xxx | grep -E '123|abc'
cat filename.xxx | egrep '123|abc'

# 过滤关键词 -v --invert-match 查找不匹配的行
ps -efw | grep -v grep | grep java

# -e --regexp=PATTERN 使用正则表达式
cat filename.xxx | grep -e 'xxx.*yyy'
```


## awk

命令格式：`awk [-F field-separator] 'commands' input-file(s)`

!!! note "选项"
    - commands 是真正awk命令
    - [-F 域分隔符] 是可选的
    - input-file(s) 是待处理的文件

在awk中，文件的每一行中，由域分隔符分开的每一项称为一个域。通常，在不指名-F域分隔符的情况下，默认的域分隔符是空格。

!!! example "Demo"
    ```bash
    # 将passwd中的每一行，以:分割，打印第一个。
    $ cat /etc/passwd | awk  -F ':'  '{print $1}'
    ```

## sed

```bash
sed -e 4a\newline testfile  //在第四行后添加一行，并将结果输出到标准输出。-e，以指定脚本处理文本文件；a，新增。

nl /etc/passwd | sed '2,5d'  //列出文件内容并显示行号，删除2-5行。d，删除。

nl /etc/passwd | sed '2d'  //只删除第2行

nl /etc/passwd | sed '3,$d'  //删除第3到最后一行

nl /etc/passwd | sed '2i drink tea'  //加在第2行前

nl /etc/passwd | sed '2,5c No 2-5 number'  //将2-5行替换。c，替换。

nl /etc/passwd | sed -n '5,7p'  //仅列出5-7行。-n，仅显示script处理后的结果；p，打印输出。

nl /etc/passwd | sed -n '/root/p'  //搜索root关键字

nl /etc/passwd | sed '/root/d'  //删除包含root的行，其他行输出。

nl /etc/passwd | sed -n '/bash/{s/bash/blueshell/;p;q}'  //搜索并替换，打印输出，退出。s，替换。一组命令用花括号包含，分号分隔。

/sbin/ifconfig eth0 | grep 'inet addr' | sed 's/^.*addr://g' | sed 's/Bcast.*$//g'  //将IP前后删除。s搭配正则表达式，如1,20s/old/new/g。

nl /etc/passwd | sed -e '3,$d' -e 's/bash/blueshell/'  //多条命令
# 直接修改文件内容，将每一行结尾若为.替换为!。-i，直接修改。
sed -i 's/\.$/\!/g' xxx.txt

sed -i '$a # This is a test' xxx.txt  //最后一行新增
```
