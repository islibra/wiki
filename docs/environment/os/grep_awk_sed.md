# grep_awk_sed

## grep

在每个FILE或标准输入中查找PATTERN.

!!! example "Demo"
    ```bash
    grep -i 'hello world' first.java second.properties
    ```

    !!! note "参数"
        - -i --ignore-case 忽略大小写
        - -v --invert-match 查找不匹配的行

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
