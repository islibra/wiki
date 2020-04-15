# vim

## 全局配置文件

`/etc/vim/vimrc`

```bash
# 默认语法高亮
i f has("syntax")
  syntax on
endif

# 自动缩进
set autoindent/noautoindent  # 新行的缩进值与上一行相等
set smartindent  # 识别花括号, #注释不缩进
set expandtab  # 使用空格代替制表符缩进
set ts=4  # 缩进空格数量

# 显示行号
set number
```


## 快捷键

- `:set paste/nopaste`  粘贴模式, 不自动缩进
- `:set nu/number/nonu/nonumber`  显示/取消显示行号
- `:set encoding=utf-8`  设置编码
- `Ctrl + u`  向上翻半屏
- `Ctrl + d`  向下翻半屏
- `Ctrl + f`  向下翻一屏
- `Ctrl + b`  向上翻一屏
- `:行号`  跳转到指定行
- `:$`  跳转到最后一行
- `/xxx`  向下搜索xxx
- `?xxx`  向上搜索xxx
- `n`  查找下一个匹配
- `shift + n`  查找上一个匹配
- `noh`  取消高亮
- `dd`  删除整行
- `ndd`  删除n行
- `D`  删除从光标到末尾
- `a`  在当前字符后插入
- `A`  在行末插入
- `i`  在当前字符前插入
- `I`  在行首插入
- `o`  在下一行插入
- `O`  在上一行插入
- `:a,bs/F/T`  从第a行到第b行将F替换为T
- `:f`  显示当前文件名、光标所在行、显示比例
- `:wq`  存盘退出
- `:q!`  强制退出


## Linux编辑二进制文件

1. 创建二进制文件`echo -n "ABCDEFGHIJKLMNOPQRSTUVWXYZ abcdefghijklmnopqrstuvwxyz" > test.bin`

    > -n: 不添加换行符

1. 使用vim打开文件`vim -b test.bin`

    > -b: 以二进制方式打开文件

1. 切换到十六进制模式`:%!xxd`
1. 进入编辑模式修改文件
1. 切换回文本模式`:%!xxd -r`
1. 保存退出

!!! quote "参考链接: [在Linux下使用vim配合xxd查看并编辑二进制文件](https://www.cnblogs.com/killkill/archive/2010/06/23/1763785.html)"
