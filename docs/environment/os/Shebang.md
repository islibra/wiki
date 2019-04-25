# Shebang

文件开头#!，后面添加解释器绝对路径如：`/bin/bash`。

## 调用场景

- 使用./xxx调用时
    - 无x，报错`-bash: ./test.sh: Permission denied`。
    - 若不存在#!，使用当前shell ${SHELL}执行。
    - 若#!之后是可执行文件，则会把文件名和参数一起传递给可执行文件。
    - 无指定程序执行权限或不存在报错`-bash: ./test.sh: /bin/bas: bad interpreter: No such file or directory`。
    - 非可执行文件，忽略，使用当前shell执行。
- 使用bash xxx调用，忽略，查找环境变量找到bash执行。

!!! tip
    使用bash xxx执行时，即使文件本身无可执行权限x，也可正常执行。
