# compare

## shebang

python为脚本语言，会在第一行写shebang，而go没有。

```python
#!/usr/bin/python
```

## main

go必须要有main方法作为程序入口，而python没有。

```go
package main

func main() {
    //...
}
```


## 注释

```python tab="python"
# 单行注释

"""
多行注释
"""

'''
多行注释
'''
```

```go tab="go"
// 注释
```


## 打印输出

```python tab="python"
print("hello world!")
# 输出多个元素
print(a, b, c)
# end关键字，控制单行输出，末尾添加指定字符。
print(x, end=',')
```

```go tab="go"
fmt.Printf("hello, world\n")
// 输出多个元素
fmt.Println(a, b, c, d, e)
// 格式化输出
fmt.Printf("the %d ele is %d\n", i, v)
```


## 运行

```bash tab="python"
python xxx.py
```

```bash tab="go"
go run xxx.go
```


## 数据类型

```python
# 布尔值
isTrue = True
isFalse = False
```

```go
```

 tab="python"

 tab="go"

### 数据类型转换

```python tab="python"
# byte  -->  int
int.from_bytes(xxx, byteorder='big')
```


## 变量赋值

```python tab="python"
# 自动转换类型
a, b = 0, 1
```

```go tab="go"
// 声明类型
var c, d int [= 1, 2]  //赋值
// 简洁赋值，只能用在函数内部
e := 3
```


## for循环

```python tab="python"
# 对列表进行遍历
names = ['Alice', 'Bob', 'Cavin', 'David']
for name in names:
  # ...
else:
  # ...

# 使用range函数生成一个数字范围列表，左闭右开区间
for i in range(len(names)):
  print(i, names[i])
```

```go tab="go"
// 对数组进行遍历
primes := [6]int{2, 3, 5, 7, 11, 13}
// 直接使用range关键字遍历数组，返回值第一个为下标，第二个为元素副本，可使用_忽略
for i, v := range primes {
    // ...
}

// 循环
for i := 0; i < 5; i++ {
	fmt.Println(i)
}
```


## 函数

```python tab="python"
def xxx(arg1, arg2):
    # TODO:
    return xxx
```

```go
```

 tab="go"


## 导入包

```python tab="python"
# 0x00_导入文件名
import filename

filename.func()

# 0x01_只导入文件中def定义的方法
from filename import func

func()

# 0x02_包目录下需包含空的__init__.py
import sound.effect
sound.effect.area()
```

```go tab="go"
// project/src下的main.go
package main

// 创建包路径如：math/rand，目录内所有文件都是
package rand

//////

// 导入包
import (
    "math/rand"
)

rand.xxx()
```


## 类

```python tab="python"
# 定义类
# (object)代表继承自object
class User(object):
    # 定义构造方法
    def __init__(self, nm, pd):
        self.name = nm
        self.password = pd

user = User('alice', 'Admin@123')

# output: alice, Admin@123
print('{user.name}, {user.password}'.format(user=user))
```

```go
```

 tab="go"
