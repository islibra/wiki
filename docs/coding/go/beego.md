# beego

go语言web框架，官方网站：<https://beego.me/>，github: <https://github.com/astaxie/beego>

!!! tip "go get"
    下载并安装package。  

    !!! example "选项"
        - -t, 同时下载测试用例

## 下载安装

```bash
go get github.com/astaxie/beego
```

## 创建文件

```go
package main

import "github.com/astaxie/beego"

func main() {
    beego.Run()
}
```

## 编译运行

```bash
go build -o hello hello.go
./hello
```

浏览器访问：<http://localhost:8080>

## 接口

```go
// 定义接口类
type MainController struct {
    beego.Controller
}

// 定义方法
func (this *MainController) Get() {
    this.Ctx.WriteString("hello world")
}

// 注册接口路径
// 声明一个自定义Controller变量，并将引用作为参数
// 相当于
// var main MainController
// 传入&main
beego.Router("/", &MainController{})
```

## 路由

```go
// 引入路由包，自动执行init方法
import (
    "quickstart/controllers"
)
```

## 执行逻辑

1. 监听端口
1. 用户连接
1. 初始化context
1. 过滤器BeforeRouter
1. 静态文件处理 | 过滤器AfterStatic
1. 查找路由 --> 正则路由 --> 自动化路由
1. Controller
    1. 过滤器BeforeExec
    1. init
    1. checkXsrfCookie
    1. prepare
    1. GET/POST
    1. render
    1. finish
    1. 过滤器afterExec
    1. destructor
1. admin监控统计URL

## 过滤器

```go
// 在main中导入filter包，自动执行init方法
import (
	"filters"
)

// 在init中创建过滤器
beego.InsertFilter(pattern string, position int, filter FilterFunc, params ...bool)
```

!!! example "参数列表"
    - pattern, 路由规则如`/*`
    - position, 执行Filter的位置
        - BeforeStatic 静态地址之前
        - BeforeRouter 寻找路由之前
        - BeforeExec 找到路由之后，开始执行相应的 Controller 之前
        - AfterExec 执行完 Controller 逻辑之后执行的过滤器
        - FinishRouter 执行完逻辑之后执行的过滤器
    - filter, 执行函数
