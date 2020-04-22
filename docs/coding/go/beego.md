# beego

go语言web框架。

!!! quote "官方网站"
    - <https://beego.me/>
    - github: <https://github.com/astaxie/beego>

## 下载安装

```bash
# 如果因为网络问题无法下载, 可以直接从github下载release包到workspace/src/github.com/astaxie/beego目录
$ go get github.com/astaxie/beego
```

!!! example "选项"
    - -t, 同时下载测试用例

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

## bee工具

## 新建项目

1. 进入`$GOPATH/src`, 执行`$ bee new quickstart`
1. `$ cd quickstart`
1. `$ bee run`

> Go语言执行过程: main --> pkg1 --> pkg2 --> pkg2.init() --> pkg1.init() --> main.init() --> main()

```go
package main

import (
    _ "quickstart/routers"
    "github.com/astaxie/beego"
)

func main() {
    beego.Run()
}
```


## Router

```go
package routers

import (
    "quickstart/controllers"
    "github.com/astaxie/beego"
)

// main中引入路由包时，自动执行init()方法
func init() {
    // 注册路由
    // 声明一个自定义Controller变量，并将其引用作为参数
    // 相当于
    // var main MainController
    // 传入&main
    beego.Router("/", &controllers.MainController{})
}
```


## Controller

```go
package controllers

import (
    "github.com/astaxie/beego"
)

// 定义接口类
type MainController struct {
    beego.Controller
}

// 定义方法(重写beego.Controller中的Get方法)
func (c *MainController) Get() {
    c.Data["Website"] = "beego.me"
    c.Data["Email"] = "astaxie@gmail.com"
    c.TplName = "index.tpl"
}

func (this *MainController) Post() {
    this.Ctx.WriteString("hello beego!")

    // 请求头
    input := this.Ctx.Input
    token := input.Header("Access-Token")
    this.Ctx.WriteString(token)
    this.Ctx.WriteString("\n")

    // 请求参数
    username := this.GetString("username")
    this.Ctx.WriteString(username)
    this.Ctx.WriteString("\n")
}
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

## 上下文context

- Input: 封装request
    - SetData: 设置Input中Data的值，方便用户在Filter中传递数据到Controller
    - GetData
- Output: 封装response

## 参数配置

默认配置文件路径: 应用同目录下的`conf/app.conf`

!!! quote "参考链接: [参数配置](https://beego.me/docs/mvc/controller/config.md)"
