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
