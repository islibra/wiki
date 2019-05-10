# helloworld

官方网站：<https://golang.org/>

中文版：<https://go-zh.org/>

提取安装包到指定目录：`tar -C /usr/local/ -zxf go-go1.12.5.tar.gz`

设置环境变量：`GOPATH`，指向自定义workspace。

!!! info
	在GOPATH下创建src目录，将项目放在src下，GoLand才能找的到依赖。

## demo

在workspace下建立目录：`src/hello`，新建`hello.go`。

```go
package main

import "fmt"

func main() {
	fmt.Printf("hello, world\n")
}
```

进入到`src/hello`，执行`go build`生成hello.exe，执行`hello`启动demo。

或

执行`go run hello.go`直接运行程序。

## 包

创建包路径如：`math/rand`，`rand`包内所有`.go`文件都以`package rand`开头。

导入时使用  
```go
import (
	"math/rand"
)
```

调用时使用`rand.xxx()`

## 库函数

- time: time.Now()获取当前时间
