# helloworld

官方网站：<https://golang.org/>

中文版：<https://go-zh.org/>

提取安装包到指定目录：`tar -C /usr/local/ -zxf go-go1.12.5.tar.gz`

设置环境变量：`GOPATH`，指向自定义workspace。

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
