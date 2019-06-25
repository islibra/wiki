# hellogo

官方网站：<https://golang.org/>

中文版：<https://go-zh.org/>

二进制安装包下载地址：<https://golang.org/dl/>

提取安装包到指定目录：`tar -C /usr/local/ -zxf go1.12.5.linux-amd64.tar.gz`

!!! info "linux添加环境变量"
	1. 执行`vim /etc/profile`
	1. 添加`export PATH=$PATH:/usr/local/go/bin`
	1. 执行`source /etc/profile`
	1. 查看go版本`go version`

!!! info "windows设置环境变量"
	1. 添加`GOPATH`，指向自定义workspace，在workspace下建立目录src，并创建main.go和package。使用`go get`也会将库默认下载到该目录下。
	1. 使用GoLand导入工程 {>>一般是包含src的目录<<} 后，File - Settings - Go - GOPATH - Project GOPATH，添加工程目录 {>>包含src的目录<<}，在GoLand中才能找到依赖。

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

!!! tip "提示"
	如果在同一个包中定义多个文件，需要执行`go run hello1.go hello2.go`，否则会报undefined。

## 包

创建包路径如：`math/rand`，`rand`包内所有`.go`文件都以`package rand`开头。

导入时使用  
```go
import (
	"math/rand"
)
```

调用时使用`rand.xxx()`

## 变量

```go
//声明变量
var a, b int
//变量初始化
var c, d int = 1, 2
//简洁赋值语句，代替var和类型声明，只能用在函数内部
e := 3
fmt.Println(a, b, c, d, e)
```

## 数组

```go
// 数组
var str [2]string
str[0] = "hello"
str[1] = "world"
fmt.Println(str[0], str[1])  // hello world
fmt.Println(str)  // [hello world]

// 注意这里使用简洁赋值语句，但还是声明了数组类型
primes := [6]int{2, 3, 5, 7, 11, 13}
fmt.Println(primes)  // [2 3 5 7 11 13]

// 切片，大小可变的数组
var s []int = primes[1:4]  //左开右闭区间，下标从0开始
fmt.Println(s)  // [3 5 7]

// 使用内建函数向切片追加元素
s = append(s, 9, 8)  //append返回新的切片，大小动态增长，为2的次幂
fmt.Println(s)  // [3 5 7 9 8]

// 使用make创建slice
sl := make([]int, 5)
fmt.Println("length:", len(sl), sl)  // length: 5 [0 0 0 0 0]

// 指定容量
sl2 := make([]int, 0, 3)  // 类型，长度，容量
fmt.Println("length:", len(sl2), "capacity:", cap(sl2), sl2)  // length: 0 capacity: 3 []
```

## 结构体

结构体是一组字段。

```go
//定义结构体
type Vertex struct {
    X int
    Y int
}

//结构体，无需实例化
fmt.Println(Vertex{1, 2})
```

## 结构体方法

带接收者参数的函数，位于`func`和方法名之间。

```go
//定义结构体
type Vertex struct {
    X int
    Y int
}

//定义结构体参数
func (v Vertex) Abs() int {
    return v.X*v.X + v.Y*v.Y  //在函数内引用结构体
}

//结构体，无需实例化
v := Vertex{1, 2}
fmt.Println(v.Abs())  //调用结构体方法
```

## 指针接收者

可以修改结构体的值。

```go
//定义结构体
type Vertex struct {
    X int
    Y int
}

//定义结构体参数
func (v Vertex) Abs() int {
    return v.X*v.X + v.Y*v.Y  //在函数内引用结构体
}

//指针接收者
func (v *Vertex) Scale(i int) {
    v.X = v.X*i
    v.Y = v.Y*i  //修改指针接收者的值，注意这里还是用点号
}

//结构体，无需实例化
v := Vertex{1, 2}
v.Scale(10)  //修改指针接收者的值，注意这里还是用点号
fmt.Println(v.Abs())  //调用结构体方法
```

## range

```go
//range
for i, v := range primes {  //返回值第一个为下标，第二个为元素副本，可使用_忽略
    fmt.Printf("the %d ele is %d\n", i, v)
}
```

## 库函数

### encoding/json

```go tab="函数原型"
// 将字节数组反序列化为对象
func Unmarshal(data []byte, v interface{}) error
```

!!! quote
	示例代码参见：go语言安全编程 - 序列化敏感数据造成信息泄露

### io/ioutil

```go tab="函数原型"
// 一次性读取整个文件
func ReadFile(filename string) ([]byte, error)
```

```go tab="示例代码" hl_lines="8"
import (
    "fmt"
    "io/ioutil"
)

func main() {
	dstFilePath := "E:\\doc\\atom\\docs\\index.md"
    content, err := ioutil.ReadFile(dstFilePath)
    if err != nil {
        fmt.Println("error")
    }
    fmt.Println(string(content))
}
```

### os/user

```go tab="函数原型"
type User struct {
}

// 运行当前程序的用户
func Current() (*User, error)
```

```go tab="示例代码"
import (
    "os/user"
    "fmt"
)

func main() {
	// 运行程序的用户
    fmt.Println(user.Current())
}
```

### path/filepath

```go tab="函数原型"
// 返回路径中的最后一个元素
func Base(path string) string

// 返回pattern匹配到的所有文件名完整路径
func Glob(pattern string) (matches []string, err error)
```

```go tab="示例代码"
import (
    "path/filepath"
    "fmt"
)

func main() {
	// 绝对路径，返回 test.sh
    fmt.Println(filepath.Base("/tmp/xxx/yyy/test.sh"))
    // 相对路径，返回 test.sh
    fmt.Println(filepath.Base("tmp/xxx/yyy/test.sh"))
    // 空，返回 .
    fmt.Println(filepath.Base(""))
    // 全部分隔符，返回 /
    fmt.Println(filepath.Base("////"))

	// 返回pattern匹配到的所有文件名完整路径
    fmt.Println(filepath.Glob("E:\\doc\\atom\\docs\\*.md"))
}
```

### runtime
 tab="函数原型"
```go
// Go通过独立的进程GC进行垃圾回收
// 可通过runtime包访问GC，如runtime.GC()显式触发GC

// 
func SetFinalizer(obj interface{}, finalizer interface{})
```

```go tab="示例代码"
```

### strconv

```go tab="函数原型"
// 将字符串转化成数字
// base: 进制2-36, 如果为0，根据字符串前缀自动判断：0x为16进制，0为8进制，其他为10进制
// bitSize: 数字类型：0 int, 8 int8, 16 int16, 32 int32, 64 int64
// 如果为空或包含非法数字返回ErrSyntax, 0，如果超过类型最大值返回ErrRange, bitSize同符号最大值。
func ParseInt(s string, base int, bitSize int) (i int64, err error)
```

```go tab="示例代码"
import (
    "strconv"
    "fmt"
)

func main() {
	// 将字符串转换为数字
    // 二进制，返回 12
    intStr := "00001100"
    fmt.Println(strconv.ParseInt(intStr, 2, 0))
    // 十进制，返回 123
    intStr = "123"
    fmt.Println(strconv.ParseInt(intStr, 10, 0))
    // 自动判断进制，返回 15
    intStr = "0x0F"
    fmt.Println(strconv.ParseInt(intStr, 0, 0))
    // 空，返回 invalid syntax, 0
    i, err := strconv.ParseInt("", 0, 0)
    if err != nil {
        fmt.Println(err)
        fmt.Println(i)
    }
    // 包含非法字符，返回 invalid syntax, 0
    j, errj := strconv.ParseInt("10ab", 0, 0)
    if errj != nil {
        fmt.Println(errj)
        fmt.Println(j)
    }
    // 超过类型最大值，返回 value out of range, 2147483647
    imax, errmax := strconv.ParseInt("2147483650", 0, 32)
    if errmax != nil {
        fmt.Println(errmax)
        fmt.Println(imax)
    }
}
```

### time

time.Now()获取当前时间

### xml

```go
package main

import (
	"encoding/xml"
	"fmt"
)

type Result struct {
	XMLName xml.Name `xml:"DockerNSAuthV2"`	 //xml根节点
	NSID int `xml:"NSID"`
	User_id string `xml:"user_id"`
	User_name string `xml:"user_name"`
	Auth int `xml:"auth"`
	//Created 结构体中不存在，忽略
	Updated string `xml:"updated"`
	Domain_name string `xml:"domain_name"`
	Namespace_name string `xml:"namespace_name"`
	Other string  //xml中不存在，忽略
}

func ParseXml() {
	data := `
	<DockerNSAuthV2>
		<NSID>0</NSID>
		<user_id>828c7f051527455db66213e8ea9e6bc4</user_id>
		<user_name>usrlee</user_name>
		<auth>7</auth>
		<created>0001-01-01T00:00:00Z</created>
		<updated>2019-05-07T11:23:23.559672796Z</updated>
		<domain_name>telee</domain_name>
		<namespace_name>repospacelee</namespace_name>
	</DockerNSAuthV2>
	`

	v := Result{}
	err := xml.Unmarshal([]byte(data), &v)  //转换成byte数组，转换后赋值给v，返回错误信息
	if err != nil {
		fmt.Printf("error: %v", err)
		return
	}
	fmt.Print(v)
	fmt.Println()
}
```

!!! quote "参考链接"
	[Go语言xml格式](https://mp.weixin.qq.com/s?__biz=MzU0ODc4MjE0Nw==&mid=2247484081&idx=1&sn=7c305948a72471a605525cf0ece0df5c&chksm=fbb8ab9dcccf228b598fd6363fd58c8151aaae465d6cbcf85c7ba3b63b4cc554ebd10abce915&scene=7&ascene=0&devicetype=android-26&version=2700043a&nettype=WIFI&abtest_cookie=BQABAAgACgALABIAEwAGAJ6GHgAjlx4AxZkeANyZHgD1mR4AAJoeAAAA&lang=zh_CN&pass_ticket=WketPNhCwlbklAEEdO8wwYBYBsa2VlSHnRJ6qOJUhQ%2Bmd%2Bs0TlxtPDDi%2FfLAamwT&wx_header=1)

### flag

实现命令行参数解析。

```go
//参数标签
var help bool  //不带参数值
var version *bool
var email string  //带参数值
//指定变量存储标签的值，标签名称，默认值，标签描述
flag.BoolVar(&help, "h", false, "display help info")
//另一种方式赋值
version = flag.Bool("v", false, "display version")
flag.StringVar(&email, "e", "admin@xxx.com", "email address")
flag.Parse()

fmt.Println(help)
fmt.Println(*version)
fmt.Println(email)
flag.PrintDefaults()  //打印参数选项
```

!!! quote "参考链接"
	[golang flag包使用笔记](https://www.jianshu.com/p/f9cf46a4de0e)

### archive

#### tar

!!! example "文件类型"
    - TypeReg           = '0'    // regular file // 普通文件
    - TypeRegA          = '\x00' // regular file // 普通文件
    - TypeLink          = '1'    // hard link // 硬链接
    - TypeSymlink       = '2'    // symbolic link // 符号链接
    - TypeChar          = '3'    // character device node // 字符设备节点
    - TypeBlock         = '4'    // block device node // 块设备节点
    - TypeDir           = '5'    // directory // 目录
    - TypeFifo          = '6'    // fifo node // 先进先出队列节点
    - TypeCont          = '7'    // reserved // 保留位
    - TypeXHeader       = 'x'    // extended header // 扩展头
    - TypeXGlobalHeader = 'g'    // global extended header // 全局扩展头
    - TypeGNULongName   = 'L'    // Next file has a long name // 下一个文件记录有个长名字
    - TypeGNULongLink   = 'K'    // Next file symlinks to a file w/ a long name // 下一个文件记录指向一个具有长名字的文件
    - TypeGNUSparse     = 'S'    // sparse file // 稀疏文件

### os

#### FileInfo

func Lstat: 返回文件或符号链接的FileInfo。

```go
type FileInfo interface {
    Name() string       // base name of the file
    Size() int64        // length in bytes for regular files; system-dependent for others
    Mode() FileMode     // 返回FileMode, file mode bits
    ModTime() time.Time // modification time
    IsDir() bool        // abbreviation for Mode().IsDir()
    Sys() interface{}   // underlying data source (can return nil)
}
```

#### FileMode

以bit形式表示文件类型和权限。

```go
type FileMode uint32
```

!!! example "文件类型"
    - ModeDir        FileMode = 1 << (32 - 1 - iota) // d: is a directory
    - ModeAppend                                     // a: append-only
    - ModeExclusive                                  // l: exclusive use
    - ModeTemporary                                  // T: temporary file (not backed up)
    - ModeSymlink                                    // L: 符号链接，symbolic link
    - ModeDevice                                     // D: device file
    - ModeNamedPipe                                  // p: named pipe (FIFO)
    - ModeSocket                                     // S: Unix domain socket
    - ModeSetuid                                     // u: setuid
    - ModeSetgid                                     // g: setgid
    - ModeCharDevice                                 // c: Unix character device, when ModeDevice is set
    - ModeSticky                                     // t: sticky
