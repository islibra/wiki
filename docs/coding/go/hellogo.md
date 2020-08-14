# hellogo

- 官方网站：<https://golang.org/>
- 中文版：<https://go-zh.org/>

## I. 安装部署

1. 二进制安装包下载地址：<https://golang.org/dl/>
1. 提取安装包到指定目录：`tar -C /usr/local/ -zxf go1.12.5.linux-amd64.tar.gz`

### II. Linux 设置环境变量

```sh
vim /etc/profile
export GOROOT=/usr/local/go
export GOPATH=/path/to/workspace
export PATH=/usr/local/go/bin:$PATH
source /etc/profile
go version
```

### II. Windows 设置环境变量

1. 添加`GOPATH`，指向自定义workspace，在workspace下建立目录src，并创建main.go和package。使用`go get`也会将库默认下载到该目录下。
1. 使用GoLand导入工程 {==一般是包含src的目录==} 后，File - Settings - Go - GOPATH - Project GOPATH，添加工程目录 {==包含src的目录==}，在GoLand中才能找到依赖。


## 工作空间

- workspace
    - src
        - code.google.com/xxx/
            - xxx.go
            - xxx_test.go

        - github.com/xxx/
            - xxx.go

    - pkg  # 包对象
    - bin  # 可执行命令

## I. Hello World

在 workspace 下建立目录：`src/hello`，新建`hello.go`。

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


## I. 包

创建包路径如：`math/rand`，`rand`包内所有`.go`文件都以`package rand`开头。

导入时使用  
```go
import (
	"math/rand"
)
```

调用时使用`rand.xxx()`


## I. Go Modules

> go version >= 1.11

```sh
# 启用后, 默认不在 GOPATH 下查找依赖, 而在 $GOPATH/pkg/mod 中查找
export GO111MODULE=on/off/auto: 根据当前目录下是否存在 go.mod 判断是否启用
export GOPROXY=https://mirrors.aliyun.com/goproxy/
export GONOSUMDB=*
```

- 新建项目

    ```sh
    $ go mod init xxx
    $ go build
    ```

- 已有项目

    ```sh
    $ go mod init
    $ go get ./...
    ```


- 项目打包: `go mod vendor`, 将所有依赖下载到本地 vendor 目录
- 依赖下载: `go mod download`


- go.mod: 必须提交到 git 仓

    ```
    replace (
        golang.org/x/text v0.3.0 => github.com/golang/text v0.3.0
    )
    ```

- go.sum: 无需提交到 git 仓

!!! quote "[使用 Go Modules 管理依赖](https://www.jianshu.com/p/dca7c631587f)"


## I. 日志

```go
package main

import (
	"log"
	"os"
)

func main() {
	logfile, err := os.Create("main.log")
	if err != nil {
		log.Fatalln("fail to create main.log.")
	}

	logger := log.New(logfile, "", log.LstdFlags|log.Lshortfile)
	logger.Println("Hello log.")
	logger.Fatal("End.")
}
```


## I. 数组和切片

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

## I. 库函数

### II. 生成 X.509 证书

```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	rd "math/rand"
	"net"
	"os"
	"time"
)

func init() {
	rd.Seed(time.Now().Unix())
}

func main() {
	// Name代表一个X.509识别名。只包含识别名的公共属性，额外的属性被忽略。
	subject := pkix.Name{
		Country:            []string{"CN"},
		Province:           []string{"GuangDong"},
		Locality:           []string{"ShenZhen"},
		Organization:       []string{"XXX"},
		OrganizationalUnit: []string{"CLOUD"},
		CommonName:         "OSC",
	}

	nowTime := time.Now()
	notBeforeDate := time.Date(nowTime.Year(), nowTime.Month(), nowTime.Day(), 0, 0, 0,
		0, nowTime.Location())
	notAfterDate := notBeforeDate.AddDate(10, 0, 0)

	template := x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(rd.Int63()),
		Subject:      subject,
		NotBefore:    notBeforeDate,
		NotAfter:     notAfterDate,
		// KeyUsage 与 ExtKeyUsage 用来表明该证书是用来做服务器认证的
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		// 密钥扩展用途的序列
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    nil,
	}

	// 生成 RSA 密钥对
	caPrivateKey, _ := rsa.GenerateKey(rand.Reader, 4096)

	// 基于模板创建一个新的证书
	cerBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template,
		&caPrivateKey.PublicKey, caPrivateKey)
	fmt.Println(cerBytes)

	// 将证书导出为文件
	certFile, _ := os.Create("ca.cer")
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE",
		Bytes: cerBytes}); err != nil {
		return
	}
	if err := certFile.Close(); err != nil {
		return
	}

	// 将私钥导出为文件(私钥未加密)
	keyFile, _ := os.Create("ca.key")
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivateKey)}); err != nil {
		return
	}
	if err := keyFile.Close(); err != nil {
		return
	}
}
```

!!! quote "[实现TLS服务 创建数字证书](https://www.jianshu.com/p/ee196e77a664)"

#### III. 密钥用途

- KeyUsageDigitalSignature KeyUsage = 1 << iota: 数字签名
- KeyUsageContentCommitment
- KeyUsageKeyEncipherment: 用于 TLS 对对称密钥进行加密
- KeyUsageDataEncipherment
- KeyUsageKeyAgreement
- KeyUsageCertSign: 用于 CA 对签发的证书进行数字签名
- KeyUsageCRLSign
- KeyUsageEncipherOnly
- KeyUsageDecipherOnly

#### III. 扩展密钥用途

- ExtKeyUsageAny ExtKeyUsage = iota
- ExtKeyUsageServerAuth: 服务端认证
- ExtKeyUsageClientAuth: 客户端认证
- ExtKeyUsageCodeSigning
- ExtKeyUsageEmailProtection
- ExtKeyUsageIPSECEndSystem
- ExtKeyUsageIPSECTunnel
- ExtKeyUsageIPSECUser
- ExtKeyUsageTimeStamping
- ExtKeyUsageOCSPSigning
- ExtKeyUsageMicrosoftServerGatedCrypto
- ExtKeyUsageNetscapeServerGatedCrypto
- ExtKeyUsageMicrosoftCommercialCodeSigning
- ExtKeyUsageMicrosoftKernelCodeSigning

### II. 调用 keytool 命令行生成 truststore

```go
caCertFilename := "ca.cer"

truststoreFilename := "server.truststore.jks"

plainStorePass := "123456"

// keytool -import -file ca.cer -keystore client.truststore.jks -alias caroot
args := "-import -file " + caCertFilename + " -keystore " + truststoreFilename + " -alias caroot -noprompt -storepass " + plainStorePass
cmd := exec.Command("keytool", strings.Split(args, " ")...)
if err := cmd.Run(); err != nil {
    fmt.Println("generate truststore error", caCertFilename, err)
}
```

### II. 读写文件

#### III. os.Create(未验证)

```go
f, err := os.Create("/tmp/dat2")
check(err)
defer f.Close()
d2 := []byte{115, 111, 109, 101, 10}
n2, err := f.Write(d2)
check(err)
fmt.Printf("wrote %d bytes\n", n2)
n3, err := f.WriteString("writes\n")
fmt.Printf("wrote %d bytes\n", n3)
f.Sync()
```

#### III. io/ioutil

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

#### III. bufio

```go
// 读取文件
propPath := "/xxx.properties"
if _, err := os.Stat(propPath); os.IsNotExist(err) {
    logErr.Println("properties is not exist.")
    return
}
propFile, err := os.OpenFile(propPath, os.O_RDONLY, 0400)
if err != nil {
    logErr.Println("properties is not readable.")
    return
}
defer propFile.Close()

rd := bufio.NewReader(propFile)
for {
    lineBytes, _, err := rd.ReadLine()
    if err != nil || io.EOF == err {
        break
    }
    line := string(lineBytes)
    // 去掉空行和注释
    if len(line) != 0 && !strings.HasPrefix(line, "#") {
        logger.Println(line)
    }
}

// 写入文件
propFile, err := os.OpenFile(propPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
if err != nil {
    logErr.Println(propPath, "can not be create.")
    return
}
defer propFile.Close()

wt := bufio.NewWriter(propFile)
for k, v := range properties {
    _, err := wt.WriteString(k + "=" + v + "\n")
    if err != nil {
        return
    }
}
wt.Flush()
```


### II. 获取本机 IP

```go
package util

import (
    "errors"
    "fmt"
    "net"
)

// 获取本机 IP
func GetExternalIP() (net.IP, error) {
    // 获取所有网络接口
    ifaces, err := net.Interfaces()
    if err != nil {
        fmt.Println(err)
    }

    for _, iface := range ifaces {
        // interface down
        if iface.Flags&net.FlagUp == 0 {
            continue
        }
        // loopback interface
        if iface.Flags&net.FlagLoopback != 0 {
            continue
        }

        // 针对网络接口
        addrs, err := iface.Addrs()
        if err != nil {
            fmt.Println(err)
        }
        for _, addr := range addrs {
            ip := getIpFromAddr(addr)
            if ip == nil {
                continue
            }
            return ip, nil
        }
    }
    return nil, errors.New("interface nod found")
}

func getIpFromAddr(addr net.Addr) net.IP {
    var ip net.IP
    // 针对不同的网络地址类型获取 IP
    switch v := addr.(type) {
    case *net.IPNet:
        ip = v.IP
    case *net.IPAddr:
        ip = v.IP
    }
    if ip == nil || ip.IsLoopback() {
        return nil
    }
    // 获取 IPv4 地址
    ip = ip.To4()
    if ip == nil {
        return nil
    }
    return ip
}

ip, err := util.GetExternalIP()
if err != nil {
    fmt.Println(err)
}
fmt.Println(ip.String())
```


### encoding/json

```go tab="函数原型"
// 将字节数组反序列化为对象
func Unmarshal(data []byte, v interface{}) error
```

!!! quote
	示例代码参见：[序列化敏感数据造成信息泄露](../go%E8%AF%AD%E8%A8%80%E5%AE%89%E5%85%A8%E7%BC%96%E7%A8%8B/#_12)

### II. os

#### III. user

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

#### III. 获取操作系统环境变量

```go
import "os"

var JAVA_HOME = os.Getenv("JAVA_HOME")
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

```go tab="函数原型"
// Go通过独立的进程GC进行垃圾回收
// 可通过runtime包访问GC，如runtime.GC()运行一次垃圾回收
func GC()
// 内存统计
type MemStats struct {
	Alloc unit64  // 已分配的字节数
}
// 获取内存统计数据
func ReadMemStats(m *MemStats)

// obj被从内存移除前执行操作
// finalizer = func(obj *typeObj), 传入obj类型的指针参数
func SetFinalizer(obj interface{}, finalizer interface{})
```

```go tab="示例代码"
// 查看内存状态
var m runtime.MemStats
runtime.ReadMemStats(&m)
fmt.Printf("%d Kb\n", m.Alloc / 1024)  // 已分配的内存总量 111 Kb

// 在对象obj被从内存移除前执行操作
func foo()  {
    var x Vertex

    runtime.SetFinalizer(&x, func(d *Vertex) {
        fmt.Println("x %p final.", d)
    })
}

for i := 0; i < 5; i++ {
	foo()
	time.Sleep(time.Millisecond)
}
```

!!! question
	如何显式看到SetFinalizer执行？

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

```go tab="函数原型"
import "time"

type Time struct {}
// 获取当前时间
func Now() Time

type Duration int64

const (
	Nanosecond Duration = 1  // 纳秒
	Microsecond         = 1000 * Nanosecond  // 微秒
	Millisecond         = 1000 * Microsecond  // 毫秒
	Second              = 1000 * Millisecond  // 秒
	Minute              = 60 * Second  // 分
	Hour                = 60 * Minute  // 时
)

func Sleep(d Duration)
```

```go tab="示例代码"
// 获取当前时间 2019-07-03 19:43:19.8512965 +0800 AWST m=+0.078125001
fmt.Println(time.Now())

time.Sleep(time.Millisecond)
```

---
以下未整理
---


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
