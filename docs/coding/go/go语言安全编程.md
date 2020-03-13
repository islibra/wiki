# go语言安全编程

## 整数安全

!!! danger "危险场景"
    - 数组索引
    - 对象长度，如使用`make([]int, size)`时，如果size是负值或`> math.MaxInt32`会导致程序退出。

        !!! example
            ```go tab="错误的做法" hl_lines="1 3"
            size := -1
            fmt.Println("size:", size)
            ary := make([]int, size)
            fmt.Println("i made a slice with -1")
            for _, i := range ary {
                fmt.Println(i)
            }

            ////// output
            size:  -1
            panic: runtime error: makeslice: len out of range

            goroutine 1 [running]:
            main.main()
            	F:/go/src/hello/hello.go:129 +0xca
            ```

            ```go tab="推荐的做法" hl_lines="5"
            // make size为负值造成程序崩溃
            size := -1
            fmt.Println("size:", size)

            if size < 0 || size > math.MaxInt32 {
                fmt.Println("error")
            } else {
                ary := make([]int, size)
                fmt.Println("i made a slice with -1")
                for _, i := range ary {
                    fmt.Println(i)
                }
            }
            ```

    - 循环计数器

### 无符号反转

```go tab="错误的做法" hl_lines="10"
import (
	"fmt"
	"math"
)

func TestUnsigned() {
	var a uint64 = math.MaxUint64  // 18446744073709551615
	fmt.Println(a)
	var b uint64 = 1
	var c uint64 = a + b
	fmt.Println(c)  // 0
}
```

```go tab="推荐的做法" hl_lines="4"
var c uint64

// 在操作前校验
if (math.MaxUint64 - a) < b {
	fmt.Println("error: c is too big.")
} else {
	c = a + b
	fmt.Println(c)
}
```

### 有符号溢出

```go tab="错误的做法" hl_lines="6"
// 有符号整数溢出
func Testsigned() {
	var a int32 = math.MaxInt32  //2147483647
	fmt.Println(a)
	var b int32 = 1
	var c int32 = a + b
	fmt.Println(c)  // -2147483648
}
```

```go tab="推荐的做法" hl_lines="2"
// 在操作前校验
if ((a > 0 && b > (math.MaxInt32 - a)) || (a < 0 && b < (math.MinInt32 - a))) {
	fmt.Println("error: c is too big.")
} else {
	var c int32 = a + b
	fmt.Println(c)
}
```

### 整型转换截断

```go tab="错误的做法" hl_lines="6"
// 整型转换截断
func Testtransfer() {
	var a int32 = math.MaxInt32  // 2147483647
	fmt.Println(a)

	var b int16 = int16(a)  // -1
	fmt.Println(b)
}
```

```go tab="推荐的做法" hl_lines="7"
// 整型转换截断
func Testtransfer() {
	var a int32 = math.MaxInt16
	fmt.Println(a)

	var b int16
	if (a > math.MaxInt16 || a < math.MinInt16) {
		fmt.Println("error")
	} else {
		b = int16(a)
		fmt.Println(b)
	}
}
```

### 整型转换符号错误

```go tab="错误的做法" hl_lines="11 12 20 21"
// 整型转换符号错误
func Testsymbol() {
	var a int32
	var b uint32
	// 有符号 --> 无符号
	// 正值不变 a= 123  b= 123
	a = 123
	b = uint32(a)
	fmt.Println("a=", a, " b=", b)
	// 负值错误 a= -123  b= 4294967173
	a = -123
	b = uint32(a)
	fmt.Println("a=", a, " b=", b)
	// 无符号 --> 有符号
	// 未使用符号位不变 b= 2147483647  a= 2147483647
	b = 1<<31 - 1
	a = int32(b)
	fmt.Println("b=", b, " a=", a)
	// 使用符号位错误 b= 2147483648  a= -2147483648
	b = 1<<31
	a = int32(b)
	fmt.Println("b=", b, " a=", a)
}
```

```go tab="推荐的做法" hl_lines="12 26"
// 整型转换符号错误
func Testsymbol() {
	var a int32
	var b uint32
	// 有符号 --> 无符号
	// 正值不变 a= 123  b= 123
	a = 123
	b = uint32(a)
	fmt.Println("a=", a, " b=", b)
	// 负值错误 a= -123  b= 4294967173
	a = -123
	if (a < 0) {
		fmt.Println("error")
	} else {
		b = uint32(a)
		fmt.Println("a=", a, " b=", b)
	}

	// 无符号 --> 有符号
	// 未使用符号位不变 b= 2147483647  a= 2147483647
	b = 1<<31 - 1
	a = int32(b)
	fmt.Println("b=", b, " a=", a)
	// 使用符号位错误 b= 2147483648  a= -2147483648
	b = 1<<31
	if (b >= (1<<31)) {
		fmt.Println("error")
	} else {
		a = int32(b)
		fmt.Println("b=", b, " a=", a)
	}
}
```


## SQL注入

```go tab="错误的做法" hl_lines="10"
import (
    "database/sql"
    //...
)

//db *sql.DB
db, err := sql.Open("mysql", "root:root@tcp(localhost:3306)/demo?charset=utf8")
//...

var sqlStr = "SELECT xxx FROM xxx WHERE x = '" + x + "'"
rows, err := db.Query(sqlStr)
//...

var result string
for rows.Next() {
    var xxx string
    rows.Scan(&xxx)
    result += xxx + "\n"
}
```  

```go tab="正确的做法"
var sqlStr = "SELECT xxx FROM xxx WHERE x = ?"
rows, err := db.Query(sqlStr, x)
```


## OS命令注入

```go tab="错误的做法" hl_lines="4"
import "os/exec"

//param: rm -f /opt/pwm/limit.txt && touch /opt/pwm/attack.txt
cmd := exec.Command("/bin/sh", "-c", param)
err := cmd.Run()
```  

```go tab="推荐的做法一"
import "os"

err := os.Remove(param)  //使用API
```

```go tab="推荐的做法二" hl_lines="11"
import (
    "os"
    "os/exec"
)

_, err := os.Stat(param)  //返回文件描述信息
if err != nil || os.IsNotExist(err) {
    //...
}

cmd := exec.Command("rm", "-f", param)  //功能单一
delErr := cmd.Run()
```


## IO安全

### 临时文件及时删除

```go tab="错误示例"
//只关闭了文件，未及时删除
import "io/ioutil"

f, err := ioutil.TempFile("/tmp/secfile", "prefix")
if err != nil //...
defer f.Close()
f.Write([]byte("This is an wrong example."))
```

```go tab="推荐做法"
import (
    "io/ioutil"
    "os"
)

func closeAndRemove(f *os.File) {
    f.Close()
    os.Remove(f.Name())  //调用os库函数删除临时文件
}

f, err := ioutil.TempFile("/tmp/secfile", "prefix")
if err != nil //...
defer closeAndRemove(f)
f.Write([]byte("This is an right example."))
```

### 创建文件时指定访问权限

!!! warning "注意"
    go语言缺省创建文件权限为666，任何人可读写，但不可执行。

```go tab="错误的做法"
import "os"

f, err := os.Create("/opt/unlimit.txt")  //缺省权限666
```

```go tab="推荐的做法一"
import "os"

f, err := os.Create("/opt/limit.txt")  //缺省权限666
//...
f.Chmod(0600)  //调用chmod更改文件权限
```

```go tab="推荐的做法二"
import "os"

//os.OpenFile指定选项和模式打开文件，O_CREATE表示文件不存在时自动创建
f, err := os.OpenFile("/opt/limit.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
```

!!! example "选项"
    - O_RDONLY int = syscall.O_RDONLY // open the file read-only.
    - O_WRONLY int = syscall.O_WRONLY // open the file write-only.
    - O_RDWR   int = syscall.O_RDWR   // open the file read-write.
    - O_APPEND int = syscall.O_APPEND // append data to the file when writing.
    - O_CREATE int = syscall.O_CREAT  // create a new file if none exists.
    - O_EXCL   int = syscall.O_EXCL   // used with O_CREATE, file must not exist
    - O_SYNC   int = syscall.O_SYNC   // open for synchronous I/O.
    - O_TRUNC  int = syscall.O_TRUNC  // if possible, truncate file when opened.

!!! info "例外情况"
    如果文件创建到安全的目录中，该目录受限访问，则允许以缺省权限创建文件。

### 文件路径验证前标准化

!!! example "go语言校验方法绕过"
    ```go
    //测试使用strings.HasSuffix库方法判断文件类型
    fmt.Println(strings.HasSuffix("hello.zip", ".zip"))  //true
    fmt.Println(strings.HasSuffix("hello.zip.sh", ".zip"))  //false
    fmt.Println(strings.HasSuffix("hello.sh;x.zip", ".zip"))  //true绕过
    fmt.Println(strings.HasSuffix("hello.sh%00x.zip", ".zip"))  //true绕过
    ```

!!! example "go语言代码示例"
    ```go tab="拼接目录路径"
    //获取当前目录路径
    pwd, _ := os.Getwd()
    fmt.Println(pwd)
    //拼接目录路径
    userDir := filepath.Join(pwd, "tmp/upload", "userId")
    fmt.Println(userDir)
    ```

    ```go tab="标准化文件路径"
    import (
        "path/filepath"
    )

    //返回绝对路径，删除目录跨越，当前目录/home/xxx/go/src
    fmt.Println(filepath.Abs("/home/xxx/go/src/../../main.go"))  ///home/xxx/main.go
    fmt.Println(filepath.Abs("../../main.go"))  ///home/xxx/main.go

    //测试使用filepath.Clean库方法标准化文件路径
    fmt.Println(filepath.Clean("../../hello.txt"))  //..\..\hello.txt
    fmt.Println(filepath.Clean("/tmp/upload/dir/../../hello.txt"))  //\tmp\hello.txt
    ```

    ```go tab="验证是否在安全目录下"
    import (
        "regexp"
    )

    //验证是否在安全目录下（文件及其所有上层目录属主为当前用户或root，且其他用户无写权限）
    pattern := `^/home/xxx`  //正则表达式
    reg := regexp.MustCompile(pattern)
    fmt.Println(reg.MatchString("/home/xxx/test1.sh"))  //true
    fmt.Println(reg.MatchString("/tmp/test2.sh"))  //false
    ```

### 避免在共享目录操作文件

!!! example "推荐的做法"
    1. 文件路径标准化
    1. 验证是否在安全目录下
    1. 判断是否为符号链接
    ```go
    import (
        "fmt"
        "os"
    )

    //获取文件的FileInfo
    finfo, err := os.Lstat("/home/islibra/go/src/linktry")
    if err != nil {
        fmt.Println("err")
        return
    }
    if finfo.Mode()&os.ModeSymlink != 0 {  //判断是否为符号链接
        fmt.Println("soft link!")
        return
    }
    //操作文件
    f, err := os.Open("/home/islibra/go/src/realtry")
    if err != nil {
        fmt.Println("err")
        return
    }
    defer f.Close()
    ```

### 安全解压

!!! example "go语言代码示例"
    ```go tab="错误的做法"
    import (
        "archive/zip"
    )

    //打开压缩包
    rc, err := zip.OpenReader(zipfile)
    //...
    //遍历压缩包内的目录和文件
    for _, file := range rc.File {
        irc, err := file.Open()
        //...
        //拼装解压路径
        var targetpath = filepath.Join(destpath, file.Name)

        //如果是目录则创建，如果是文件则复制
        if file.FileInfo().IsDir() {
            os.MkdirAll(targetpath, file.Mode())  //错误1：直接将拼装路径传给MkdirAll()
        } else {
            f, err := os.OpenFile(targetpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
            //...
            wt, err := io.Copy(f, irc)  //错误2：直接拷贝流中数据
            //...
        }
    }
    ```

    ```go tab="推荐的做法"
    import (
        "archive/zip"
    )

    const TOO_MANY_FILE int = 1024
    const BUFSIZE int = 1024
    const TOOBIG int = 0x6400000  //100M

    //打开压缩包
    rc, err := zip.OpenReader(zipfile)
    //...
    //校验1：文件数量超过1024
    if len(rc.File) > TOO_MANY_FILE {
        return
    }
    //遍历压缩包内的目录和文件
    for _, file := range rc.File {
        irc, err := file.Open()
        //...
        //拼装解压路径
        var targetpath = filepath.Join(destpath, file.Name)

        //如果是目录则创建，如果是文件则复制
        if file.FileInfo().IsDir() {
            os.MkdirAll(targetpath, file.Mode())  //校验2：这里应该校验目录名是否为..
        } else {
            f, err := os.OpenFile(targetpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
            //...
            wt, err := bufferCopy(f, irc)  //校验3：通过缓冲区拷贝文件
            //...
            //校验4：这里还要校验总的文件大小，防止将大文件分割为小文件
        }
    }

    func bufferCopy(dst io.Writer, src io.Reader) (written int64, err error) {
        buf := make([]byte, BUFSIZE)
        for {
            nr, er := src.Read(buf)
            if nr > 0 {
                //校验3：判断文件大小是否超限
                if written > TOOBIG {
                    err = error.New("too big!")
                    break
                }
                nw, ew := dst.Write(buf[0:nr])
                if nw > 0 {
                    written += int64(nw)  //记录已写入数据量
                }
                if ew != nil {
                    err = ew
                    break
                }
                if nr != nil {
                    err = io.ErrShortWrite
                    break
                }
            }
            if er == io.EOF {
                break
            }
            if er != nil {
                err = er
                break
            }
        }
        return written, err
    }
    ```

## 序列化和反序列化

### 序列化敏感数据造成信息泄露

```go tab="错误的做法"
package main

import (
	"fmt"
	"encoding/json"
)

type creditCard struct {
	// 注意首字母大写，public的才能被序列化
	ID int `json:"card_id"`
	Name string `json:"username"`
	Bank string `json:"bankname"`
	Password string `json:"password"`  // 敏感信息
}

func Serialize() []byte {
	var mycredit creditCard
	mycredit.ID = 123456
	mycredit.Name = "aaron"
	mycredit.Bank = "zhaoshang"
	mycredit.Password = "1qaz@WSX"

	serializeStr, err := json.Marshal(mycredit)
	if err != nil {
		fmt.Println("serialize error")
		return nil
	}
	// 敏感信息被序列化
	// {"card_id":123456,"username":"aaron","bankname":"zhaoshang","password":"1qaz@WSX"}
	fmt.Println(string(serializeStr))
	return serializeStr
}

func Deserialize(serializeStr []byte) {
	var decredit creditCard
	err := json.Unmarshal(serializeStr, &decredit)
	if err != nil {
		fmt.Println("deserialize error")
		return
	}
	fmt.Println(decredit.ID)
	fmt.Println(decredit.Name)
	fmt.Println(decredit.Bank)
	fmt.Println(decredit.Password)
}

// 在main中调用
se := Serialize()
Deserialize(se)
```

```go tab="推荐的做法"
Password string `json:"-"`  // 阻止敏感信息被序列化
```

!!! info "提示"
    - 示例仅对json, xml有效
    - 其他方法：首字母小写
    - 如果敏感数据已加密，可以序列化

### 反序列化恶意数据

### 敏感数据序列化后1.传输或2.在硬盘上持久保存需先签名后加密

```go tab="错误的做法"
import (
	"bytes"
	"encoding/gob"
)

// 直接序列化
cache := new(bytes.Buffer)
encoder := gob.NewEncoder(cache)
err := encoder.Encode(mycredit)
```

## ReDoS

搜索`regexp`
