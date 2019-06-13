# go语言安全编程

## 整数安全

!!! danger "危险场景"
    - 数组索引
    - 对象长度
    - 循环计数器
    - 使用`make([]int, size)`时，如果size是负值或`>math.MaxInt32`会导致程序退出。

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

参见[上传下载](../../../../paas/docs/icsl/%E5%B8%B8%E7%94%A8%E6%94%BB%E5%87%BB%E5%91%BD%E4%BB%A4/#_12)

### 避免在共享目录操作文件

参见[上传下载](../../../../paas/docs/icsl/%E5%B8%B8%E7%94%A8%E6%94%BB%E5%87%BB%E5%91%BD%E4%BB%A4/#_12)

### 安全解压

参见[上传下载](../../../../paas/docs/icsl/%E5%B8%B8%E7%94%A8%E6%94%BB%E5%87%BB%E5%91%BD%E4%BB%A4/#_12)

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
