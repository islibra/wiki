# go语言安全编程

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



使用make([]int, size)时，如果size是负值或>math.MaxInt32会导致程序退出




如果未调用filepath
.
Abs
(
path
)，则文件路径中可能存在软连接，目录跨越


// 打开压缩包

    rc
,
err
:=
zip
.
OpenReader
(
zipfile
)
// 解压文件的数量超过1024限制

   
if
len
(
rc
.
File
)

>
TOO_MANY_FILE

destpath
=
filepath
.
Clean
(
destpath
)

// 将目的路径标准化

// 拼装指定的解压路径

       
var
targetpath
=
filepath
.
Join
(
destpath
,
file
.
Name
)

wt
,
err
:=
copyBuffer
(
f
,
irc
)

// 检查解压文件消耗情况
