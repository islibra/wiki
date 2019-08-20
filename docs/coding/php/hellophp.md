# hellophp

官方网址: <https://www.php.net/>  
中文文档: <https://www.php.net/manual/zh/>

## Start

> macOS中已安装php

1. 下载安装[XAMPP](https://www.apachefriends.org/zh_cn/index.html)
1. General - Start
1. Volumes - Mount

> phpMyAdmin: 管理MySQL.

```php
<html>
    <head>
        <title>PHP</title>
    </head>
    <body>
    <?php
    echo '<p>Hello World</p>';
    ?>
    </body>
</html>
```

## 变量

- $_POST: 接收post请求参数值

    ```php
    <?php echo $_POST["fname"]; ?>
    ```

- $_REQUEST: 接收get, post, cookie中的参数值

    ```php
    <?php echo $_REQUEST["fname"]; ?>
    ```

## 运算符

### 错误控制运算符

`@`: 放在表达式之前, 产生的任何错误信息都会被忽略.

### 比较

- `===`: 全等, 同时比较值和类型
- `==`: 等于, 如果比较一个数字和一个字符串, 或者比较涉及到数字内容的字符串, 先将字符串转换成数值再比较

```php
var_dump(0 == "a"); // 0 == 0 -> true
var_dump("1" == "01"); // 1 == 1 -> true
var_dump("10" == "1e1"); // 10 == 10 -> true
var_dump(100 == "1e2"); // 100 == 100 -> true
```

## 流程控制

> include/require包含并运行指定文件

```php
// vars.php
<?php

$color = 'green';
$fruit = 'apple';

?>

// test.php
<?php

echo "A $color $fruit";  // A

include 'vars.php';

echo "A $color $fruit";  // A green apple

?>
```

## 库函数

### eval

```php
// eval, 把字符串作为php代码执行
<?php
$string = 'cup';
$name = 'coffee';
$str = 'This is a $string with my $name in it.';
// This is a $string with my $name in it.
echo $str. "\n";
eval("\$str = \"$str\";");
// This is a cup with my coffee in it.
echo $str. "\n";
?>
```

### system

```php
// system, 执行外部程序, 返回命令输出的最后一行
<?php
echo '<pre>';

// 输出 shell 命令 "ls" 的返回结果
// 并且将输出的最后一行内容返回到 $last_line。
// 将命令的返回值保存到 $retval。
$last_line = system('ls', $retval);

// 打印更多信息
echo '
</pre>
<hr />Last line of the output: ' . $last_line . '
<hr />Return value: ' . $retval;
?>
```

### show_source/highlight_file

```php
// 语法高亮一个文件
// 高亮显示当前文件的源码
show_source(__FILE__);
```

### strpos

```php
// 查找字符串第一次出现的位置, 区分大小写, 如果未找到返回FALSE
strpos(string, find, start)
```

### addslashes

```php
<?php
// 在每个单引号, 双引号, 反斜杠, NULL前添加反斜杠
$str = addslashes('Shanghai is the "biggest" city in China.');
// Shanghai is the \"biggest\" city in China.
echo($str);
?>
```

### ord

```php
<?php
// 返回首个字符的ASCII
// 83
echo ord("S")."<br>";
// 83
echo ord("Shanghai")."<br>";
?>
```
