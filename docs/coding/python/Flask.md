# Flask

- 官方网站：<https://palletsprojects.com/p/flask/>
- github: <https://github.com/pallets/flask>
- 文档：<https://flask.palletsprojects.com/en/1.1.x/>


## 虚拟环境变量

> 在项目中使用虚拟环境变量管理依赖可使安装的package相互独立，减少对其他项目或系统的影响。

1. 创建项目和venv

    ```bash tab="Linux"
    $ mkdir flaskproj
    $ cd flaskproj
    $ python3 -m venv venv
    ```

    ```bash tab="Windows"
    $ py -3 -m venv venv
    ```

1. 激活venv

    ```bash tab="Linux"
    $ . venv/bin/activate
    ```

    ```bash tab="Windows"
    > venv\Scripts\activate
    ```

???+ note
    已在Windows上验证通过.


## 安装

### 方式一

```
pip --proxy=http://l0025xxxx:pass%40word@proxy.xxx.com:8080 install Flask
```

### 方式二

1. 下载[Flask-1.1.1.tar.gz](https://pypi.org/project/Flask/#files)
1. 下载[Werkzeug-0.15.5.tar.gz](https://pypi.org/simple/werkzeug/)
1. 下载[Jinja2-2.10.1.tar.gz](https://pypi.org/simple/jinja2/)
1. 下载[MarkupSafe-1.1.1.tar.gz](https://pypi.org/simple/markupsafe/)
1. 下载[itsdangerous-1.1.0.tar.gz](https://pypi.org/simple/itsdangerous/)
1. 下载[Click-7.0.tar.gz](https://pypi.org/simple/click/)

```bash
pip3 install ./Werkzeug-0.15.5.tar.gz
pip3 install ./MarkupSafe-1.1.1.tar.gz
pip3 install ./Jinja2-2.10.1.tar.gz
pip3 install ./itsdangerous-1.1.0.tar.gz
pip3 install ./Click-7.0.tar.gz
pip3 install ./Flask-1.1.1.tar.gz
```

???+ tip
    如果已将软件包安装到`C:\Users\l0025xxxx\AppData\Local\Programs\Python\Python37-32\Lib\site-packages`, 需要拷贝到`F:\python\flaskproj\venv\Lib\site-packages`目录下.


## Start

```python tab="示例代码"
from flask import Flask, escape, request

# 创建Flask应用实例
app = Flask(__name__)

# 定义URL接口及路由
@app.route('/')
def hello():
    name = request.args.get("name", "World")
    return f'Hello, {escape(name)}!'
```

```bash tab="运行程序"
# 方式一：

# Linux:
$ env FLASK_APP=hello.py
$ flask run
 * Serving Flask app "hello"
 * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)

# Windows cmd:
C:\path\to\app>set FLASK_APP=hello.py

# Windows PowerShell:
PS C:\path\to\app> $env:FLASK_APP = "hello.py"


# 方式二：
$ export FLASK_APP=hello.py
$ python -m flask run
 * Running on http://127.0.0.1:5000/
```

???+ tip
    1. 在Windows系统环境变量中设置`FLASK_APP`为`flaskdemo.py`
    1. 开始 - 运行 - cmd, 执行`flask run`


## SECRET_KEY

```python tab="生成session" hl_lines="6 12 13"
from flask import Flask, session

# 创建Flask应用实例
app = Flask(__name__)
# 设置SECRET_KEY
app.config['SECRET_KEY'] = 'CHANGEME'

# 定义URL接口及路由
@app.route('/')
def index():
    if 'logged_in' not in session:
        # 这一步会将session加密后放到Cookies中
        # 如: eyJsb2dnZWRfaW4iOmZhbHNlfQ.XTke1Q.YZ1AUTasQbmerPSIos5593wzw5g
        session['logged_in'] = False

    if session['logged_in']:
        return '<h1>You are logged in!</h1>'
    else:
        return '<h1>Access Denied.</h1>', 403


if __name__ == '__main__':
    app.run()
```

```python tab="解密session"
from itsdangerous import *

session = 'eyJsb2dnZWRfaW4iOmZhbHNlfQ.XTke1Q.YZ1AUTasQbmerPSIos5593wzw5g'
data, timestamp, secret = session.split('.')

# session data: b'{"logged_in":false}'
print(base64_decode(data))
# timestamp: 1564024533
print(int.from_bytes(base64_decode(timestamp), byteorder='big'))
# 根据session data, timestamp, SECRET_KEY生成sha1 hash: b'a\x9d@Q6\xacA\xb9\x9e\xac\xf4\x88\xa2\xcey\xf7|3\xc3\x98'
print(base64_decode(secret))
```

> cmd执行`python flaskdemo.py`.

???+ danger "安全风险"
    获取SECRET_KEY伪造session.

    - SECRET_KEY固定: 字典暴力破解: `$ pip install flask-unsign[wordlist]`

???+ check "消减措施"
    1. 随机化密钥

        ```python
        import uuid

        print(uuid.uuid4())
        ```
    1. 使用[Flask-Session](https://pythonhosted.org/Flask-Session/)

        ```bash
        $ pip install Flask-Session
        ```

        ```python hl_lines="8 9 11"
        import os
        from flask import Flask, session
        from flask_session import Session

        # 创建Flask应用实例
        app = Flask(__name__)
        # 设置SECRET_KEY
        app.config['SECRET_KEY'] = os.urandom(64)
        app.config['SESSION_TYPE'] = 'filesystem'

        Session(app)

        # 定义URL接口及路由
        @app.route('/')
        def index():
            if 'logged_in' not in session:
                # 这一步会将session加密后放到Cookies中
                # 如: eyJsb2dnZWRfaW4iOmZhbHNlfQ.XTke1Q.YZ1AUTasQbmerPSIos5593wzw5g
                session['logged_in'] = False

            if session['logged_in']:
                return '<h1>You are logged in!</h1>'
            else:
                return '<h1>Access Denied.</h1>', 403


        if __name__ == '__main__':
            app.run()
        ```


???+ quote "参考链接"
    [浅谈Flask cookie与密钥的安全性](https://www.anquanke.com/post/id/170466)


## Flask_SQLAlchemy

```python tab="示例代码"
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
db = SQLAlchemy(app)


# 定义数据模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username


# 创建表
from yourapplication import db
db.create_all()


# 增加记录
from yourapplication import User
admin = User(username='admin', email='admin@example.com')
guest = User(username='guest', email='guest@example.com')

db.session.add(admin)
db.session.add(guest)
db.session.commit()


# 查询记录
User.query.all()
[<User u'admin'>, <User u'guest'>]
User.query.filter_by(username='admin').first()
<User u'admin'>
```


???+ quote "参考链接"
    <https://flask-sqlalchemy.palletsprojects.com/en/2.x/>


???+ danger "安全风险"
    数据表对象继承自`SQLAlchemy`, 导入了`flask.current_app`[^app], 其`config`中存放了`SECRET_KEY`, 如果存在格式化字符串漏洞, 可以泄露该敏感信息.

    payload:

    - `{user_m.__class__.__base__.__class__.__init__.__globals__[current_app].config}`
    - `{user_m.__class__.__mro__[1].__class__.__mro__[0].__init__.__globals__[SQLAlchemy].__init__.__globals__[current_app].config}`

[^app]: <https://flask.palletsprojects.com/en/1.1.x/api/?highlight=current_app#flask.current_app>


???+ quote "参考链接"
    [Python Web之flask session&格式化字符串漏洞](https://xz.aliyun.com/t/3569)
