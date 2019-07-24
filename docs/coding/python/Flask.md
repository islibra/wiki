# Flask

- 官方网站：<https://palletsprojects.com/p/flask/>
- github: <https://github.com/pallets/flask>
- 文档：<https://flask.palletsprojects.com/en/1.1.x/>

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

```python tab="示例代码"
from flask import Flask, escape, request

app = Flask(__name__)

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

# Windows:
C:\path\to\app>set FLASK_APP=hello.py


# 方式二：
$ export FLASK_APP=hello.py
$ python -m flask run
 * Running on http://127.0.0.1:5000/
```


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
