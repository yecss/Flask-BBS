import os
import sys
import click
from datetime import datetime
from flask import Flask, render_template, request, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy  # 数据库
from werkzeug.security import generate_password_hash, check_password_hash  # 账户检查
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user  # 账户登录
app = Flask(__name__)

"""数据库配置 start"""

# 判断当前设备是windows还是linux
WIN = sys.platform.startswith('win')
if WIN:  # 如果是 Windows 系统，使用三个斜线
    prefix = 'sqlite:///'
else:  # 否则使用四个斜线
    prefix = 'sqlite:////'
# 告诉SQLAlchemy 数据库连接地址
app.config['SQLALCHEMY_DATABASE_URI'] = prefix + os.path.join(app.root_path, 'data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # 关闭对模型修改的监控
app.config["SECRET_KEY"] = 'TPmi4aLWRbyVq8zu9678789WYW1'
db = SQLAlchemy(app)  # 初始化扩展，传入程序实例 app


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20))
    username = db.Column(db.String(20))  # 用户名
    password_hash = db.Column(db.String(128))  # 密码散列值

    def set_password(self, password):  # 用来设置密码的方法，接受密码作为参数
        self.password_hash = generate_password_hash(password)  # 将生成的密码保持到对应字段

    def validate_password(self, password):  # 用于验证密码的方法，接受密码作为参数
        return check_password_hash(self.password_hash, password)  # 返回布尔值


class Message(db.Model):  # 表名将会是 movie
    id = db.Column(db.Integer, primary_key=True)  # 主键
    name = db.Column(db.String(20))  # 名字
    word = db.Column(db.Text)  # 留言的话
    qq = db.Column(db.String(20))  # qq号
    time = db.Column(db.DateTime, default=datetime.now)

"""数据库配置 end"""

"""注册自定义命令 start"""
# flask initdb --drop
@app.cli.command()
@click.option('--drop', is_flag=True, help='Create after drop.')
def initdb(drop):
    if drop:
        db.drop_all()
    db.create_all()
    click.echo('Initialized database.')


# flask forge
@app.cli.command()
def forge():
    """Generate fake data."""
    db.create_all()

    messages = [
        {'name': 'Yecss', 'qq': '2078136028', 'word': '天王盖地虎,宝塔镇河妖.'},
        {'name': 'Lindsay', 'qq': '263007544', 'word': '幸福都雷同，悲伤千万种.'},
        {'name': 'chris', 'qq': '1203102902', 'word': '我要做个下载软件，名字叫掩耳。因为迅雷不及掩耳.'},
        {'name': 'Delia', 'qq': '2639973907', 'word': '将薪比薪想一下，算了，不想活了.'},
        {'name': 'Fiona', 'qq': '2832507171', 'word': '我有一筐的愿望，却等不到一颗流星.'},
        {'name': 'frederica', 'qq': '11234221', 'word': '再多的努力和妥协，都无法缝补和填满空白.'},
        {'name': 'Amaris', 'qq': '2679992887', 'word': '时光总在刻伤，我真的不会如何疗伤，所幸的是我坚强.'},

    ]
    for m in messages:
        message = Message(name=m['name'], qq=m['qq'], word=m['word'])
        db.session.add(message)

    db.session.commit()
    click.echo('Done.')


@app.cli.command()
@click.option('--username', prompt=True, help='The username used to login.')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='The password used to login.')
def admin(username, password):
    """Create user."""
    db.create_all()

    user = User.query.first()
    if user is not None:
        click.echo('Updating user...')
        user.username = username
        user.set_password(password)  # 设置密码
    else:
        click.echo('Creating user...')
        user = User(username=username, name='Admin')
        user.set_password(password)  # 设置密码
        db.session.add(user)

    db.session.commit()  # 提交数据库会话
    click.echo('Done.')
"""注册自定义命令 end"""


"""视图配置 start"""
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # 获取表单数据
        name = request.form.get('name') # 传入表单对应输入字段的 name 值
        qq = request.form.get('qq')
        word = request.form.get('bbs')
        # 验证数据
        if not name or not qq or len(name) > 20 or len(qq) > 20:
            flash('Invalid input.')  # 显示错误提示
            return redirect(url_for('index'))  # 重定向回主页
        # 保存表单数据到数据库
        message = Message(name=name, qq=qq, word=word)  # 创建记录
        db.session.add(message)  # 添加到数据库会话
        db.session.commit()  # 提交数据库会话
        flash('Item created.')  # 显示成功创建的提示
        return redirect(url_for('index'))  # 重定向回主页

    mes = Message.query.all()
    return render_template('index.html', mes=mes)


@app.route('/edit/<int:message_id>', methods=['GET', 'POST'])
@login_required  # 登录保护,未登录账户的人访问不了edit
def edit(message_id):
    message = Message.query.get_or_404(message_id)
    if request.method == 'POST':
        name = request.form['name']
        qq = request.form['qq']
        bbs = request.form['bbs']
        if not name or not qq or len(name) > 20 or len(qq) > 20:
            flash('修改失败')
            return redirect(url_for('edit',message_id = message_id))
        message.name = name
        message.qq = qq
        message.word = bbs
        db.session.commit()
        flash('更新成功')
        return redirect(url_for('index'))
    return render_template('edit.html', card=message)


@app.route('/delete/<int:message_id>', methods=['POST'])
@login_required
def delete(message_id):
    message = Message.query.get_or_404(message_id)
    db.session.delete(message)  # 删除对应的记录
    db.session.commit()  # 提交数据库会话
    flash('留言删除成功.')
    return redirect(url_for('index'))  # 重定向回主页


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Invalid input.')
            return redirect(url_for('login'))

        user = User.query.first()
        # 验证用户名和密码是否一致
        if username == user.username and user.validate_password(password):
            login_user(user)  # 登入用户
            flash('Login success.')
            return redirect(url_for('index'))  # 重定向到主页

        flash('Invalid username or password.')  # 如果验证失败，显示错误消息
        return redirect(url_for('login'))  # 重定向回登录页面

    return render_template('login.html')


@app.route('/logout')
@login_required  # 用于视图保护
def logout():
    logout_user()  # 登出用户
    flash('Goodbye.')
    return redirect(url_for('index'))  # 重定向回首页
"""账户登录 start"""
login_manager = LoginManager(app)  # 实例化扩展类
login_manager.login_view = 'login' # 设为我们程序的登录视图端点（函数名）

@login_manager.user_loader
def load_user(user_id): # 创建用户加载回调函数，接受用户 ID 作为参数
    user = User.query.get(int(user_id)) # 用 ID 作为 User 模型的主键查询对应的用户
    return user  # 返回用户对象

if __name__ == '__main__':
    app.run()
