# import os

from flask import Flask, render_template, request, flash, session, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

import hashlib

import datetime

app = Flask(__name__)
# app.config[
# "SQLALCHEMY_DATABASE_URI"
# ] = "postgresql+psycopg2://team2:poepoe@localhost/team2db"
# app.config["SQLALCHEMY_TRACK_MODIFICATION"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///team2db"
app.config[
    "SECRET_KEY"
] = "\xe1\xf0\xe1\x10M\xc5(\x93\xbb\xc5\xaf\xaf\xd5\xa7\xeb\x89\x80\xa0D\xccG\xed\x0b\x1e"


db = SQLAlchemy(app)
migrate = Migrate(app, db)


class Menu(db.Model):
    id = db.Column(db.Integer(), autoincrement=True, primary_key=True)
    name = db.Column(db.String(), nullable=False)
    price = db.Column(db.Integer(), nullable=False)
    kind = db.Column(db.String(), nullable=False)
    out_of = db.Column(db.Boolean(), nullable=False, default=True)
    cal = db.Column(db.String(), nullable=False)
    img = db.Column(db.String(), nullable=False)
    date = db.Column(db.Date())


class User(db.Model):
    id = db.Column(db.Integer(), autoincrement=True, primary_key=True)
    sid = db.Column(db.String(), nullable=False)
    password_hash = db.Column(db.String(), nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)

    def authenticate(sid, pw):
        pw_hash = hashlib.sha256(pw.encode()).hexdigest()
        password_hash = db.session.execute(
            db.select(User.password_hash).filter_by(sid=sid)
        ).scalar()

        if pw_hash == password_hash:
            return True
        else:
            return False


class Comment(db.Model):
    id = db.Column(db.Integer(), autoincrement=True, primary_key=True)
    tag = db.Column(db.Integer(), nullable=False)
    comment = db.Column(db.String())
    editor = db.Column(db.Integer(), nullable=False)
    update = db.Column(db.Date())


products = Menu.query.all()
a = list(
    filter(
        lambda p: p.kind == "a"
        and p.date is not None
        and p.date.month == datetime.date.today().month
        and p.date.day == datetime.date.today().day,
        products,
    )
)[0]
b = list(
    filter(
        lambda p: p.kind == "b"
        and p.date is not None
        and p.date.month == datetime.date.today().month
        and p.date.day == datetime.date.today().day,
        products,
    )
)[0]
menuinfo = list(
    filter(
        lambda p: p.kind == "p",
        products,
    )
)


def current_user():
    if "sid" in session:
        return User.query.filter_by(sid=session["sid"]).scalar()
    return None


def back():
    return request.args.get("next") or request.referrer or "/"


@app.route("/")
def main():
    return render_template("index.html", menus=menuinfo, a=a, b=b)


@app.route("/detail", methods=["GET", "POST"])
def detail():
    if "flag" in session or session["flag"]:
        pid = request.form.get("pid")
        stock = db.session.execute(db.select(Menu).filter_by(id=pid)).scalar()
        print(stock.out_of)
        stock.out_of = not stock.out_of
        print(stock.out_of)
        db.session.add(stock)
        db.session.commit()
        db.session.add(
            Comment(
                tag=pid,
                comment=request.form.get("comment"),
                editor=session["sid"],
                update=datetime.datetime.now(),
            )
        )
        db.session.commit()
        review = Comment.query.all()

        return render_template("detail.html", menus=menuinfo, a=a, b=b, review=review)
    else:
        flash("ログインしてください")
        return redirect(back())


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    sid = request.form.get("sid")
    pw = request.form.get("password")
    print(sid)
    error = None

    if not sid:
        error = "学籍番号を入力してください"
    elif not pw:
        error = "パスワードを入力してください"
    else:
        user = db.session.execute(db.select(User.sid).filter_by(sid=sid)).first()
        if not user or not User.authenticate(sid, pw):
            error = "学籍番号かパスワードが間違っています。"

    if error is None:
        session.clear()
        session["sid"] = sid
        session["flag"] = True
        flash("ログインしました。")
        admin = db.session.execute(db.select(User.admin).filter_by(sid=sid)).scalar()
        if admin:
            return redirect("admin")
        else:
            return redirect("detail")
    else:
        flash(error)

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("ログアウトしました。")
    return redirect("/")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    sid = request.form.get("sid")
    pw = request.form.get("password")
    error = None

    if not sid:
        error = "学籍番号を入力してください"
    elif not pw:
        error = "パスワードを入力してください"
    elif User.query.filter_by(sid=sid).first() is not None:
        error = "このアカウントはすでに登録されています。"
    else:
        hashed_password = hashlib.sha256(pw.encode()).hexdigest()
        db.session.add(User(sid=sid, password_hash=hashed_password))
        db.session.commit()
        flash("アカウントを作成しました。")
        return redirect("login")

    if error is None:
        flash("no error")
    else:
        flash(error)

    return render_template("signup.html")


@app.route("/admin", methods=["POST"])
def admin():
    return render_template("admin.html")


if __name__ == "__main__":
    # app.run(host="0.0.0.0", port=8082)
    app.run(host="0.0.0.0", port=8090, debug=True)


# DOCUMENT ----------------------------------------
# \dt;   show table;
# insert into menu () values();
