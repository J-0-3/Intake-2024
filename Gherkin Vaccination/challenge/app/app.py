import datetime

from flask import Flask, redirect, render_template, request, session

import db
from post import Post
import os

DB_PATH = "db.sqlite"
with db.connection(DB_PATH) as conn:
    conn.setup()

app = Flask(__name__)

app.secret_key = os.urandom(24).hex()


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    with db.connection(DB_PATH) as conn:
        success = conn.login(username, password)
    if success:
        session["username"] = username
        return redirect("/")
    return render_template("login.html", error="Login Failed")


@app.route("/", methods=["GET"])
def index():
    if "username" in session:
        return redirect("/posts")
    return redirect("/login")


@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")


@app.route("/post", methods=["POST"])
def create_post():
    if "username" not in session:
        return redirect("/login")
    title = request.form["title"]
    caption = request.form["caption"]
    posted = datetime.datetime.now()
    post = Post(title, posted, caption)
    with db.connection(DB_PATH) as conn:
        conn.insert_post(session["username"], post)
    return redirect("/posts")


@app.route("/posts", methods=["GET"])
def posts_page():
    if "username" not in session:
        return redirect("/login")
    with db.connection(DB_PATH) as conn:
        posts = conn.get_posts(session["username"])
    return render_template("posts.html", posts=posts)


@app.route("/logout", methods=["GET"])
def logout():
    if "username" in session:
        session.clear()
    return redirect("/login")


@app.route("/register", methods=["GET"])
def register_page():
    if "username" in session:
        return redirect("/")
    return render_template("register.html")


@app.route("/register", methods=["POST"])
def register():
    if "username" in session:
        return redirect("/")
    username = request.form["username"]
    password = request.form["password"]
    confirm = request.form["confirm"]
    if password != confirm:
        return render_template("register.html", error="Passwords do not match")
    if len(username) < 3:
        return render_template(
            "register.html", error="Username must be at least 3 letters"
        )
    if len(password) < 8:
        return render_template(
            "register.html", error="Password must be at least 8 letters"
        )

    with db.connection(DB_PATH) as conn:
        if conn.user_exists(username):
            return render_template("register.html", error="User already exists")
        conn.create_user(username, password)
    return redirect("/login")
