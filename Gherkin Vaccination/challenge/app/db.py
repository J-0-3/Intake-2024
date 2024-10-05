import sqlite3 as sql
from contextlib import contextmanager

from post import Post, deserialize


class _Database:
    def __init__(self, path: str):
        self.path = path
        self.conn = sql.Connection(self.path)

    def setup(self):
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS User (Username TEXT UNIQUE, Password TEXT) STRICT"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS Post (PostID INTEGER PRIMARY KEY AUTOINCREMENT, Username TEXT, Post BLOB) STRICT"
        )
        self.conn.commit()

    def user_exists(self, username: str) -> bool:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM User WHERE Username=?", (username,))
        return len(cur.fetchall()) > 0

    def create_user(self, username: str, password: str):
        if self.user_exists(username):
            raise ValueError("User Exists")

        self.conn.execute(
            "INSERT INTO User (Username, Password) VALUES (?, ?)", (username, password)
        )
        self.conn.commit()

    def insert_post(self, username: str, post: Post):
        self.conn.execute(
            f"INSERT INTO Post (Username, Post) VALUES ('{username}', ?)",
            (post.serialize(),),
        )
        self.conn.commit()

    def get_posts(self, username: str) -> list[Post]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT Post FROM Post WHERE Username=? ORDER BY PostID ASC", (username,)
        )
        return [deserialize(p) for (p,) in cur.fetchall()]

    def get_users(self) -> list[str]:
        cur = self.conn.cursor()
        cur.execute("SELECT Username from User")
        return list(cur.fetchall())

    def login(self, username: str, password: str) -> bool:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT * FROM User WHERE Username=? AND Password=?", (username, password)
        )
        return len(cur.fetchall()) > 0

    def close(self):
        self.conn.close()


@contextmanager
def connection(path: str):
    db_conn = _Database(path)
    try:
        yield db_conn
    except Exception as e:
        raise e
    finally:
        db_conn.close()
