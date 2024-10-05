import datetime
import pickle


class Post:
    title: str
    posted: datetime.datetime
    caption: str

    def __init__(self, title: str, posted: datetime.datetime, caption: str):
        self.title = title
        self.posted = posted
        self.caption = caption

    def serialize(self) -> bytes:
        return pickle.dumps(self)


def deserialize(data: bytes) -> Post:
    # I've heard pickle is unsafe, but this data is never user-supplied, so it should be fine :)
    return pickle.loads(data)
