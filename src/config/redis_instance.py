from threading import Lock
import redis


class SingletonMeta(type):
    _instances = {}

    _lock = Lock()

    def __call__(self, *args, **kwds):
        with self._lock:
            instance = super().__call__(*args, **kwds)
            self._instances[self] = instance
        return self._instances[self]


class RedisSingleton(metaclass=SingletonMeta):
    def __init__(self):
        self.conn = redis.Redis(host="localhost", port=6379, decode_responses=True)

    def getInstance(self) -> redis.Redis:
        return self.conn
