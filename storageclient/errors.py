class RequestError(Exception):
    def __init__(self, message):
        self.message = message

class NotFoundError(RequestError):
    def __init__(self, message):
        self.message = message
