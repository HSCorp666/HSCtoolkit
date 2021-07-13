import os


def out_of_order(f):
    def wrapper(*args, **kwargs):
        raise OutOfOrder(f"The function {f.__name__} is out of order.")

    return wrapper


def lightweight_generator(f):
    def wrapper(*args, **kwargs):
        lines = 0

        for data in f(*args, **kwargs):
            lines += 1

            yield data

            if lines > 20:
                os.system('clear')
                lines = 0

        return ''  # So the wrapper is not a NoneType.

    return wrapper


class OutOfOrder(Exception):
    def __init__(self, msg="Function out of order."):
        super().__init__(msg)


class TooManyThreadsError(Exception):
    def __init__(self, msg="To many threads"):
        super().__init__(msg)
