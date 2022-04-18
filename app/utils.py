import logging
import sys

log_format = "[%(asctime)s.%(msecs)03d] %(levelname)-8s %(name)-12s %(lineno)d %(funcName)s - %(message)s"
log_date_format = "%Y-%m-%d:%H:%M:%S"

# show all messages below in order of seriousness
log_level = logging.DEBUG  # shows all
# log_level = logging.INFO  # shows info and below
# log_level = logging.WARNING
# log_level = logging.ERROR
# log_level = logging.CRITICAL

logging.basicConfig(
    # Define logging level
    level=log_level,
    # Define the date format
    datefmt=log_date_format,
    # Declare the object we created to format the log messages
    format=log_format,
    # Force this log handler to take over the others that may have been declared in other modules
    # see: https://github.com/python/cpython/blob/3.8/Lib/logging/__init__.py#L1912
    force=True,
    # Declare handlers
    handlers=[
        # logging.FileHandler(config.logfile, encoding='UTF-8'),
        logging.StreamHandler(sys.stdout),
    ],
)


# https://stackoverflow.com/questions/739654/how-to-make-function-decorators-and-chain-them-together?rq=1
def benchmark(func):
    """
    A decorator that prints the time a function takes
    to execute.
    """
    import time

    def wrapper(*args, **kwargs):
        t = time.perf_counter()
        res = func(*args, **kwargs)
        print("====== {0} {1}".format(func.__name__, time.perf_counter() - t))
        # logging.debug("====== {0} {1}".format(func.__name__, time.perf_counter()-t))
        return res

    return wrapper


def logging(func):
    """
    A decorator that logs the activity of the script.
    (it actually just prints it, but it could be logging!)
    """

    def wrapper(*args, **kwargs):
        res = func(*args, **kwargs)
        print("====== {0} {1} {2}".format(func.__name__, args, kwargs))
        # logging.debug("====== {0} {1} {2}".format(func.__name__, args, kwargs))
        return res

    return wrapper


def counter(func):
    """
    A decorator that counts and prints the number of times a function has been executed
    """

    def wrapper(*args, **kwargs):
        wrapper.count = wrapper.count + 1
        res = func(*args, **kwargs)
        print("====== {0} has been used: {1}x".format(func.__name__, wrapper.count))
        # logging.debug("====== {0} has been used: {1}x".format(func.__name__, wrapper.count))
        return res

    wrapper.count = 0
    return wrapper
