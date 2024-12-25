import random

# انتخاب عدد تصادفی در بازه مشخص
def myrandom(low, high):
    return random.randint(low, high)

# چاپ خطا در کنسول
def print_err(*args):
    print("ERROR:", *args, flush=True)
