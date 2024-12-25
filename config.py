# تنظیمات اصلی پروکسی تلگرام
MASK = False  # فعال‌سازی ماسکینگ
MASK_HOST = "your.mask.host"  # هاست برای ماسکینگ
MASK_PORT = 3443  # پورت هاست ماسکینگ
TLS_DOMAIN = "www.example.com"  # دامنه برای گواهی TLS

# تنظیمات سرور
LISTEN_ADDR_IPV4 = "0.0.0.0"  # آدرس IPv4 برای گوش دادن
LISTEN_ADDR_IPV6 = "::"  # آدرس IPv6 برای گوش دادن
LISTEN_UNIX_SOCK = None  # سوکت یونیکس در صورت نیاز
PORT = 443  # پورت پیش‌فرض
METRICS_PORT = None  # پورت برای متریک‌ها (در صورت نیاز)

# تنظیمات پروکسی میانی
USE_MIDDLE_PROXY = True  # استفاده از پروکسی‌های میانی تلگرام
GET_TIME_PERIOD = 600  # بازه زمانی برای به‌روزرسانی زمان
PROXY_INFO_UPDATE_PERIOD = 1800  # بازه زمانی به‌روزرسانی اطلاعات پروکسی

# کاربران و اطلاعات امنیتی
USERS = {
    "user1": "aae8690a223629dba24367591546a24a",
    "user2": "cde7381b992e458abd19467214bcba29"
}

MY_DOMAIN = None  # دامنه اختیاری سرور

# حالت‌های پروکسی
MODES = {
    "tls_only": True,  # فعال‌سازی فقط TLS
    "simple_proxy": True,  # فعال‌سازی پروکسی ساده
    "masked": False  # فعال‌سازی پروکسی با ماسک
}

# سایر تنظیمات
PREFER_IPV6 = False  # اولویت استفاده از IPv6
SOCKS5_HOST = None  # در صورت استفاده از پروکسی SOCKS5
SOCKS5_PORT = None
GET_CERT_LEN_PERIOD = 300  # بازه زمانی بررسی گواهی‌ها
