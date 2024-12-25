import asyncio

# مدیریت درخواست‌های کلاینت
async def handle_client_wrapper(reader, writer):
    try:
        # کدی برای مدیریت ارتباط با کلاینت
        data = await reader.read(1024)
        writer.write(data)
        await writer.drain()
    except Exception as e:
        print("Error handling client:", e)
    finally:
        writer.close()
        await writer.wait_closed()

# مدیریت متریک‌ها (در صورت استفاده)
async def handle_metrics(reader, writer):
    try:
        writer.write(b"Metrics data here\n")
        await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()
