import asyncio

from wildburrow.core.types import StreamReader, StreamWriter

CHUNK = 65536


async def _pipe(src: StreamReader, dst: StreamWriter) -> None:
    while chunk := await src.read(CHUNK):
        dst.write(chunk)
        await dst.drain()
    if dst.can_write_eof():
        dst.write_eof()
        await dst.drain()
    else:
        dst.close()


async def relay(a: tuple[StreamReader, StreamWriter], b: tuple[StreamReader, StreamWriter]) -> None:
    try:
        async with asyncio.TaskGroup() as group:
            group.create_task(_pipe(a[0], b[1]))
            group.create_task(_pipe(b[0], a[1]))
    except* OSError:
        pass
    finally:
        a[1].close()
        b[1].close()
