# Fixture for trentina-sync-classify-in-async.
import asyncio

from mcp_trentina_crunchtools.quarantine.classifier import classify, classify_async


async def scan_response(text):
    # ruleid: trentina-sync-classify-in-async
    result = classify(text, fail_on_truncate=True)
    return result


async def scan_offloaded(text):
    # ok: trentina-sync-classify-in-async
    return await asyncio.to_thread(classify, text)


async def scan_async(text):
    # ok: trentina-sync-classify-in-async
    return await classify_async(text)


def scan_sync(text):
    # ok: trentina-sync-classify-in-async
    return classify(text)


async def scan_with_helper(text):
    def helper():
        # ruleid: trentina-sync-classify-in-async
        return classify(text)

    return await asyncio.to_thread(helper)


async def scan_with_offloaded_helper(text):
    def helper():
        # ok: trentina-sync-classify-in-async
        return classify(text)  # nosemgrep: trentina-sync-classify-in-async -- only in to_thread

    return await asyncio.to_thread(helper)
