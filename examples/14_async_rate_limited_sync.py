#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Async onboarding that stays under the PCE rate limit.

When you drive the (synchronous) illumio client from asyncio with
``asyncio.to_thread`` and fan out with ``asyncio.gather`` / ``asyncio.TaskGroup``,
the blocking calls run on a thread pool **in parallel**. Nothing throttles that
by default, so a large sync easily exceeds the PCE's per-minute limit and you get
HTTP 429 errors (see the "Retries and rate limiting" guide).

This is the safe pattern:

  1. Prefetch labels ONCE (synchronously) before fanning out — no per-label GETs.
  2. Bound concurrency with an ``asyncio.Semaphore`` (the piece usually missing).
  3. Pace requests with a small token-bucket limiter (requests per minute).
  4. Wrap each blocking illumio call in ``asyncio.to_thread``.

Requires Python 3.9+ (``asyncio.to_thread``).

WRITES: creates unmanaged workloads (and any missing labels), then deletes them.
"""
import asyncio
import time

from illumio import Label, Workload

from _common import connect

# Stay under the PCE limit (e.g. 500/min) with headroom for retries and other calls.
MAX_REQUESTS_PER_MIN = 400
MAX_CONCURRENT = 3

INVENTORY = [
    {"name": "async-lb-{:02d}".format(i),
     "hostname": "async-lb-{:02d}.example.com".format(i),
     "public_ip": "10.40.0.{}".format(i),
     "labels": {"role": "R-LoadBalancer", "app": "A-Shop", "env": "E-Prod", "loc": "L-AWS"}}
    for i in range(1, 9)
]


class AsyncRateLimiter:
    """Allow at most ``rate`` operations per ``period`` seconds by spacing them
    at least ``period / rate`` apart.

    ``await limiter.acquire()`` returns immediately if enough time has passed
    since the previous acquisition, otherwise it sleeps just long enough to keep
    the average rate at or below the limit.
    """

    def __init__(self, rate, period=60.0):
        self._min_interval = period / float(rate)
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            wait = self._next - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = self._next
            self._next = now + self._min_interval


async def onboard(pce, inventory):
    # 1) Prefetch labels once, synchronously, before any fan-out.
    all_labels = pce.labels.get(params={"max_results": 100000})
    by_kv = {(label.key, label.value): label for label in all_labels}
    label_lock = asyncio.Lock()          # dedupe concurrent creation of the same label

    sem = asyncio.Semaphore(MAX_CONCURRENT)
    limiter = AsyncRateLimiter(MAX_REQUESTS_PER_MIN)

    async def call(fn, *args, **kwargs):
        """Run a blocking illumio call rate-limited, concurrency-bounded, off-loop."""
        await limiter.acquire()
        async with sem:
            return await asyncio.to_thread(fn, *args, **kwargs)

    async def get_or_create_label(key, value):
        if (key, value) in by_kv:
            return by_kv[(key, value)]
        async with label_lock:
            if (key, value) not in by_kv:            # re-check inside the lock
                by_kv[(key, value)] = await call(pce.labels.create, Label(key=key, value=value))
            return by_kv[(key, value)]

    async def create_workload(item):
        labels = [await get_or_create_label(k, v) for k, v in item["labels"].items()]
        return await call(pce.workloads.create, Workload(
            name=item["name"], hostname=item["hostname"],
            public_ip=item["public_ip"], labels=labels))

    # 2) Fan out. gather runs these concurrently; the semaphore caps how many run
    #    at once and the limiter caps the request rate. On Python 3.11+ you could
    #    use ``asyncio.TaskGroup`` instead of gather for structured concurrency.
    return await asyncio.gather(*[create_workload(item) for item in inventory],
                                return_exceptions=True)


def main():
    pce = connect()
    results = asyncio.run(onboard(pce, INVENTORY))

    created = [r for r in results if not isinstance(r, Exception) and getattr(r, "href", None)]
    failed = [r for r in results if isinstance(r, Exception)]
    print("Created {} workloads; {} failed.".format(len(created), len(failed)))
    for r in created:
        print("  ", r.href)
    for e in failed:
        print("  ERROR:", type(e).__name__, e)

    if created:
        pce.workloads.bulk_delete([r.href for r in created])
        print("Cleaned up example workloads.")


if __name__ == "__main__":
    main()
