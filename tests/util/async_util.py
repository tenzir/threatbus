import asyncio


def run_await(routine):
    """Run and await async function. Return its result."""
    return asyncio.get_event_loop().run_until_complete(routine)
