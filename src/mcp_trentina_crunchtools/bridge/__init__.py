"""The Matrix bridge process (#162, spec 015): the upstream half.

Runs in its own container, holds the upstream Matrix login, device and crypto
store, and nothing else. It hands decrypted events to the gateway and sends
what the gateway hands back. Needs the ``bridge`` extra.
"""
