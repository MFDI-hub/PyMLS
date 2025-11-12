from __future__ import annotations


def secure_wipe(buf: bytearray) -> None:
    """
    Overwrite the provided bytearray with zeros in-place.
    """
    for i in range(len(buf)):
        buf[i] = 0


