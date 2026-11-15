"""Offline provisioning of an AIRLOCK drive from its ASSETS partition.

``forensic-provision`` (tasks 2B.4 to 2B.7, 2B.12) and ``forensic-import`` (task 4A.7) share
this package: ``system`` holds the refusal checks and the hardware and tool summary, ``runner``
the checkpointed steps, ``cli`` the two commands. Nothing here uses a network.
"""
