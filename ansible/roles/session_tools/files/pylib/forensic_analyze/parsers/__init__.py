"""Pure-Python (standard library only) parsers for NTFS and Windows artifacts.

Each parser reads bytes that came from evidence and returns plain data. They never execute or
interpret evidence text; names and paths are returned as ``str`` for the findings writer to
escape. Every parser raises its own ``*Error`` (a ``ValueError``) on malformed input.

* ``filetime``  FILETIME (100 ns ticks since 1601) to ISO 8601 UTC.
* ``bodyfile``  The Sleuth Kit bodyfile lines (``fls -m``).
* ``mft``       ``$MFT`` records: ``$STANDARD_INFORMATION``, ``$FILE_NAME``, ``$DATA`` streams.
* ``usn``       ``$UsnJrnl:$J`` records (USN_RECORD_V2 and V3), and carving them from raw bytes.
* ``recycle``   Recycle bin ``$I`` files (version 1 and 2).
* ``lnk``       Shell link (``.lnk``) header, LinkInfo, and string data.
* ``sds``       ``$Secure:$SDS`` security descriptors (owner SID per security ID).
* ``ezcsv``     CSV output of Eric Zimmerman's tools (MFTECmd, RBCmd, LECmd, JLECmd).
* ``dissect_json``  ``target-query -j`` record streams from Dissect.
"""
