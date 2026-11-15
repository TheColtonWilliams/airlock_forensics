# Runbook: deleted files and media metadata on a Windows external drive (NTFS)

Task 4.12. This is the manual path, one command per step, using the tools of tasks 4.1 to 4.8
in order. `forensic-analyze` (`docs/workflows/guided-analysis.md`) runs most of it for you; use
this page when you want to run, check, or explain a single step. Tool list: `docs/tools.md`.

Rules for every step:

* **Never write to the evidence drive.** Connect it through a hardware write blocker if you have
  one. AIRLOCK also sets a *software read-only policy* on every attached drive; that policy is a
  second layer, not a substitute for a write blocker.
* **Never mount the evidence.** Every tool below reads the drive or the image directly.
* **Everything you make goes to the output drive**, here `OUT=/srv/airlock/output/cases/C-001/EX-01`.
  Make that folder first: `mkdir -p "$OUT"`.
* **File names from the evidence are data.** Name recovered files by their MFT entry number, not
  by the name on the drive, and never paste an evidence file name into a shell command.
* **Do not open recovered pictures or videos.** Screen them first
  (`docs/workflows/media-screening.md`). The metadata steps below read files without showing them.

The examples use `/dev/sdX` for the evidence drive, `EX-01.E01` for its image, and 2048 for the
start sector of the NTFS partition. Replace them with what step 3 and step 5 show.

## 1. Start a session

```
sudo forensic-session-start
```

It asks for your authority, checks the clock against a trusted clock, records whether a hardware
write blocker is in use, and logs the state of the machine. See `docs/workflows/session.md`.

## 2. Attach the drive and confirm it is read-only

```
lsblk -o NAME,SIZE,MODEL,SERIAL,RO,TYPE
sudo blockdev --getro /dev/sdX
```

`RO` must be `1` and `blockdev --getro` must print `1`. If not, unplug the drive and stop.

## 3. Hash the drive before anything else

```
sudo evidence-hash /dev/sdX
```

SHA-256 and MD5 of the whole drive, read in one pass, written to the session log.

## 4. Make an image (copy first, recommended)

E01 with case details and a second hash (4.1, `ewf-tools`):

```
sudo ewfacquire -u -t "$OUT/EX-01" -C C-001 -E EX-01 -D "Windows external drive" \
  -e "Examiner name" -N "Received sealed" -c best -f encase6 -d sha256 /dev/sdX
sudo ewfverify "$OUT/EX-01.E01"
```

For a drive with read errors, use GNU ddrescue (4.1, `gddrescue`): the first pass skips bad
areas, the second retries them, and the map file lets you stop and resume.

```
sudo ddrescue -d -n /dev/sdX "$OUT/EX-01.raw" "$OUT/EX-01.map"
sudo ddrescue -d -r3 /dev/sdX "$OUT/EX-01.raw" "$OUT/EX-01.map"
```

dc3dd writes a raw image and its hash log in one go: `sudo dc3dd if=/dev/sdX
hof="$OUT/EX-01.raw" hash=sha256 log="$OUT/EX-01.dc3dd.log"`. Guymager (`sudo guymager`) does
the same from a window.

Some tools below need a raw image. Expose the E01 as one, read-only, without copying it:

```
mkdir -p /tmp/ewf && sudo ewfmount "$OUT/EX-01.E01" /tmp/ewf   # gives /tmp/ewf/ewf1
RAW=/tmp/ewf/ewf1
```

## 5. Partitions and file system (4.2, The Sleuth Kit, libfsntfs, ntfs-3g)

```
mmls "$OUT/EX-01.E01"
fsstat -o 2048 "$OUT/EX-01.E01"
fsntfsinfo -o $((2048 * 512)) "$RAW"
```

`mmls` lists the partitions and their start sectors; `fsstat` shows the NTFS volume (serial,
cluster size, MFT location); `fsntfsinfo` gives the same from a second library.

## 6. Deleted files (4.2)

List every deleted name with its full path and MFT entry:

```
fls -r -d -p -o 2048 "$OUT/EX-01.E01" > "$OUT/deleted.txt"
```

A line such as `r/r * 84-128-2:	Users/test-user/Documents/report.txt` means MFT entry 84,
deleted (`*`). Look at its times and clusters, then copy it out by entry number:

```
istat -o 2048 "$OUT/EX-01.E01" 84
mkdir -p "$OUT/recovered"
icat -o 2048 "$OUT/EX-01.E01" 84 > "$OUT/recovered/entry-84.bin"
```

Or copy every deleted file that still has its data: `tsk_recover -o 2048 "$OUT/EX-01.E01"
"$OUT/recovered"`. A recovered file can hold leftover data from other files (NIST IR 8354).

File system timeline (MACB times of every entry, in UTC):

```
fls -r -m C: -o 2048 "$OUT/EX-01.E01" > "$OUT/body.txt"
mactime -b "$OUT/body.txt" -d -y -z UTC > "$OUT/fs-timeline.csv"
```

## 7. The MFT through two parsers (4.3 Dissect, 4.4 EZ Tools)

Two independent parsers on the same artifact are a cross-check: a deleted file that one lists and
the other does not needs a closer look.

```
icat -o 2048 "$OUT/EX-01.E01" 0 > "$OUT/MFT"
MFTECmd -f "$OUT/MFT" --csv "$OUT/mftecmd" --csvf mft.csv
target-query -f mft -j "$OUT/EX-01.E01" > "$OUT/mft-dissect.jsonl"
```

In `mft.csv`, `InUse` is `False` for deleted entries; in the Dissect output, `inuse` is `false`.
Dissect opens the E01 and finds the partition itself.

## 8. The USN journal (4.2, 4.3, 4.4, 4.6)

Windows logs file creation, renames and deletions in `$Extend/$UsnJrnl:$J`.

```
usnjls -o 2048 "$OUT/EX-01.E01" > "$OUT/usn-tsk.txt"
target-query -f usnjrnl -j "$OUT/EX-01.E01" > "$OUT/usn-dissect.jsonl"
```

For MFTECmd, copy the `$J` stream out first. `ifind` gives the entry; `istat` lists its
attributes; the `$DATA` attribute named `$J` has a type-id such as `128-4`:

```
ifind -n '/$Extend/$UsnJrnl' -o 2048 "$OUT/EX-01.E01"          # for example 77
istat -o 2048 "$OUT/EX-01.E01" 77 | grep -F '$J'
icat -o 2048 "$OUT/EX-01.E01" 77-128-4 > "$OUT/J"
MFTECmd -f "$OUT/J" --csv "$OUT/mftecmd" --csvf usn.csv
```

Old USN records often survive in unallocated space. Copy the unallocated clusters out and carve
them (4.6):

```
blkls -o 2048 "$OUT/EX-01.E01" > "$OUT/unallocated.bin"
usncarve -f "$OUT/unallocated.bin" -o "$OUT/usn-carved.bin"
MFTECmd -f "$OUT/usn-carved.bin" --csv "$OUT/mftecmd" --csvf usn-carved.csv
```

## 9. Recycle bin (4.2, 4.3, 4.4)

Each deleted-to-bin file leaves a `$I` file (original path, size, deletion time) and a `$R` file
(the content) under `$Recycle.Bin/<account SID>/`.

```
fls -r -p -o 2048 "$OUT/EX-01.E01" | grep -F '$Recycle.Bin' > "$OUT/recycle-bin.txt"
target-query -f recyclebin -j "$OUT/EX-01.E01" > "$OUT/recycle-dissect.jsonl"
```

For RBCmd, copy each `$I` file out by its entry number, then parse the folder:

```
mkdir -p "$OUT/recycle"
icat -o 2048 "$OUT/EX-01.E01" 112 > "$OUT/recycle/entry-112.I"
RBCmd -d "$OUT/recycle" --csv "$OUT/rbcmd"
```

Reports name the account SID, never a person.

## 10. Volume Shadow Copies (4.1)

```
vshadowinfo -o $((2048 * 512)) "$RAW"
```

If it lists stores, older versions of deleted files may be inside; `forensic-analyze` reports
them, and `vshadowmount` exposes each store read-only for the tools above.

## 11. Shortcuts, jump lists, prefetch, event logs (4.4)

Copy the folders out by entry number with `icat` (or all allocated files with
`tsk_recover -a -o 2048 "$OUT/EX-01.E01" "$OUT/files"`), then:

```
LECmd -d "$OUT/files/Users" --csv "$OUT/lecmd"
JLECmd -d "$OUT/files/Users" --csv "$OUT/jlecmd"
PECmd -d "$OUT/files/Windows/Prefetch" --csv "$OUT/pecmd"
EvtxECmd -d "$OUT/files/Windows/System32/winevt/Logs" --csv "$OUT/evtxecmd"
SBECmd -d "$OUT/files/Users" --csv "$OUT/sbecmd"
bstrings -f "$OUT/unallocated.bin" -o "$OUT/strings.txt"
```

An external data drive usually has none of these; they matter when the drive held a Windows
installation or a user profile backup.

## 12. Registry hives (4.8, 4.4)

```
regfinfo "$OUT/files/Windows/System32/config/SYSTEM"
rip.pl -r "$OUT/files/Windows/System32/config/SYSTEM" -a > "$OUT/regripper-system.txt"
hivexml "$OUT/files/Windows/System32/config/SOFTWARE" > "$OUT/software.xml"
RECmd -d "$OUT/files/Windows/System32/config" --bn /opt/eztools/RECmd/BatchExamples/RECmd_Batch_MC.reb --csv "$OUT/recmd"
AmcacheParser -f "$OUT/files/Windows/AppCompat/Programs/Amcache.hve" --csv "$OUT/amcache"
AppCompatCacheParser -f "$OUT/files/Windows/System32/config/SYSTEM" --csv "$OUT/shimcache"
```

The RECmd batch file path depends on the RECmd zip; `find /opt/eztools/RECmd -name '*.reb'`
lists them. Open hives read-only: `hivexsh` without `-w`.

## 13. Media metadata (4.7)

Read metadata without opening or previewing the files:

```
exiftool -r -csv -n "$OUT/recovered" > "$OUT/exif.csv"
exiv2 -pa "$OUT/recovered/entry-84.bin"
mediainfo --Output=JSON "$OUT/recovered/entry-90.bin" > "$OUT/entry-90.mediainfo.json"
ffprobe -v error -show_format -show_streams -of json "$OUT/recovered/entry-90.bin"
```

Thumbnail caches keep small copies of pictures, including pictures that were deleted:

```
vinetto -o "$OUT/thumbs-db" "$OUT/files/Pictures/Thumbs.db"
thumbcache-extract --output-dir "$OUT/thumbcache" "$OUT/files/Users/u/AppData/Local/Microsoft/Windows/Explorer/thumbcache_256.db"
```

The extracted thumbnails are images: screen them before anyone views them.

## 14. Super-timeline (4.5, Plaso)

```
log2timeline --unattended --partitions all --vss_stores none \
  --storage-file "$OUT/EX-01.plaso" "$OUT/EX-01.E01"
psort -o dynamic -w "$OUT/timeline.csv" "$OUT/EX-01.plaso"
```

`psort` writes UTC times. The `.plaso` file can be loaded into Timesketch on another computer.

## 15. Carving (4.6)

Files with no file system record left can still be in unallocated space:

```
bulk_extractor -o "$OUT/bulk" "$OUT/EX-01.E01"
photorec /log /d "$OUT/photorec/" /cmd "$RAW" partition_none,options,paranoid,search
foremost -t jpg,png,pdf -i "$RAW" -o "$OUT/foremost"
```

For scalpel, copy `/etc/scalpel/scalpel.conf`, uncomment the file types you need, and run
`scalpel -c my-scalpel.conf -o "$OUT/scalpel" "$RAW"`. Carved pictures and videos go through
screening like any other recovered media.

## 16. Finish

```
sudo umount /tmp/ewf
sudo evidence-hash /dev/sdX
```

The second hash must equal the first. Then unplug the drive. Record any difference in your notes;
`forensic-analyze` treats a changed hash as an integrity warning (exit code 3).
