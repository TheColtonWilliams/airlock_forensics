# Validation guide

How to check, on your own hardware, that an AIRLOCK drive does what it says. The automated tests
(`docs/controls.md`) run in an emulator. They cannot prove behaviour on a real PC, a real USB bridge,
or a real radio. The checks here can. Record every result; a check you skip is a check that did not
pass.

The read-only layer is a **software read-only policy**, not a write blocker. These checks show the
policy works on your machine. They do not replace a hardware write blocker on real evidence.

## Bare-metal check

Task 3.10. Run this on every new AIRLOCK release and on every PC model you will use it on. It takes
about 15 minutes. You need:

* the AIRLOCK drive, freshly written from the release image;
* a **scratch** USB drive you do not care about (it must hold no evidence and nothing you need);
  format it with one partition (exFAT or ext4) and put a small text file on it;
* a second computer to compute a hash of the scratch drive before and after (optional but best).

Never use a real evidence drive for this check.

### Before you start

1. On the second computer, hash the whole scratch drive and write the result down. On Linux:
   `sudo sha256sum /dev/sdX` (replace `sdX` with the scratch drive). On Windows, use any tool that
   hashes a whole physical disk.
2. Note the PC make and model, the AIRLOCK release, and the date in the results table below.

### Steps

Boot the PC from the AIRLOCK drive with the scratch drive **unplugged**. Open a terminal. Then:

1. **Session log.** Run `forensic-session-start` and confirm it finishes without an error.
2. **Plug in the scratch drive.** Wait 10 seconds. No window, notification, or file manager may
   open.
3. **Not mounted.** Run `findmnt -rn -o SOURCE,TARGET`. No line may name the scratch drive. Find the
   scratch drive's name with `lsblk -o NAME,SIZE,MODEL,TRAN` (it is the one with the size you expect
   and `usb` transport; call it `sdX`).
4. **Read-only flag.** Run `sudo blockdev --getro /dev/sdX` and `sudo blockdev --getro /dev/sdX1`.
   Both must print `1`. Run `sudo airlock-setro --check`; it must end with `writable=0` and list the
   scratch drive as `ro`.
5. **Write refused.** Run
   `sudo dd if=/dev/sdX of=/tmp/block bs=4096 count=1 && sudo dd if=/tmp/block of=/dev/sdX bs=4096 count=1 oflag=direct conv=notrunc`.
   The second `dd` must fail with "Operation not permitted" (it writes back the bytes already there,
   so even a wrong pass changes nothing).
6. **Decision logged.** Run `grep ro_policy /var/log/forensic-session/current.log | tail -n 4`.
   The scratch drive must appear with `"decision":"readonly"`.
7. **No swap.** Run `swapon --show`. It must print nothing.
8. **Radios off.** Run `rfkill list`. Every entry must say `Soft blocked: yes`, or the list is empty.
   Run `ip -br link`: no name starting with `wl` or `ww`, and nothing `UP` except `lo`. The desktop's
   quick settings must not offer Wi-Fi or Bluetooth.
9. **No network.** Plug in an Ethernet cable to a working network if the PC has a port. Wait 10
   seconds. Run `ip -br addr`: no address except on `lo`. Run `ping -c 1 -W 2 9.9.9.9`: it must fail.
10. **Unplug the scratch drive**, shut down AIRLOCK, and hash the scratch drive again on the second
    computer. The hash must match step 1 of "Before you start".

### Results

Copy this table into your validation record, one row per PC model.

| Date | AIRLOCK release | PC make and model | Boot mode (UEFI/BIOS, Secure Boot) | 2 no window | 3 not mounted | 4 ro flag | 5 write refused | 6 logged | 7 no swap | 8 radios off | 9 no network | 10 hash unchanged | Tester |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| | | | | | | | | | | | | | |

If any step fails, stop using that release on that PC model and open an issue with the step number,
the command output, and `sudo airlock-setro --check` output. Do not attach evidence data.

### What a pass does not show

* The flag is honoured by Linux filesystem drivers and the block layer. A hostile USB bridge or drive
  firmware can still change its own contents. Use a hardware write blocker with a published NIST CFTT
  or DHS test report for real evidence.
* Root can clear the flag with `blockdev --setrw`. `evidence-unlock-output` does that for one named
  output drive and logs it.
* A radio driver that does not depend on `cfg80211` or `bluetooth` would not be stopped by the module
  block. `rfkill` and the masked network services are the second and third layers; the firewall is
  the fourth.
