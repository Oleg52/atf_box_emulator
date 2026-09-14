# AdvanceBox / ATF Turbo Flasher — Protocol & Activation Reverse Engineering

Capture from box with valid rsa file is in dump_info.txt.

There are also .rsa files from other boxes in this folder.

## 1. Basic device identity

- The box reports a serial number (`box_sn`, 12 bytes) and firmware version over the FTDI
  link using a simple challenge/response exchange (opcodes `0x55`/`0x5E`/`0x56`).
- The FTDI chip's own USB descriptor serial (visible via `FT_ListDevices`) matches the
  **first 4 bytes** of `box_sn` — this is just a manufacturing/tracking convenience; it has
  no cryptographic significance (see §4).
- Raw values read back from the box sometimes require a byte-pair-swap or full-byte-reversal
  transform before they read as sensible ASCII text — this transform shows up repeatedly
  throughout the protocol.

## 2. The `.rsa` activation file format

Each file is exactly 128 bytes: `AES-128-CBC(key, IV=0, plaintext)`.

- **Key:** `"gortakXIRGHE9GHE"` (static, embedded in the client, identical across every box)
- **IV:** all-zero
- **Plaintext layout (128 bytes):**
  - bytes 0–7: `magic` (8 bytes, per-box secret — see §4)
  - bytes 8–19: `box_sn` (12 bytes)
  - bytes 20–107: `[magic + box_sn]` tiled repeatedly (pure padding — proven empirically to
    be ignored entirely by both the client and the box; see §4)
  - bytes 108–127: `SHA1(bytes 0–107)` — a self-consistency check the client verifies before
    ever talking to the box

### Filename

```
filename = SHA1(volume_sn(4B) + box_sn(12B) + suffix(2B)).hex() + ".rsa"
```

- `volume_sn` — the Windows volume serial number of the PC's system drive (as a 4-byte value,
  same byte order as the `vol` command displays it, e.g. `2093-C8EB` → `20 93 C8 EB`).
- `suffix` — the first two characters of the product name as shown by the app, byte-swapped
  and encoded as their hex character values (e.g. `"AdvanceBox..."` → `"Ad"` → swapped `"dA"` →
  `64 41`; `"ATF..."` → `"AT"` → swapped `"TA"` → `54 41`).

This is a pure **client-side file lookup key** — it has no bearing on whether the box itself
accepts the file. Confirmed in practice: copying a genuine `.rsa` file to a different PC and
spoofing that PC's volume serial number to match the filename formula makes the box work
normally on the new machine.

## 3. The box's own validation (FTDI challenge/response)

After the client decrypts and self-checks a `.rsa` file, it performs a live check against the
physical box over FTDI:

1. Client sends `0x5E`. Box (firmware ≥ v11 only — see §5) responds with an 8-byte random
   challenge.
2. Client sends a 129-byte packet (`0x56` header + mostly random padding + 8 meaningful
   "landmark" bytes at fixed offsets).
3. Box responds with a single status byte: `0x00`/similar on match, `0x5A` on mismatch.

The 8 landmark bytes are computed as:

```
landmark[k] = magic[k] XOR box_sn[k+4] XOR challenge[j]      for k = 0..7
```

(`box_sn[k+4]` uses only the **last 8 bytes** of the 12-byte `box_sn` — the first 4 bytes,
which mirror the FTDI chip's own serial, are never used in this check at all.)

This formula was verified exhaustively:
- Confirmed against 12+ real and synthetic `magic`/`box_sn` combinations, including blind
  predictions made *before* testing them against real hardware (all matched exactly).
- Proven to be a real arithmetic identity, not a "file present/valid" flag — e.g. setting
  `magic == box_sn_tail` (both fully non-zero) produces an all-zero landmark, exactly as the
  formula predicts, ruling out simpler "sentinel" theories.
- Proven that only the first 20 bytes of the 128-byte plaintext are ever read by anything —
  the repeated-tile padding bytes are cosmetic only (verified by replacing them with random
  garbage and confirming the box still accepted the file).

**What this does *not* give you:** a way to derive `magic` for a box you don't already have a
genuine file for. The box's internal copy of `magic` is presumably burned into hardware
(likely the FPGA's own persistent storage) at manufacture time, and is an independent secret
per box — it was not possible to derive it from `box_sn`, `volume_sn`, firmware/version
strings, or any combination thereof, via any standard hash/XOR/CRC construction, tested
across every real sample available.

## 4. Where does `magic` actually come from?

The client's `.rsa`-activation HTTP request (to the vendor's — now dead — activation server)
was fully decoded. It bundles two logically separate things into one call:

- A software-license/HWID check (motherboard/BIOS fragments, disk serial, app version)
- A device-activation lookup, keyed by `box_sn`

No standalone `magic` field appears anywhere in that request — consistent with `magic`
being looked up server-side from a `box_sn → magic` database (or handed back after some
signing operation), rather than computed from anything the client sends.

## 5. Firmware v10/v9 vs v11: the licensing check is not present at all in older firmware

Confirmed via live packet capture on real hardware:

- **Firmware v9/v10:** the box does not implement the `0x5E`/`0x56` opcodes at all — the
  FTDI reads simply return empty. The client tolerates this silently and proceeds directly
  to normal operation. **No `.rsa` file is required or checked in any way.**
- **Firmware v11:** implements the full challenge/response above, and a mismatch is a **hard
  gate** — the client halts all further functionality on rejection. This is the actual root
  cause of "box stopped working after losing the activation file."

This strongly suggests the licensing/activation requirement was introduced specifically in
firmware v11, layered on top of otherwise-identical hardware.

## 6. Practical recovery paths (no `magic` recovery needed)

1. **Same box, different PC:** copy the genuine `.rsa` file over, then spoof the destination
   PC's volume serial number to match what the filename formula expects. Works because
   `volume_sn` is a pure client-side lookup key (§2) with zero bearing on the box-side check (§3).
2. **Firmware downgrade:** flashing a box back to v9/v10 (where it exists for your exact
   hardware variant) removes the licensing gate entirely, since that firmware never checks
   for it. Firmware updates for this platform are done via genuine JTAG (Microsemi's
   `DirectC` ISP tool, driven over the same FT2232H USB link in bit-banged mode — not MPSSE,
   plain GPIO toggling) — **be sure you have the correct non-modified-PCB image for your
   exact board variant**, and be aware Microsemi's FlashLock passkey protection means even
   direct JTAG read/write access cannot bypass this without the vendor's original passkey
   (confirmed: `DirectC`'s own error strings explicitly gate FlashROM read/write behind a
   pass key).
3. **Genuine file from another source:** since `magic` isn't derivable, the only way to
   restore a box with no valid file and no v9/v10 firmware option is to obtain a real
   `.rsa` file matching that exact `box_sn` from elsewhere (a prior backup, another user
   with the same unit, etc.).

## Disclaimer

This research was conducted for interoperability and repair purposes.
It does not defeat any payment/licensing mechanism that was active at the
time of research — the vendor's activation server is offline, and this documents how the
existing protocol behaves, not a way to generate new unauthorized activations.
