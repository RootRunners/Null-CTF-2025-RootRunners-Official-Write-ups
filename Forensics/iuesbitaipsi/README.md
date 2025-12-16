# NullCTF – iuesbitaipsi (Forensics)

## Challenge Overview

- **Name:** iuesbitaipsi  
- **Category:** Forensics  
- **Artifact:** `nullctf.pcapng`  
- **Flag format:** `nullctf{...}`

The challenge provides a PCAPNG file, indicating that the solution requires traffic analysis.

## Initial Traffic Inspection

The file was opened in **Wireshark**.

A quick inspection shows:
- No HTTP or DNS data of interest
- No file transfers
- No plaintext credentials

This suggests the traffic is not related to standard network communication.

## USB HID Identification

Filtering for USB traffic: usb

Reveals multiple **USB Interrupt Transfer** packets, typical of **HID keyboard devices**.

---

## HID Packet Structure

Each USB HID keyboard report is 8 bytes long and structured as follows:

| Byte | Description |
|----|------------|
| 0 | Modifier keys (Shift, Ctrl, Alt, etc.) |
| 1 | Reserved |
| 2–7 | Up to 6 simultaneous keycodes |

The **modifier byte** is a bitmask where:
- `0x02` = Left Shift
- `0x20` = Right Shift

This is required to determine uppercase characters and symbols.

---

## Keystroke Decoding Process

To reconstruct the typed input, the following steps were performed:

1. **Packets were analyzed in chronological order**, preserving the keystroke sequence.
2. Only packets where at least one keycode byte (bytes 2–7) was non-zero were considered.
3. Each keycode was mapped to its corresponding character using the standard **USB HID Usage Table**.
4. The modifier byte was checked to determine whether the **Shift key** was pressed.
5. Key release packets (all-zero keycode fields) were ignored.
6. Repeated keycodes were handled as individual keystrokes to preserve the original input.

This process allows full reconstruction of the text exactly as typed on the keyboard.

---

## Extracted Input

After decoding all relevant HID reports, the following string was recovered:


## Flag

Applying leetspeak and the required format:

nullctf{4nd_7h47s_h0w_4_k3yl0gg3r_w0rks}
