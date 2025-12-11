# NullCTF 2025 - Netfilter Nightmare

**Author:** vektor  
**Difficulty:** Medium  
**Category:** Reverse Engineering  

**Challenge Description**:  

> I ran a program some friend sent me and all my traffic is now messed up! All this while I was looking at a great steal on the web and can't remember the website(s) I found it on. Help!
>
> Note: By default no traffic passes through the given program.
>
> use `sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0 --queue-bypass` to send traffic to it.  
> use `sudo iptables -D OUTPUT -j NFQUEUE --queue-num 0 --queue-bypass` to delete the previous rule.

**Provided Files**:

```
netfilter-nightmare/
├── nightmare          # Stripped ELF64 binary (Netfilter queue handler)
└── traffic.pcap       # PCAP file with encrypted DNS traffic
```

## Intro

This challenge presents a sophisticated network traffic manipulation scenario involving a malicious binary that intercepts and obfuscates DNS queries using Linux Netfilter queues. The binary operates as a man-in-the-middle for outgoing DNS traffic, encrypting domain names in real-time before they leave the system. Participants are provided with a stripped ELF64 binary (`nightmare`) and a packet capture file (`traffic.pcap`) containing the encrypted DNS traffic. The objective is to reverse engineer the encryption algorithm, decrypt the captured DNS queries, and extract the flag hidden across multiple DNS requests.

The challenge demonstrates advanced concepts including:
- Linux Netfilter Queue (NFQUEUE) packet interception
- UDP/DNS protocol manipulation at the network layer
- Custom XOR-based encryption with dynamic key generation
- Binary reverse engineering of stripped executables
- Network protocol analysis and packet capture forensics

## Initial Analysis

### Step 1: Initial Binary Analysis

First, we examine the binary to understand its nature and capabilities:

```bash
$ file nightmare
nightmare: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, 
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=440f1e117fef472e3f394786d9817047548b0560, 
for GNU/Linux 3.2.0, stripped
```

The binary is a 64-bit Linux executable that has been stripped of debugging symbols. Let's check which libraries it uses:

```bash
$ strings nightmare | head -n 30
/lib64/ld-linux-x86-64.so.2
nfq_set_verdict
nfq_fd
nfq_create_queue
nfq_open
nfq_get_payload
nfq_unbind_pf
nfq_handle_packet
nfq_close
nfq_get_msg_packet_hdr
nfq_set_mode
nfq_bind_pf
nfq_destroy_queue
perror
free
recv
malloc
__libc_start_main
__cxa_finalize
```

The `nfq_*` functions indicate this binary uses **libnetfilter_queue**, which is used to intercept and manipulate network packets in Linux using the NFQUEUE target in iptables.

### Step 2: PCAP File Analysis

Let's examine the packet capture to understand the traffic patterns:

```bash
$ tshark -r traffic.pcap -z io,phs -q
===================================================================
Protocol Hierarchy Statistics
Filter: 

frame                                    frames:99 bytes:11722
  eth                                    frames:99 bytes:11722
    ip                                   frames:78 bytes:10230
      udp                                frames:72 bytes:9870
        dns                              frames:68 bytes:9020
        dhcp                             frames:2 bytes:700
        llmnr                            frames:2 bytes:150
      igmp                               frames:6 bytes:360
    arp                                  frames:13 bytes:762
    ipv6                                 frames:8 bytes:730
      icmpv6                             frames:6 bytes:540
      udp                                frames:2 bytes:190
        llmnr                            frames:2 bytes:190
===================================================================
```

The traffic is predominantly DNS queries. Let's look at some examples:

```bash
$ tshark -r traffic.pcap -Y "dns" | head -n 10
    1   0.000000 192.168.58.10 → 192.168.58.2 DNS 81 Standard query 0x5010 A EEEB713DFBFF75.E8FC7D
    2   0.038289 192.168.58.10 → 192.168.58.2 DNS 120 Standard query 0xbfb2 A CDACD0D6CCA6.C5B5D7D1D4B0.C4A2C6DE.CDAAD1CDCFB0DDD9D4.C3ACDF
    3   0.038426 192.168.58.10 → 192.168.58.2 DNS 120 Standard query 0xeeb5 AAAA CDACD787CCA6.C5B5D080D4B0.C4A2C18F.CDAAD69CCFB0DA88D4.C3ACD8
    4   0.038943 192.168.58.2 → 192.168.58.10 DNS 156 Standard query response 0x5010 No such name A EEEB713DFBFF75.E8FC7D SOA a.root-servers.net
```

The domain names appear to be hexadecimal strings, suggesting they have been encrypted or obfuscated. This is abnormal DNS behavior.

### Step 3: Reverse Engineering the Binary

Using `objdump`, we disassemble the main function to understand the program flow:

```bash
$ objdump -d nightmare | grep -A 100 "1b59:"
```

**Key findings from the disassembly:**

#### Main Function (0x1b59)
The main function performs the following operations:

1. **Opens a Netfilter Queue connection** (`nfq_open`)
2. **Unbinds and rebinds** to the AF_INET protocol family (`nfq_unbind_pf`, `nfq_bind_pf`)
3. **Creates a queue** with queue number 0 and registers a callback function at address `0x134e`
4. **Sets NFQNL_COPY_PACKET mode** to receive full packet payloads
5. **Enters a loop** calling `recv()` and `nfq_handle_packet()` to process packets

#### Callback Function (0x134e)
This is where the packet processing happens. The callback:

1. **Extracts the packet header** using `nfq_get_msg_packet_hdr()`
2. **Gets the packet payload** using `nfq_get_payload()`
3. **Checks if the packet is IPv4 UDP** (checks for IP version 4 and protocol 0x11)
4. **Verifies it's DNS traffic** (checks destination port 0x0035 = port 53)
5. **Parses the DNS query** and extracts the Question Name (QNAME)
6. **Encrypts the domain name** using a custom algorithm
7. **Modifies the packet** with the encrypted domain
8. **Returns verdict** to allow the modified packet through

### Step 4: Understanding the Encryption Algorithm

By analyzing the encryption routine starting at address `0x1280`, we discover:

#### Key Generation

The encryption key is **4 bytes** derived from packet headers:

```
Key[0] = Source Port (Low Byte)
Key[1] = Source Port (High Byte)
Key[2] = DNS Transaction ID (Low Byte)
Key[3] = DNS Transaction ID (High Byte)
```

This means each packet has a potentially different key based on its source port and DNS transaction ID.

#### Encryption Process

For each DNS label in the domain name:

1. **Read each byte** of the label
2. **XOR with the key**: `encrypted_byte[i] = plaintext_byte[i] ^ key[i % 4]`
3. **Convert to hexadecimal**: Each encrypted byte becomes a 2-character hex string
4. **Join labels** with dots to form the encrypted domain name

**Example:**

```
Original domain: "example.com"
Source Port: 0xB916 (47382 decimal)
DNS ID: 0x784A (30794 decimal)

Key = [0x16, 0xB9, 0x4A, 0x78]

Encryption of "example":
e (0x65) ^ 0x16 = 0x73 → "73"
x (0x78) ^ 0xB9 = 0xC1 → "C1"
a (0x61) ^ 0x4A = 0x2B → "2B"
m (0x6D) ^ 0x78 = 0x15 → "15"
p (0x70) ^ 0x16 = 0x66 → "66"
l (0x6C) ^ 0xB9 = 0xD5 → "D5"
e (0x65) ^ 0x4A = 0x2F → "2F"

Result: "73C12B1566D52F"
```

### Step 5: Extracting Packet Metadata

To decrypt the DNS queries, we need to extract the source port and DNS transaction ID from each packet:

```bash
$ tshark -r traffic.pcap -Y "dns && udp.srcport" -T fields -e frame.number -e udp.srcport -e dns.id -e dns.qry.name | head -n 5
1	37771	0x5010	EEEB713DFBFF75.E8FC7D
2	49074	0xbfb2	CDACD0D6CCA6.C5B5D7D1D4B0.C4A2C6DE.CDAAD1CDCFB0DDD9D4.C3ACDF
3	49074	0xeeb5	CDACD787CCA6.C5B5D080D4B0.C4A2C18F.CDAAD69CCFB0DA88D4.C3ACD8
7	40843	0x64d0	ABDABF03A0D0.AFDABD
9	40843	0x11c1	E6E9B579F4E2.E2EFAC
```

### Step 6: Decryption Script

We create a Python script to decrypt all DNS queries:

```python
import sys

def solve(line):
    parts = line.strip().split('\t')
    if len(parts) < 4:
        return
    
    frame_num = parts[0]
    src_port = parts[1]
    dns_id = parts[2]
    qry_name = parts[3]
    
    if not src_port or not dns_id or not qry_name:
        return

    try:
        sp = int(src_port)
        did = int(dns_id, 16)
    except ValueError:
        return

    # Key Calculation
    # Key[0] = SP LSB
    # Key[1] = SP MSB
    # Key[2] = ID LSB
    # Key[3] = ID MSB
    
    k0 = sp & 0xFF
    k1 = (sp >> 8) & 0xFF
    k2 = did & 0xFF
    k3 = (did >> 8) & 0xFF
    
    key = [k0, k1, k2, k3]
    
    # Decrypt
    labels = qry_name.split('.')
    decoded_labels = []
    
    try:
        for label in labels:
            if not label:
                continue               
            try:
                enc_bytes = bytes.fromhex(label)
            except ValueError:               
                decoded_labels.append(label)
                continue
            
            dec_str = ""
            for i, b in enumerate(enc_bytes):
                k = key[i % 4]
                dec_str += chr(b ^ k)
            decoded_labels.append(dec_str)
            
        decoded_name = '.'.join(decoded_labels)
        print(f"Frame {frame_num}: {decoded_name}")
        
    except Exception as e:
        print(f"Frame {frame_num}: Error {e}")

def main():
    # Read from stdin
    for line in sys.stdin:
        solve(line)

if __name__ == "__main__":
    main()
```

### Step 7: Running the Decryption

Execute the decryption script on all DNS packets:

```bash
$ tshark -r traffic.pcap -Y "dns && udp.srcport" -T fields -e frame.number -e udp.srcport -e dns.id -e dns.qry.name | python3 decrypt_all.py
```

**Key Output (relevant frames):**

```
Frame 1: example.com
Frame 2: mobile.events.data.microsoft.com
Frame 7: google.com
Frame 9: github.com
Frame 11: cloudflare.com
Frame 13: openai.com
Frame 15: wikipedia.org
Frame 23: yahoo.com
Frame 25: bing.com
Frame 27: nullctf{dns_.ro
Frame 49: amazon.com
Frame 52: stackoverflow.com
Frame 58: python.org
Frame 62: reddit.com
Frame 67: is_br0k3n_.ro
Frame 69: apple.com
Frame 84: why_is_i7.ro
Frame 86: cnn.com
Frame 88: bbc.co.uk
Frame 90: mit.edu
Frame 92: duckduckgo.com
Frame 98: _4lw4ys_dns}.ro
```

### Step 8: Extracting the Flag

The flag is split across multiple DNS queries to `.ro` domains (frames 27, 67, 84, 98):

1. Frame 27: `nullctf{dns_`
2. Frame 67: `is_br0k3n_`
3. Frame 84: `why_is_i7`
4. Frame 98: `_4lw4ys_dns}`

Concatenating these subdomains in chronological order:

```
nullctf{dns_ + is_br0k3n_ + why_is_i7 + _4lw4ys_dns}
```

## Key Takeaways

1. **Network Layer Manipulation**: Linux Netfilter provides powerful packet manipulation capabilities that can be abused
2. **Custom Encryption**: Even simple XOR encryption can be effective for obfuscation when keys are unpredictable
3. **Protocol-Aware Attacks**: Understanding protocol structure (DNS in this case) is essential for both attack and defense
4. **Metadata Importance**: The encryption key was hidden in plain sight within packet headers
5. **Multi-Step Analysis**: Solving required combining reverse engineering, network analysis, and cryptography

Pwned!

KOREONE
