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
