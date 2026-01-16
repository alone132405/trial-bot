# Protocol Bot Setup - Step-by-Step Guide

## Step 1: Install Wireshark

1. **Download Wireshark** from: https://www.wireshark.org/download.html
2. **Install** with default options (include Npcap for packet capture)
3. **Restart your computer** if prompted

---

## Step 2: Extract Auth Data from Existing Bot

The existing bot already has your credentials. Let's extract them!

### 2.1 Check the acc.json files
Each account folder has encrypted credentials in `acc.json`.

### 2.2 Use Packet Capture (HTTP Catcher method)
The bot communicates with IGG servers - we can capture this traffic.

---

## Step 3: Capture Traffic

### 3.1 Start Wireshark
1. Open Wireshark
2. Select your **network adapter** (usually "Ethernet" or "Wi-Fi")
3. Click the **blue shark fin** to start capture

### 3.2 Set Filter
In the filter bar, type:
```
tcp.port == 443 or tcp.port == 80 or host contains igg
```

### 3.3 Start the Bot
1. Open LordsMobileBot.exe
2. Connect an account
3. Watch Wireshark for traffic to IGG servers

### 3.4 Look for:
- Connections to `cgi.igg.com`
- POST/GET requests with JSON payloads
- Look for `igg_id`, `device_id`, `access_key` in packets

---

## Step 4: Alternative - Check Bot's Network Calls

Since the bot is protected, we can observe its traffic patterns instead of reading its code.

Run the Python sniffer I'll create next to automatically capture the data.

---

## Step 5: Test the Protocol

Once you have:
- IGG ID (you already have this: 987303841)
- Device ID
- Access Key

We can test the protocol client!
