# hwsec-netlist-scanner

A small hardware-security checker for KiCad schematics. Give it a KiCad netlist and it flags places where an attacker with physical access could get into the board: exposed debug ports, boot-mode overrides, unprotected power inputs, glitchable supplies, tamperable trimmers and more. Each finding comes with a cybersecurity explanation (attack, attacker access, CIA impact, STRIDE category, CWE ID).

It works on digital boards, analog boards and **mains-powered IoT appliances**. For appliances like a washing machine it also checks the cyber-physical side: which dangerous loads (heater, motor, door lock) the firmware controls, and whether hardware interlocks still keep the machine safe if that firmware is hacked.

It's a single Python file with no dependencies (Python 3.8+).

<img width="1672" height="941" alt="image" src="https://github.com/user-attachments/assets/f968a079-1d76-4fb3-a4ef-d983e1145d54" />


## Usage

1. In KiCad's schematic editor: **File → Export → Netlist**, KiCad format.
2. Run:

```bash
python3 circuit.py path/to/board.net
```

Try it on the included examples (run from the project folder):

```bash
python3 circuit.py examples/mygenwashy.net      # washing machine
python3 circuit.py examples/doorman.net         # smart door opener
python3 circuit.py examples/pic_programmer.net
```

### JSON and HTML reports

Besides the text report, you can save the results as JSON (for scripts and other tools) or as an HTML page (to read in a browser or share):

```bash
python3 circuit.py examples/doorman.net --html doorman.html     # styled web page
python3 circuit.py examples/doorman.net --json doorman.json     # machine-readable
python3 circuit.py examples/doorman.net --json - | jq .assessment   # JSON only, to the screen
```

The HTML page is a single self-contained file (no internet needed). It shows the overall risk, who can exploit the board, the CIA impact, the top fixes, and every check with its cybersecurity view. It follows your system's light/dark mode. Passed checks are hidden until you tick "Show passed checks".

The JSON has the same content: `components`, `nets`, `board_profile`, `sections` (each check with its `findings` and `threat`), `assessment` (overall risk, score, attacker access, CIA, fix-first list) and a `summary` count per level.

## Chips it knows

On most boards the scanner works from net and pin names alone. For these chips it also knows what specific pins do, so it catches debug and boot pins even when the nets have generic names:

| Chip | Pins it understands |
|---|---|
| ESP32, ESP32-S3, ESP32-C3, ESP32-C6 | Boot strap pins, UART0 bootloader console, built-in USB-Serial/JTAG |
| ESP8266 (ESP-12E/F modules) | GPIO0/GPIO2/GPIO15 boot straps, UART0 |
| STM32 (all families) | SWD (PA13/PA14), JTAG (PA15/PB3/PB4), BOOT0, USART1 ROM bootloader (PA9/PA10) |
| RP2040, RP2350 (Raspberry Pi Pico) | SWD, BOOTSEL (QSPI_SS), UART0 on GPIO0/1 |
| nRF52 series | SWD |
| ATSAMD21 | SWD (PA30/PA31) |
| ATmega328P, ATmega32U4 | ISP programming pins, RESET/debugWIRE, UART |
| ATtiny 2-series | UPDI, I2C |
| Raspberry Pi Compute Module 5 | UART console, nRPIBOOT, boot EEPROM write-protect |

To add a chip, add an entry to `KNOWN_PINS` in `circuit.py`: the part value to match, then pin name → what that pin does. Descriptions containing "programming", "debug" or "UART" are treated as debug ports, and "Boot-mode" marks a boot pin.

## What it checks

**Digital checks**

| Check | Looks for |
|---|---|
| Debug interfaces | UART consoles, JTAG/SWD, PIC ICSP and AVR UPDI/ISP pins or programming headers reaching the outside |
| Wireless interfaces | Bluetooth, Wi-Fi, LoRa, Zigbee and similar modules or headers: a remote attack surface |
| Boot-mode pins | Boot/strap pins that a switch or connector can drive |
| Write protection | Floating, unconnected or externally reachable EEPROM/flash write-protect pins |
| Power test points | Supply rails exposed on test points (voltage-glitching access) |
| Exposed SPI/I2C buses | Bus signals brought out to connectors (sniffing/spoofing) |
| USB ESD protection | USB data lines without ESD protection |

**Analog checks** (useful on any board)

| Check | Looks for |
|---|---|
| Signal input/output protection | Connector pins wired straight into chip pins, or with no clamp diodes/TVS |
| Power input protection | Power entry without fuse, reverse-polarity diode or TVS (and tells power inputs from outputs) |
| Supply decoupling | Chip supply pins with no decoupling capacitor (easier fault injection) |
| Mains & actuator safety | For mains appliances: fuse and surge protection at the mains input, isolation between mains and logic, and which loads (heater, motor, door lock...) the firmware controls vs. which are blocked by hardware interlocks. For boards that drive an external relay/SSR, flags the lack of a hardware cutoff |
| Clock / crystal | Oscillator lines reachable from outside, tunable crystals |
| Trimmers | Internal calibration parts that could be tampered with (vs. front-panel controls) |

The report ends with a **security assessment**: overall risk rating, findings by attacker access (external vs. case opened), impact on confidentiality/integrity/availability, and the top fixes.

## Results on the example boards

| Board | Type | Overall risk | Main findings |
|---|---|---|---|
| `mygenwashy.net` | Washing machine controller (230 V, ATtiny3226) | **HIGH** | Exposed UPDI programming port; unprotected sensor and I²C pins; mains side well protected, with hardware interlocks |
| `doorman.net` | Smart door intercom / door opener (ESP32-S3, Wi-Fi) | **HIGH** | USB-C is a built-in JTAG/programming port; UART console on test pads; boot button; Wi-Fi/BLE remote surface; door-opener relay driven by firmware alone |
| `satellite_tracker.net` | Desktop satellite tracker base board (ESP32-C6, Wi-Fi/BLE) | **HIGH** | Auto-programming header (UART + DTR/RTS drive reset and the boot pin); USB-C is a built-in JTAG/programming port; Wi-Fi/BLE remote surface; sensor connectors wired straight into the chip |
| `open_vapors.net` | Reflow oven controller (ATmega32U4, Bluetooth) | **HIGH** | AVR ISP programming header; Bluetooth module header (remote attack surface); heater SSR driven by firmware with no hardware cutoff |
| `pic_programmer.net` | PIC programmer | **HIGH** | Programming pins on the sockets (by design); EEPROM write-protect unconnected; serial data line unclamped |
| `sonde_xilinx.net` | JTAG cable | **HIGH** | JTAG lines on the connectors (by design); partial clamp protection |
| `CM5_MINIMA_3.net` | Raspberry Pi CM5 carrier | MEDIUM | Boot pin on a switch; USB-C power input with no TVS/fuse; power rails on test points |
| `multichannel_mixer.net` | Audio mixer (analog) | MEDIUM | 12 V power jack with no reverse-polarity, fuse or TVS protection |
| `modul.net` | PAL video encoder (analog) | LOW | Unclamped module ports; tamperable trimmers |

### Case study: washing machine (MyGenWashy)

A connected washing machine shows why hardware security matters for IoT. Its firmware switches 230 V loads, so a firmware compromise can turn into a physical hazard.

- **Main risk (HIGH):** the ATtiny3226's UPDI programming port is on a header (J1). With the case open, anyone can read out or replace the firmware that drives the heater, motor and door lock.
- **Exposed interfaces:** the temperature sensor (J17) and the I²C header (J13, likely the link to a Wi-Fi/ESPHome module) go straight into the chip with no protection, and the I²C traffic can be tapped.
- **Good mains design:** fused and surge-protected mains input, an isolated power supply, and optocouplers between mains and logic.
- **Hardware interlocks:** the water-level and door switches drive their own relays, which gate the heater, water valves, drain and door lock. Even malicious firmware can't, for example, heat with no water.
- **Remaining gap:** the drum motor (triac Q1) is switched by firmware alone, so a hacked or buggy firmware could run it in an unsafe state.

### Case study: smart door opener (Doorman S3)

Doorman connects a building's door intercom to Wi-Fi so you can ring and open the door from your phone. Taking it over means getting through the door.

- **Programming and debug ports (HIGH):** the ESP32-S3's built-in USB-Serial/JTAG goes straight to the USB-C port, and the UART0 console is on test pads (J4/J5). Unless these are locked down in the chip's eFuses (secure boot, flash encryption, JTAG disabled), anyone with the device in hand can dump or replace the firmware.
- **Boot button (MEDIUM):** the "Flash" button (SW2 on IO0) puts the chip into download mode at reset.
- **Remote attack surface (MEDIUM):** Wi-Fi and Bluetooth on the ESP32-S3. Weak authentication in the firmware or app would let someone nearby open the door.
- **Cyber-physical risk (MEDIUM):** the door-opener relay (U3, RELAY_WIRE1/2 on J2) is switched by firmware alone, with no hardware interlock, so compromised firmware can open the door at will.
- **USB ESD (MEDIUM):** the USB-C data lines have no ESD protection.

### Case study: reflow oven (Open-Vapors)

An oven controller you can talk to over Bluetooth.

- **Remote attack surface (MEDIUM):** a Bluetooth module header (JP1) is wired to the microcontroller's UART. Anyone in radio range can send it commands, so the firmware must authenticate and validate them.
- **Programming header (HIGH):** the AVR ISP header (ISP1) lets anyone with the case open read out or replace the firmware.
- **Cyber-physical risk (MEDIUM):** the firmware switches the heater through an external solid-state relay (JP4), and there is no hardware cutoff on the board. Hacked or crashed firmware could leave the heater on. A thermal fuse in the heater path would stop that.

## Old KiCad projects (missing libraries)

If a schematic won't export (common with KiCad 5 projects whose symbol libraries weren't committed), build the netlist from the PCB instead:

```bash
python3 tools/pcb2net.py board.kicad_pcb board.net
python3 circuit.py board.net
```

The PCB has every part and connection but no pin names or types, so a few checks find less than they would from the schematic. `examples/open_vapors.net` was made this way.

## Example output

```
== Power input protection ==
   [MEDIUM] Power input +12V from J5 feeds IC1, IC2, IC3, IC4, IC5 directly - no fuse, reverse-polarity diode or TVS
            -> A wrong adapter, reversed plug or deliberate voltage spike reaches the chips. Add a series diode/P-FET, a TVS and a fuse or PTC.
   Cybersecurity view:
      Attack    : Reverse the plug, apply overvoltage or a surge on the power input to destroy the
                  board. A controllable bench supply on that input also makes voltage glitching
                  easy.
      Attacker  : External - just plug something into a connector, no need to open the case
      Impact    : Integrity, Availability
      STRIDE    : Denial of service, Tampering
      CWE       : CWE-1384 (physical/environmental conditions), CWE-1247 (voltage glitches)

######## SECURITY ASSESSMENT ########

Overall risk: MEDIUM   (score 15 - HIGH=10, MEDIUM=5, LOW=2, INFO=0.5 each)
```

## Limitations

This is a netlist-only review. It can't see firmware settings (secure boot, read-out protection, disabled consoles), the enclosure or the PCB layout, and it relies on naming conventions (reference designators, net and pin names). Treat findings as places to check, not final verdicts.

## Example boards and credits

The netlists in [`examples/`](examples/) were exported from third-party open designs and are included only to demonstrate the tool. They remain under their original authors' terms.

| File | Board | Source / credit |
|---|---|---|
| `CM5_MINIMA_3.net` | CM5 MINIMA (Raspberry Pi Compute Module 5 carrier) | Designed by Pierluigi Colangeli. Some library parts by Antmicro (Apache-2.0). |
| `multichannel_mixer.net` | Multichannel audio mixer | KiCad demo project by CERN, licensed CC-BY-SA 4.0 |
| `modul.net` | Video (PAL encoder) module | KiCad demo project |
| `pic_programmer.net` | JDM COM84 PIC programmer | KiCad demo project |
| `sonde_xilinx.net` | Xilinx "Parallel Cable III" JTAG programming cable | KiCad demo project ("sonde xilinx") |
| `mygenwashy.net` | MyGenWashy washing machine controller (230 V, ATtiny3226) | [mayermakes/MyGenWashy](https://github.com/mayermakes/MyGenWashy), GPL-3.0. This netlist is exported from that design and stays under GPL-3.0. |
| `doorman.net` | Doorman S3 door intercom gateway, Rev 1.6.1 | [AzonInc/Doorman](https://github.com/AzonInc/Doorman), GPL-3.0. This netlist is exported from that design and stays under GPL-3.0. |
| `satellite_tracker.net` | Desktop Satellite Tracker, base board | [KJ7NLL/Satellite-Tracker-Circuit-Design-Files](https://github.com/KJ7NLL/Satellite-Tracker-Circuit-Design-Files), GPL-3.0. This netlist is exported from that design and stays under GPL-3.0. |
| `open_vapors.net` | Open Vapors reflow oven controller, Rev 2 | [baldengineer/Open-Vapors](https://github.com/baldengineer/Open-Vapors) by baldengineer, MIT license (the project's LICENSE reads "Copyright (c) 2013-2021 Damien P. George"). Generated from the KiCad PCB with `tools/pcb2net.py`. |

## License

Copyright (c) 2026 Sri Sowmya Nemani. All rights reserved. The scanner code (`circuit.py`) is shared for viewing; please ask before reusing it. The example netlists belong to their original authors; see the credits above.
