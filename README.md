# hwsec-netlist-scanner

[![tests](https://github.com/srisowmya2000/hwsec-netlist-scanner/actions/workflows/tests.yml/badge.svg)](https://github.com/srisowmya2000/hwsec-netlist-scanner/actions/workflows/tests.yml)

A small hardware-security checker for KiCad schematics. Give it a KiCad netlist and it flags places where an attacker with physical access could get into the board: exposed debug ports, boot-mode overrides, unprotected power inputs, glitchable supplies, tamperable trimmers and more. Each finding comes with a cybersecurity explanation (attack, attacker access, CIA impact, STRIDE category, CWE ID).

It works on digital boards, analog boards, **mains-powered IoT appliances** and **satellites**. For appliances like a washing machine it also checks the cyber-physical side: which dangerous loads (heater, motor, door lock) the firmware controls, and whether hardware interlocks still keep the machine safe if that firmware is hacked. For satellite boards it switches to a spacecraft view: in orbit the radio link is the only way in, so physical-access findings are reported as risks before launch.

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
python3 circuit.py examples/espgaggia.net       # espresso machine (heater appliance)
python3 circuit.py examples/cicada_2g.net       # 2G cellular IoT module
python3 circuit.py examples/oresat_c3.net       # satellite flight computer
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
| Cellular modems: Quectel (BG95/96, BC66/95, EC25, EG25, M95), SIMCom (SIM800/900, SIM7000/7020/7080/7600, A7670), u-blox (SARA, LARA, LENA, TOBY), Telit, Sierra, Nordic nRF91, Sequans GM02S | Modem USB port, debug UART, AT-command UART, USB_BOOT/BOOT_CFG download-mode pins, SIM card lines |
| Plug-in dev boards (ESP32 DevKitC, NodeMCU, Wemos D1 mini, Arduino, Pico, Blue Pill, Feather, XIAO) | Built-in USB programming port; their own 3.3V regulator and decoupling |

To add a chip, add an entry to `KNOWN_PINS` in `circuit.py`: the part value to match, then pin name → what that pin does. Descriptions containing "programming", "debug" or "UART" are treated as debug ports, and "Boot-mode" marks a boot pin.

## What it checks

**Digital checks**

| Check | Looks for |
|---|---|
| Debug interfaces | UART consoles, JTAG/SWD, PIC ICSP and AVR UPDI/ISP pins or programming headers reaching the outside |
| Wireless interfaces | Bluetooth, Wi-Fi, LoRa, Zigbee and similar modules or headers: a remote attack surface |
| Cellular modem | Modems that put the device on the mobile network, reachable from anywhere (not just radio range). Warns about 2G-only modems (no network authentication, fake base stations) |
| SIM card | Removable SIM card holders (the SIM can be taken out and used elsewhere) vs. soldered eSIMs |
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
| Mains & actuator safety | For mains appliances: fuse and surge protection at the mains input, isolation between mains and logic (isolated supplies, optocouplers, solid-state relays), and which loads (heater, boiler, pump, motor, door lock...) the firmware controls through relays, triacs or SSRs vs. which are blocked by hardware interlocks. For boards that drive an external relay/SSR, flags the lack of a hardware cutoff |
| Clock / crystal | Oscillator lines reachable from outside, tunable crystals |
| Trimmers | Internal calibration parts that could be tampered with (vs. front-panel controls) |

The report ends with a **security assessment**: overall risk rating, findings by attacker access (external vs. case opened), impact on confidentiality/integrity/availability, and the top fixes.

**Spacecraft profile.** When a board has a satellite-band radio chip (AT86RF215, AX5043, SX12xx, RFM9x...) and subsystem names on its nets (EPS, ADCS, OBC, UHF, L-band...), the report treats it as a satellite. The radio is reported as the link to the ground, reachable from any ground station in view. Links to the satellite's other boards over the CAN stack connector are reported as internal links, not debug ports. And physical-access findings are grouped as "before launch" (assembly, testing and integration), since nobody can touch the board in orbit.

## Results on the example boards

| Board | Type | Overall risk | Main findings |
|---|---|---|---|
| `mygenwashy.net` | Washing machine controller (230 V, ATtiny3226) | **HIGH** | Exposed UPDI programming port; unprotected sensor and I²C pins; mains side well protected, with hardware interlocks |
| `doorman.net` | Smart door intercom / door opener (ESP32-S3, Wi-Fi) | **HIGH** | USB-C is a built-in JTAG/programming port; UART console on test pads; boot button; Wi-Fi/BLE remote surface; door-opener relay driven by firmware alone |
| `satellite_tracker.net` | Desktop satellite tracker base board (ESP32-C6, Wi-Fi/BLE) | **HIGH** | Auto-programming header (UART + DTR/RTS drive reset and the boot pin); USB-C is a built-in JTAG/programming port; Wi-Fi/BLE remote surface; sensor connectors wired straight into the chip |
| `elixir.net` | Golioth Elixir cellular IoT device (nRF9160 LTE-M, ESP32-C3 Wi-Fi/BLE, GPS) | **HIGH** | SWD and ESP32-C3 programming headers; cellular + Wi-Fi/BLE remote surface; removable nano-SIM slot next to the soldered eSIM |
| `cicada_2g.net` | EnAccess Cicada 2G IoT module (SIM800C) | **HIGH** | Modem USB port on a connector; 2G-only modem (fake base stations); removable SIM |
| `cicada_4g.net` | EnAccess Cicada 4G IoT module (SIM7600) | **HIGH** | Modem USB port on a connector; modem boot pin (BOOT_CFG0) on a test pad; removable SIM |
| `espgaggia.net` | Espresso machine controller (230 V, ESP32 DevKitC, Wi-Fi) | **HIGH** | Dev board with a USB programming port; boiler heater on an external SSR driven by firmware alone; pump and valve switched by SSRs with no hardware interlock |
| `open_vapors.net` | Reflow oven controller (ATmega32U4, Bluetooth) | **HIGH** | AVR ISP programming header; Bluetooth module header (remote attack surface); heater SSR driven by firmware with no hardware cutoff |
| `oresat_c3.net` | OreSat C3 satellite flight computer (OSD3358, UHF and L-band radios) | **HIGH** | JTAG test points and a debug UART connector (before launch); two radios as the ground command link; EEPROM write-protect reachable from a header |
| `osusat_obc.net` | OSUSat CubeSat flight computer (STM32H743, LoRa radio) | **HIGH** | SWD programming header and a spare UART header (before launch); LoRa radio as the ground command link; inter-board UART and CAN links on the stack connectors |
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

### Case study: cellular IoT (Cicada and Elixir)

A cellular modem changes who can attack a device: Wi-Fi and Bluetooth need someone nearby, but a modem is reachable from anywhere through the mobile network.

- **Modem USB port on a connector (HIGH):** on both Cicada boards the SIM800C/SIM7600 USB lines go straight to the USB connector. That port gives AT commands, modem diagnostics and modem firmware updates to anyone who plugs in.
- **Modem boot pin on a test pad (MEDIUM, Cicada 4G):** the SIM7600's BOOT_CFG0 is on TP1. Shorting it at power-up puts the modem in download mode, so its firmware can be replaced.
- **2G-only modem (LOW, Cicada 2G):** 2G phones never check that the cell tower is real, so a cheap fake base station can intercept or inject traffic. 2G networks are also being switched off.
- **Removable SIM (LOW):** both Cicada boards use a SIM card holder. Elixir has a soldered eSIM, but also a nano-SIM slot on the same lines. A SIM taken out can use the data plan, or impersonate the device if the backend trusts the SIM.

### Case study: satellites (OreSat and OSUSat)

A satellite flips the usual threat model. Once it's in orbit nobody can open the case, so the radio is the only way in, and the debug ports matter before launch, during assembly, testing and integration.

- **Ground command link (MEDIUM):** OreSat's C3 card has two AT86RF215 radios (UHF and L-band) and OSUSat's flight computer has a LoRa radio. Anyone with a ground station in view can transmit to them, so every telecommand needs authentication with replay protection, and a safe mode that commands can't switch off.
- **Debug access before launch (HIGH):** OreSat brings the processor's JTAG pins out to test points and its debug UART to a connector (J8); OSUSat has an SWD programming header (J1) and a spare UART header (J6). They're needed for development, and they're the place to tamper with a flight board on its way to the launch.
- **Internal links (INFO):** OSUSat's main and auxiliary UARTs go only to the stack connectors (J10, J11) that join it to the satellite's other boards. One of them is also the STM32's ROM bootloader port, so a compromised neighbouring board could reflash this one.

### Case study: espresso machine (espgaggia)

A Wi-Fi controller that replaces the brains of a Gaggia Classic espresso machine: it runs the boiler heater, the pump and the solenoid valve. This is the same kind of circuit as a popcorn machine, kettle or toaster oven: a heater and a motor on mains, switched by a microcontroller.

- **Programming port (HIGH):** the ESP32 sits on a DevKitC development board, whose USB port can dump or replace the firmware. Unless secure boot and flash encryption are on, anyone who opens the case owns the machine.
- **Remote attack surface (MEDIUM):** Wi-Fi/Bluetooth on the ESP32. A bug in the web interface or OTA update could hand control of the heater to someone on the network.
- **Heater driven by firmware alone (MEDIUM):** the boiler's solid-state relay is wired straight to an ESP32 pin (J10). There is no thermal cutoff on the board, so hacked or crashed firmware could keep the boiler heating. The machine's own thermostat and thermal fuse (not on this board) are what stop a fire.
- **Pump and valve (MEDIUM):** switched by two Omron G3MB solid-state relays on mains, with no hardware interlock.
- **Good mains design:** fused 220 V input, an isolated HLK-PM01 power module, and SSRs that keep mains away from the logic. Only surge protection (a varistor) is missing.
- **Boot pin on a header (MEDIUM):** IO0, the ESP32's download-mode strap, is on the "Misc" header J5.

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

## Tests

The tests use Python's built-in `unittest`, so there's nothing to install. From the project folder:

```bash
python3 -m unittest discover -s tests -v
```

They check that:
- every example board still gives exactly the same report (saved copies in `tests/expected/`)
- each chip in `KNOWN_PINS` is recognised, using a hand-written test board (`tests/boards/chips.net`)
- the report is the same on every run
- the JSON and HTML reports are valid and match the findings
- bad input (no file, wrong file type) gives a clear error

GitHub runs them on every push, on Python 3.8 and 3.13.

If you change a rule on purpose and the findings change, refresh the saved reports. Then review the changes with `git diff tests/expected` before committing:

```bash
python3 tests/test_circuit.py --update
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
| `elixir.net` | Golioth Elixir, open-source cellular IoT device | [golioth/elixir-hw](https://github.com/golioth/elixir-hw) by Golioth, CERN-OHL-P-2.0. Exported from its KiCad schematic with KiCad 10. |
| `cicada_2g.net`, `cicada_4g.net` | Okra Cicada 2G and 4G IoT communication modules | [EnAccess/Cicada-GSM-HW](https://github.com/EnAccess/Cicada-GSM-HW), MIT license ("Copyright (c) 2019 EnAccess Foundation"). Exported from its KiCad schematics with KiCad 10. |
| `espgaggia.net` | espgaggia, ESP32 controller for a Gaggia Classic espresso machine | [rvt/espgaggia](https://github.com/rvt/espgaggia) by R. van Twisk, MIT license ("Copyright (c) 2021 R. van Twisk"). Exported from its KiCad schematic with KiCad 10. |
| `oresat_c3.net` | OreSat C3 (Command, Communication and Control) card, the flight computer of the OreSat CubeSats | [oresat/oresat-c3-hardware](https://github.com/oresat/oresat-c3-hardware) by the Portland State Aerospace Society (OreSat), CERN-OHL-S-2.0. Exported from its KiCad schematic (commit 738a430) with KiCad 10. This netlist stays under CERN-OHL-S-2.0. |
| `osusat_obc.net` | OSUSat on-board computer (OBC) v1 | [OSUSat/cubesat](https://github.com/OSUSat/cubesat) by OSUSat (Oregon State University), MIT license ("Copyright (c) 2025 OSUSat"). Exported from its KiCad schematic (commit afa93ab) with KiCad 10. |
| `open_vapors.net` | Open Vapors reflow oven controller, Rev 2 | [baldengineer/Open-Vapors](https://github.com/baldengineer/Open-Vapors) by baldengineer, MIT license (the project's LICENSE reads "Copyright (c) 2013-2021 Damien P. George"). Generated from the KiCad PCB with `tools/pcb2net.py`. |

## License

Copyright (c) 2026 Sri Sowmya Nemani. All rights reserved. The scanner code (`circuit.py`) is shared for viewing; please ask before reusing it. The example netlists belong to their original authors; see the credits above.
