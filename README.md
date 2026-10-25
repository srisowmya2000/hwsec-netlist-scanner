# hwsec-netlist-scanner

A small hardware-security checker for KiCad schematics. Give it a KiCad netlist and it flags places where an attacker with physical access could get into the board: exposed debug ports, boot-mode overrides, unprotected power inputs, glitchable supplies, tamperable trimmers and more. Each finding comes with a cybersecurity explanation (attack, attacker access, CIA impact, STRIDE category, CWE ID).

It's a single Python file with no dependencies (Python 3.8+).

## Usage

1. In KiCad's schematic editor: **File → Export → Netlist**, KiCad format.
2. Run:

```bash
python3 circuit.py path/to/board.net
```

Try it on the included examples:

```bash
python3 circuit.py examples/pic_programmer.net
```

## What it checks

**Digital checks**

| Check | Looks for |
|---|---|
| Debug interfaces | UART consoles, JTAG/SWD, PIC ICSP pins reaching a header or test point |
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
| Clock / crystal | Oscillator lines reachable from outside, tunable crystals |
| Trimmers | Internal calibration parts that could be tampered with (vs. front-panel controls) |

The report ends with a **security assessment**: overall risk rating, findings by attacker access (external vs. case opened), impact on confidentiality/integrity/availability, and the top fixes.

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

## License

The scanner code (`circuit.py`) is released under the [MIT License](LICENSE). The example netlists are not covered by this license; see the credits above.
