#!/usr/bin/env python3
"""
circuit.py - a tiny hardware-security checker for KiCad netlists.

Usage:
    python3 circuit.py path/to/board.net
    python3 circuit.py board.net --html report.html --json report.json

It reads a KiCad netlist (File -> Export -> Netlist, "KiCad" format),
builds a list of components and nets, then runs simple security rules.
No extra libraries needed - just Python 3.8+.
"""

import argparse
import html
import json
import os
import re
import sys
import textwrap
from collections import defaultdict

# ---------------------------------------------------------------------------
# 1. Parse the netlist (KiCad netlists are "S-expressions": nested brackets)
# ---------------------------------------------------------------------------

def tokenize(text):
    # Matches "(", ")", quoted strings, or plain words
    return re.findall(r'\(|\)|"(?:[^"\\]|\\.)*"|[^\s()"]+', text)


def parse(tokens):
    stack = [[]]
    for tok in tokens:
        if tok == "(":
            stack.append([])
        elif tok == ")":
            done = stack.pop()
            stack[-1].append(done)
        else:
            stack[-1].append(tok[1:-1] if tok.startswith('"') else tok)
    return stack[0][0]


def find(node, key):
    """Return all child lists that start with `key`."""
    return [c for c in node if isinstance(c, list) and c and c[0] == key]


def value_of(node, key, default=""):
    hits = find(node, key)
    return hits[0][1] if hits and len(hits[0]) > 1 else default


def load_netlist(path):
    with open(path, encoding="utf-8") as f:
        tree = parse(tokenize(f.read()))

    comp_section = find(tree, "components")
    net_section = find(tree, "nets")
    if not comp_section or not net_section:
        raise ValueError("not a KiCad netlist (missing 'components' or 'nets' section). "
                         "Export it with File -> Export -> Netlist, KiCad format.")

    components = {}
    for comp in find(comp_section[0], "comp"):
        ref = value_of(comp, "ref")
        lib = find(comp, "libsource")
        sheet = ""
        for prop in find(comp, "property"):
            if value_of(prop, "name") == "Sheetname":
                sheet = value_of(prop, "value")
        components[ref] = {
            "ref": ref,
            "value": value_of(comp, "value"),
            "part": value_of(lib[0], "part") if lib else "",
            "description": value_of(lib[0], "description") if lib else "",
            "sheet": sheet,
        }

    nets = {}
    for net in find(net_section[0], "net"):
        name = value_of(net, "name")
        nodes = []
        for n in find(net, "node"):
            nodes.append({
                "ref": value_of(n, "ref"),
                "pin": value_of(n, "pin"),
                "function": value_of(n, "pinfunction"),
                "type": value_of(n, "pintype"),   # input / output / power_in / passive ...
            })
        nets[name] = nodes

    return components, nets


# ---------------------------------------------------------------------------
# 2. Small knowledge base: pins whose job isn't obvious from the net name
#    (add your own chips here as the project grows)
# ---------------------------------------------------------------------------

KNOWN_PINS = {
    # part value             pin-function contains -> meaning
    "ComputeModule5-CM5": {
        "GPIO14_": "UART0 TX (Linux/bootloader debug console)",
        "GPIO15_": "UART0 RX (Linux/bootloader debug console)",
        "nRPIBOOT": "Forces USB boot (lets the eMMC be reflashed)",
        "EEPROM_nWP": "Boot EEPROM write-protect",
    },
    # RISC-V ESP32 variants: boot strap on GPIO9, built-in USB-Serial/JTAG on fixed pins.
    "ESP32-C6": {
        "IO9": "Boot-mode strap: held low at reset = download mode (firmware can be reflashed)",
        "TXD0": "UART0 TX (ROM bootloader / debug console)",
        "RXD0": "UART0 RX (ROM bootloader / debug console)",
        "IO12": "USB D- of the built-in USB-Serial/JTAG (programming and debug port)",
        "IO13": "USB D+ of the built-in USB-Serial/JTAG (programming and debug port)",
    },
    "ESP32-C3": {
        "IO9": "Boot-mode strap: held low at reset = download mode (firmware can be reflashed)",
        "TXD0": "UART0 TX (ROM bootloader / debug console)",
        "RXD0": "UART0 RX (ROM bootloader / debug console)",
        "IO18": "USB D- of the built-in USB-Serial/JTAG (programming and debug port)",
        "IO19": "USB D+ of the built-in USB-Serial/JTAG (programming and debug port)",
    },
    # ESP32-S3 (modules like ESP32-S3-WROOM-1). Listed before plain ESP32 so it matches first.
    "ESP32-S3": {
        "IO0": "Boot-mode strap: held low at reset = UART/USB download mode (firmware can be reflashed)",
        "TXD0": "UART0 TX (ROM bootloader / debug console)",
        "RXD0": "UART0 RX (ROM bootloader / debug console)",
        "IO19": "USB D- of the built-in USB-Serial/JTAG (programming and debug port)",
        "IO20": "USB D+ of the built-in USB-Serial/JTAG (programming and debug port)",
    },
    "ESP32": {
        "IO0": "Boot-mode strap: held low at reset = UART download mode (firmware can be reflashed)",
        "TXD0": "UART0 TX (ROM bootloader / debug console)",
        "RXD0": "UART0 RX (ROM bootloader / debug console)",
    },
    # ESP8266 modules (ESP-12E/F, ESP-07...) and the bare chip
    "ESP-12": {
        "GPIO0": "Boot-mode strap: held low at reset = UART download mode (firmware can be reflashed)",
        "GPIO15": "Boot-mode strap (must be low at reset; high = boot from SD card mode)",
        "GPIO2": "Boot-mode strap (must be high at reset)",
        "TXD": "UART0 TX (ROM bootloader / debug console)",
        "RXD": "UART0 RX (ROM bootloader / debug console)",
    },
    "ESP8266": {
        "GPIO0": "Boot-mode strap: held low at reset = UART download mode (firmware can be reflashed)",
        "GPIO15": "Boot-mode strap (must be low at reset; high = boot from SD card mode)",
        "GPIO2": "Boot-mode strap (must be high at reset)",
        "U0TXD": "UART0 TX (ROM bootloader / debug console)",
        "U0RXD": "UART0 RX (ROM bootloader / debug console)",
    },
    # STM32 (all families): SWD on PA13/PA14, JTAG on PA15/PB3/PB4, ROM bootloader on USART1.
    "STM32": {
        "PA13": "SWD SWDIO (programming/debug port)",
        "PA14": "SWD SWCLK (programming/debug port)",
        "PA15": "JTAG TDI (programming/debug port)",
        "PB3": "JTAG TDO / SWO trace output (debug)",
        "PB4": "JTAG nTRST (debug)",
        "BOOT0": "Boot-mode pin: high at reset = ROM bootloader (firmware can be read or reflashed over UART/USB)",
        "PA9": "USART1 TX (ROM bootloader / debug console)",
        "PA10": "USART1 RX (ROM bootloader / debug console)",
    },
    # Raspberry Pi RP2040 / RP2350 (Pico, Pico 2)
    "RP2040": {
        "SWCLK": "SWD clock (programming/debug port)",
        "SWD": "SWD data (programming/debug port)",
        "QSPI_SS": "Boot-mode pin (BOOTSEL): held low at reset = USB bootloader (firmware can be reflashed)",
        "GPIO0": "UART0 TX (default debug console)",
        "GPIO1": "UART0 RX (default debug console)",
    },
    "RP2350": {
        "SWCLK": "SWD clock (programming/debug port)",
        "SWDIO": "SWD data (programming/debug port)",
        "QSPI_SS": "Boot-mode pin (BOOTSEL): held low at reset = USB bootloader (firmware can be reflashed)",
        "GPIO0": "UART0 TX (default debug console)",
        "GPIO1": "UART0 RX (default debug console)",
    },
    # Nordic nRF52 series (Bluetooth LE)
    "nRF91": {
        "SWDCLK": "SWD clock (programming/debug port)",
        "SWDIO": "SWD data (programming/debug port)",
    },
    "nRF52": {
        "SWDCLK": "SWD clock (programming/debug port)",
        "SWDIO": "SWD data (programming/debug port)",
    },
    # Microchip SAM D21 (Arduino Zero, many Adafruit boards)
    "ATSAMD21": {
        "PA30": "SWD SWCLK (programming/debug port)",
        "PA31": "SWD SWDIO (programming/debug port)",
    },
    # Classic AVR: ISP programming shares the SPI pins; RESET doubles as debugWIRE.
    "ATmega32U4": {
        "PB2": "ISP MOSI (programming port, shared with SPI MOSI)",
        "PB3": "ISP MISO (programming port, shared with SPI MISO)",
        "PB1": "ISP SCK (programming port, shared with SPI SCK)",
        "RESET": "RESET / debugWIRE (programming/debug pin)",
        "PD3": "UART TX (serial console)",
        "PD2": "UART RX (serial console)",
    },
    "ATmega328": {
        "PB3": "ISP MOSI (programming port, shared with SPI MOSI)",
        "PB4": "ISP MISO (programming port, shared with SPI MISO)",
        "PB5": "ISP SCK (programming port, shared with SPI SCK)",
        "PC6": "RESET / debugWIRE (programming/debug pin)",
        "PD1": "UART TX (Arduino bootloader upload / serial console)",
        "PD0": "UART RX (Arduino bootloader upload / serial console)",
    },
    # tinyAVR 2-series (matched as a substring of the part value)
    "ATtiny3226": {
        "PA0": "UPDI programming/debug pin",
        "PB0": "I2C SCL",
        "PB1": "I2C SDA",
    },
}

# ---------------------------------------------------------------------------
# 3. Helper checks
# ---------------------------------------------------------------------------

# Headers, connectors, test points. ("X" is left out: KiCad uses it for crystals.)
EXPOSED_PREFIXES = ("J", "P", "CN", "CON", "TP", "USB", "JP", "ISP", "JTAG", "SWD", "HDR")
SWITCH_PREFIXES = ("SW", "S")
ESD_PARTS = ("RCLAMP", "TPD", "PUSB", "ESD", "TVS", "PESD", "USBLC")


def ref_prefix(ref):
    m = re.match(r"[A-Za-z]+", ref or "")
    return m.group(0).upper() if m else ""


def is_exposed(ref):
    return ref_prefix(ref) in EXPOSED_PREFIXES


# Plug-in development boards carry their own USB programming port, regulator and caps.
DEVBOARD = re.compile(r"DEVKIT|NODEMCU|WEMOS|D1[_ -]?MINI|LOLIN|ARDUINO|RASPBERRY_?PI_?PICO|\bPICO(_?W|_?2)?\b|"
                      r"BLUE_?PILL|BLACK_?PILL|FEATHER|XIAO|THING_?PLUS", re.I)


def is_devboard(ref, components):
    c = components.get(ref, {})
    return not is_exposed(ref) and bool(DEVBOARD.search(f"{c.get('value', '')} {c.get('part', '')}"))


def is_switch(ref):
    return ref_prefix(ref) in SWITCH_PREFIXES


def is_power_net(name):
    n = short(name).upper()
    # Status/sense signals named after a rail (e.g. VCC_SENSE, PWR_GOOD) are not rails.
    if re.search(r"SENSE|ERR|DETECT|GOOD|_EN\b|\bPG\b", n):
        return False
    # Signals named after their voltage level (UART_RX_3V3, SPI_CLK_3V3, NCS_3G_3V3) are not rails.
    if re.search(r"(^|_)(N?CS|UART|TXD?|RXD?|SPI|CLK|SCK|MISO|MOSI|SDA|SCL|DATA|IRQ|INT|RST|RESET)(_|$)", n):
        return False
    return (n.startswith("+") or "VBUS" in n or n.startswith("VCC")
            or n.startswith("VDD") or n.endswith("V") or "_3V3" in n or "BATT" in n)


def short(name):
    return name.split("/")[-1].replace("{slash}", "/")


def nice_net(name):
    """Turn KiCad auto-names like 'Net-(U20-VCC)' into 'U20 VCC pin'."""
    m = re.match(r"^Net-\((\w+)-(.+)\)$", name)
    if not m:
        return short(name)
    pin = m.group(2).replace("{slash}", "/")
    return f"{m.group(1)} pad {pin[3:]}" if pin.startswith("Pad") else f"{m.group(1)} {pin} pin"


# Cellular modems by model: Quectel, SIMCom, u-blox, Telit, Sierra, Nordic nRF91, Sequans, Sony Altair.
CELL_MODEL = re.compile(
    r"\b(SIM(5\d{3}|7\d{3}|8\d{2}|9\d{2})\w*|A76\d\d\w*|BG(7\d|9\d|600L?)\w*|BC(6[068]|9[25])\w*|"
    r"EC2[015]\w*|EG(2[15]|9[15]|915)\w*|M95|M66|UC(15|20)|RM5\d\d\w*|EM0[56]\w*|"
    r"SARA-\w+|LARA-\w+|LENA-\w+|TOBY-\w+|UL865\w*|[LM]E910\w*|HL78\d\d\w*|WP76\d\d\w*|"
    r"NRF91\d\d\w*|GM02S\w*|ALT1250\w*)\b", re.I)
CELL_WORDS = re.compile(r"\b(CELLULAR|LTE|GSM|NB-?IOT|CAT-?M1?)\b.*\bMODULE\b|\bMODEM\b", re.I)


def is_cellular(ref, components):
    c = components.get(ref, {})
    return (ref_prefix(ref) not in EXPOSED_PREFIXES
            and bool(CELL_MODEL.search(f"{c.get('value', '')} {c.get('part', '')}")
                     or CELL_WORDS.search(c.get("description", ""))))


# Service pins that every modem family has under similar names.
MODEM_PINS = [
    (r"USB_D[PMN+-]", "Modem USB port (AT commands, diagnostics and firmware update: a programming/debug port)"),
    (r"DBG_?(TXD|RXD)|(TXD|RXD)_?DBG|DEBUG_?(TX|RX)D?", "Modem debug UART (debug console)"),
    (r"USB_BOOT|BOOT_CFG\d?", "Boot-mode pin: forces the modem into firmware download mode (modem firmware can be replaced)"),
    (r"(MAIN_|UART1?_)?(TXD|RXD)|C10[34]/(TXD|RXD)", "Modem AT command UART (send SMS, change APN, read SIM and network data)"),
]


def meaning_of(node, components):
    part = components.get(node["ref"], {}).get("value", "").upper()
    pins = next((p for chip, p in KNOWN_PINS.items() if chip.upper() in part), {})
    for key, meaning in pins.items():
        # "GPIO1" must not match "GPIO10", so a key ending in a digit can't be followed by one.
        tail = r"(?!\d)" if key[-1].isdigit() else ""
        if re.search(re.escape(key) + tail, node["function"]):
            return meaning
    if is_cellular(node["ref"], components):
        name = pin_name(node)
        for pattern, meaning in MODEM_PINS:
            if re.fullmatch(pattern, name, re.I):
                return meaning
    return None


# ---------------------------------------------------------------------------
# 4. Rules - each one returns a list of findings
# ---------------------------------------------------------------------------

PROG_PIN = re.compile(r"\b(ICSP\w*|PGC\d?|PGD\d?|SWDIO|SWCLK|TCK|TMS|TDI|TDO|nTRST|MCLR|UPDI|PDI_?DATA)\b", re.I)


# Connectors that are a board's normal interface to its host (e.g. a module's "Host" header).
HOST_CONNECTOR = re.compile(r"\b(HOST|MAIN|MAINBOARD|EXT|EXTERNAL|INTERFACE|UEXT|MIKRO_?BUS)\b", re.I)


def rule_debug_ports(components, nets):
    findings = []
    pattern = re.compile(r"UART|_TX|_RX|TXD|RXD|SWD|SWCLK|SWDIO|JTAG|TCK|TMS|TDI|TDO|UPDI|CONSOLE|DEBUG", re.I)
    for name, nodes in nets.items():
        meanings = [m for m in (meaning_of(n, components) for n in nodes)
                    if m and re.search(r"UART|UPDI|debug|programming", m) and "Boot-mode" not in m]
        prog = [f"{n['ref']}.{pin_name(n)}" for n in nodes if PROG_PIN.search(pin_name(n))]
        if re.search(r"UPDI|ICSP|SWD|JTAG", short(name), re.I) or any("programming" in m for m in meanings):
            prog = prog or [f"{n['ref']}.{pin_name(n)}" for n in nodes if not is_exposed(n["ref"])]
        if not (pattern.search(name) or meanings or prog):
            continue
        if name.startswith("unconnected"):
            continue
        exposed = sorted({n["ref"] for n in nodes if is_exposed(n["ref"])})
        if meanings:
            label = meanings[0]
        elif prog:
            label = "programming/debug pin " + ", ".join(prog)
        else:
            label = "debug-looking signal"
        # A UART that only goes to the board's host/main connector is usually the intended link, not a console.
        host_link = (not meanings and not prog and exposed
                     and all(HOST_CONNECTOR.search(components.get(r, {}).get("value", "")) for r in exposed))
        if host_link:
            findings.append(("INFO", f"UART {nice_net(name)} goes to the host interface "
                             f"{', '.join(connector_name(r, components) for r in exposed)}",
                             "This looks like the intended link to the main board, not a debug port. Make sure the "
                             "firmware offers no console or command shell on it without authentication."))
        elif exposed:
            fix = ("Anyone with access can read out or reprogram the chip. Remove the header/pad on production "
                   "boards and enable code/read protection." if prog else
                   "Remove the header/pad on production boards or disable the console in firmware.")
            findings.append(("HIGH", f"Debug interface {nice_net(name)} ({label}) reaches {', '.join(exposed)}", fix))
        else:
            findings.append(("OK", f"{nice_net(name)} ({label}) is not routed to any header or test point", ""))

    # Programming headers recognised by the connector itself (e.g. ISP1 "AVRISP-6"),
    # unless one of their pins was already reported above.
    reported = {r for f in findings if f[0] == "HIGH" for r in re.findall(r"reaches (.*)$", f[1])[0].split(", ")}
    for ref, comp in components.items():
        text = f"{ref_prefix(ref)} {comp['value']} {comp['part']}"
        if (is_exposed(ref) and ref not in reported
                and re.search(r"\b(ISP|AVRISP\w*|ICSP|JTAG|SWD|UPDI|PDI|TAG-?CONNECT)\b", text, re.I)):
            pins = sorted({short(net) for net in nets_by_ref(nets)[ref]
                           if not (is_ground(net) or is_power_net(net) or net.startswith(("Net-", "unconnected")))})
            findings.append(("HIGH", f"Programming header {ref} ({comp['value']})"
                             + (f" carries {', '.join(pins)}" if pins else ""),
                             "Anyone with access can read out or reprogram the chip. Remove the header on production "
                             "boards and set the lock/read-protection bits."))

    for ref in sorted(r for r in components if is_devboard(r, components)):
        findings.append(("HIGH", f"{ref} ({components[ref]['value']}) is a development board with a built-in USB "
                         "programming port (USB-serial bridge with auto-reset, or native USB bootloader)",
                         "Anyone with access to the board can plug in a USB cable and dump or replace the firmware. "
                         "Use a bare module on production boards, or enable secure boot and flash encryption."))
    return findings


WIRELESS = re.compile(r"\b(BT|BLE|BLUETOOTH|WI-?FI|WIFI|WLAN|ESP\d*\w*|LORA\w*|ZIGBEE|GSM|LTE|NB-?IOT|NRF\d+\w*|"
                      r"HC-?0[56]|RFM\d+\w*|CC\d{4}|SIM\d{3,4}\w*|XBEE)\b", re.I)


def rule_wireless(components, nets):
    """Radios (or headers for radio modules) give a remote attack surface."""
    radios = defaultdict(set)              # part/header -> signals it uses
    for ref, comp in components.items():
        if WIRELESS.search(f"{comp['value']} {comp['part']} {comp['description']}") \
                and not is_cellular(ref, components) \
                and not (ref_prefix(ref) in ("AE", "ANT") or "ANTENNA" in f"{comp['value']} {comp['part']}".upper()):
            # modems have their own check; antennas are passive parts, not radios
            radios[ref]
    for name, nodes in nets.items():
        # A chip select or enable named after a radio (nCS_WIFI, BT_EN) doesn't make a header a radio link.
        if re.search(r"(^|_)(N?CS|EN|RST|RESET|PWR|IRQ|INT|LED)(_|$)", short(name), re.I):
            continue
        if WIRELESS.search(short(name).replace("-", " ").replace("_", " ")):
            for n in nodes:
                if is_exposed(n["ref"]) or n["ref"] in radios:
                    radios[n["ref"]].add(short(name))
    findings = []
    for ref, sigs in sorted(radios.items()):
        uart = sorted(s for s in sigs if re.search(r"TX|RX", s, re.I))
        link = f" over UART ({', '.join(uart)})" if uart else (f" ({', '.join(sorted(sigs)[:5])})" if sigs else "")
        findings.append(("MEDIUM", f"Wireless module/header {ref} ({components[ref]['value']}) talks to the board{link}",
                         "This is a remote attack surface: anyone in radio range can reach the firmware. Require "
                         "pairing/authentication, validate every command, and keep the module's firmware updated."))
    return findings


TWO_G_ONLY = re.compile(r"\b(SIM8\d\d\w*|SIM9\d\d\w*|M95|M66)\b", re.I)


def rule_cellular(components, nets):
    """Cellular modems: the device can be reached from anywhere, not just within radio range."""
    findings = []
    for ref in sorted(r for r in components if is_cellular(r, components)):
        comp = components[ref]
        findings.append(("MEDIUM", f"Cellular modem {ref} ({comp['value']}) puts the device on the mobile network: "
                         "reachable from anywhere, not just within radio range",
                         "Use a private APN or carrier firewall so the device has no open ports on the internet, "
                         "use TLS with certificate checks, ignore SMS commands, and keep the modem firmware updated."))
        if TWO_G_ONLY.search(f"{comp['value']} {comp['part']}"):
            findings.append(("LOW", f"{ref} ({comp['value']}) is 2G-only: 2G doesn't authenticate the network, so a "
                             "fake base station can intercept or inject traffic",
                             "Use end-to-end encryption (TLS) for everything. For new designs pick an LTE-M/NB-IoT "
                             "modem; 2G networks are also being switched off."))
    return findings


SIM_DATA_PIN = re.compile(r"U?SIM\d?_?(DATA|IO|I/O)", re.I)
SOLDERED_SIM = re.compile(r"\bE?SIM\b|\bSIM[-_]|UICC|MFF2", re.I)


def rule_sim(components, nets):
    """Removable SIM cards can be pulled out and used elsewhere; soldered eSIMs can't."""
    findings = []
    by_ref = nets_by_ref(nets)
    for modem in sorted(r for r in components if is_cellular(r, components)):
        data_nets = sorted({net for net in by_ref[modem] for x in nets[net]
                            if x["ref"] == modem and SIM_DATA_PIN.fullmatch(pin_name(x))})
        near = set()
        for net in data_nets:
            refs = {x["ref"] for x in nets[net]} - {modem}
            for r in list(refs):                 # look through a series resistor (usually 22R)
                if ref_prefix(r) == "R":
                    refs |= {x["ref"] for other in by_ref[r] - {net} if not is_ground(other) for x in nets[other]}
            near |= refs - {modem}
        holders = sorted(r for r in near if is_exposed(r) and ref_prefix(r) != "TP")
        soldered = sorted(r for r in near if not is_exposed(r) and not is_cellular(r, components)
                          and SOLDERED_SIM.search(part_text(r, components)))
        if holders:
            findings.append(("LOW", f"SIM card holder {short_list(holders)} for {modem} takes a removable SIM: it can be "
                             "taken out and used in another device" +
                             (f" (a soldered eSIM {short_list(soldered)} is also fitted)" if soldered else ""),
                             "Someone could use the data plan, or talk to your backend as this device if it trusts the "
                             "SIM. Prefer a soldered eSIM/MFF2, set a SIM PIN, and ask the carrier to lock the SIM "
                             "to this device's IMEI."))
        elif soldered:
            findings.append(("OK", f"{modem} uses a soldered SIM/eSIM ({short_list(soldered)}), which can't simply "
                             "be pulled out", ""))
    return findings


def rule_boot_pins(components, nets):
    findings = []
    for name, nodes in nets.items():
        # Prefer the chip pin that is the boot pin (it carries the description) over a test pad on the same net.
        boot_node = next((n for n in nodes if "Boot-mode" in (meaning_of(n, components) or "")), None) \
            or next((n for n in nodes if re.search(r"BOOT|STRAP", n["function"] + name, re.I)), None)
        if not boot_node or name.startswith("unconnected"):
            continue
        reach = [n["ref"] for n in nodes if is_exposed(n["ref"]) or is_switch(n["ref"])]
        # One step through a transistor, e.g. the DTR/RTS auto-programming circuit on ESP32 boards
        by_ref = nets_by_ref(nets)
        for n in nodes:
            if ref_prefix(n["ref"]) == "Q" or "TRANSISTOR" in part_text(n["ref"], components):
                for other in sorted(by_ref[n["ref"]] - {name}):
                    if is_ground(other) or is_power_net(other):
                        continue
                    hits = sorted({m["ref"] for m in nets[other] if is_exposed(m["ref"])})
                    reach += [f"{h} (via {n['ref']}, {short(other)})" for h in hits]
        reach = list(dict.fromkeys(reach))
        label = meaning_of(boot_node, components) or "boot-mode pin"
        if reach:
            findings.append(("MEDIUM", f"Boot pin {nice_net(name)} ({label}) can be driven from {', '.join(reach)}",
                             "Fine for dev boards. On products, remove the switch or lock boot mode with OTP/secure boot."))
    return findings


def rule_write_protect(components, nets):
    findings = []
    for name, nodes in nets.items():
        # Pin names may carry KiCad overbar markup, e.g. "~{WP}" or "~{WP}/IO2".
        wp_pins = [n for n in nodes if re.match(r"N?WP\b|WRITE_PROT", re.sub(r"[~{}]", "", pin_name(n)), re.I)]
        if not (re.search(r"N?WP\b|WRITE_PROT", short(name), re.I) or wp_pins):
            continue
        if name.startswith("unconnected"):
            pin = f"{wp_pins[0]['ref']}.{pin_name(wp_pins[0])}" if wp_pins else short(name)
            findings.append(("MEDIUM", f"Write-protect pin {pin} is left unconnected",
                             "Most EEPROMs/flash then default to writable, so anyone on the bus can overwrite them. "
                             "Tie WP high if the contents must be protected."))
            continue
        others = [n["ref"] for n in nodes if not n["ref"].startswith(("Module", "U"))]
        exposed = [r for r in others if is_exposed(r)]
        memories = {n["ref"] for n in wp_pins}
        drivers = sorted({n["ref"] for n in nodes if n["ref"].startswith(("Module", "U")) and n["ref"] not in memories})
        if not others and memories and drivers:
            findings.append(("OK", f"Write-protect {short(name)} is driven by {short_list(drivers)} "
                             "(set by firmware)", ""))
        elif not others:
            findings.append(("HIGH", f"Write-protect {short(name)} is floating", "Tie it to a defined level."))
        elif exposed:
            findings.append(("MEDIUM", f"Write-protect {short(name)} reachable from {', '.join(exposed)}",
                             "Someone could change the protection state from outside."))
        else:
            findings.append(("OK", f"Write-protect {short(name)} is tied via {', '.join(others)}", ""))
    return findings


def rule_power_testpoints(components, nets):
    findings = []
    for name, nodes in nets.items():
        if not is_power_net(name):
            continue
        tps = [n["ref"] for n in nodes if ref_prefix(n["ref"]) == "TP"]
        if tps:
            findings.append(("LOW", f"Power rail {short(name)} exposed on test point(s) {', '.join(tps)}",
                             "Easy access for voltage-glitch attacks. Consider removing or covering on production boards."))
    return findings


def rule_exposed_buses(components, nets):
    headers = defaultdict(list)
    pattern = re.compile(r"(^|[_.])(MOSI|MISO|SCLK|SCK|CS|SDA\d?|SCL\d?)($|[_.])", re.I)
    for name, nodes in nets.items():
        # Bus signal either by net name, or by what the chip pin is (e.g. ATtiny PB1 = I2C SDA)
        bus_meaning = next((m for m in (meaning_of(n, components) for n in nodes)
                            if m and re.search(r"I2C|SPI", m)), None)
        if not (pattern.search(short(name)) or bus_meaning):
            continue
        label = short(name) if pattern.search(short(name)) else f"{bus_meaning} ({short(name)})"
        for n in nodes:
            if is_exposed(n["ref"]):
                headers[n["ref"]].append(label)
    return [("INFO", f"{ref} ({components.get(ref, {}).get('value', '')}) exposes bus signals: {', '.join(sorted(sigs))}",
             "Anything on this bus (sensors, EEPROMs, flash) can be read or spoofed by a device plugged in here.")
            for ref, sigs in headers.items()]


def rule_usb_esd(components, nets):
    findings = []
    for name, nodes in nets.items():
        if not re.search(r"USB.*(D_?[NP]|D[+-]|DP|DM)$", short(name), re.I):
            continue
        if not any(is_exposed(n["ref"]) for n in nodes):
            continue
        protected = [n["ref"] for n in nodes
                     if any(p in components.get(n["ref"], {}).get("value", "").upper() for p in ESD_PARTS)]
        if protected:
            findings.append(("OK", f"USB line {short(name)} has ESD protection ({', '.join(protected)})", ""))
        else:
            findings.append(("MEDIUM", f"USB line {short(name)} goes to a connector with no ESD protection",
                             "Add a TVS/ESD diode array close to the connector."))
    return findings


DIGITAL_HINTS = re.compile(r"GPIO|UART|TXD|RXD|_TX|_RX|MOSI|MISO|SCLK|SDA|SCL|USB|JTAG|SWD|BOOT|nRST|RESET"
                           r"|ICSP|MCLR|\bRB\d|\bGP\d|\bTCK|\bTMS|\bTDI|\bTDO|UPDI|\bP[A-F]\d\b", re.I)


def digital_signals(nets):
    """Return the names of nets that look like digital interfaces (by net name or chip pin name)."""
    return sorted({short(name) for name, nodes in nets.items()
                   if not name.startswith("unconnected")
                   and (DIGITAL_HINTS.search(short(name)) or any(DIGITAL_HINTS.search(pin_name(n)) for n in nodes))})


# ---------------------------------------------------------------------------
# 4b. Analog rules - these work on any board, digital or not
# ---------------------------------------------------------------------------

PROTECTION_PARTS = ESD_PARTS + ("ZENER", "SMBJ", "SMAJ", "SMF", "BAT54", "BAV99", "1N4", "SS1", "SS3")
SERIES_PREFIXES = ("R", "C", "L", "FB", "F")
# Supply pin names like VCC, VDD_IO, AVDD, V+ (but not e.g. "Vsw", a switching pin).
POWER_PIN = re.compile(r"^(A|D|P)?(VCC|VDD|VEE|VIN|VBAT|VS|V\+|V-)(A|IO|Q)?(?![A-Za-z])", re.I)


def part_text(ref, components):
    c = components.get(ref, {})
    return " ".join((c.get("value", ""), c.get("part", ""), c.get("description", ""))).upper()


def is_ground(name):
    return bool(re.search(r"GND|VSS|^0$", short(name), re.I))


def is_led(ref, components):
    t = part_text(ref, components)
    return "LED" in t or bool(re.search(r"\b(RED|GREEN|BLUE|YELLOW|WHITE|AMBER|ORANGE)\b|WS28\d\d|SK68\d\d|"
                                        r"APA10\d|NEOPIXEL", t))


def is_protection(ref, components):
    if is_led(ref, components):
        return False
    return ref_prefix(ref) in ("D", "TVS", "ESD") or any(p in part_text(ref, components) for p in PROTECTION_PARTS)


def is_fuse(ref, components):
    t = part_text(ref, components)
    return ref_prefix(ref) in ("F", "PTC") or "FUSE" in t or "POLYFUSE" in t or "PTC" in t


def is_active_pin(node):
    """A pin on a chip/transistor that actually drives or reads the signal."""
    t = node["type"]
    return t != "" and not t.startswith("passive") and "no_connect" not in t


def nets_by_ref(nets):
    index = defaultdict(set)
    for name, nodes in nets.items():
        for n in nodes:
            index[n["ref"]].add(name)
    return index


def pin_name(node):
    return re.sub(r"_\d+$", "", node["function"]) or node["pin"]


def short_list(items, limit=6):
    items = sorted(set(items), key=lambda s: (ref_prefix(s), int(re.sub(r"\D", "", s) or 0), s))
    return ", ".join(items[:limit]) + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


# ---- Mains (high-voltage) awareness -------------------------------------------

MAINS_NAME = re.compile(r"(\b|_)(1[0-2]\d|2[2-4]\d)\s?V(AC)?(\b|_)|MAINS|\bLIVE|NEUTRAL|\bVAC\b|\bAC_?[LN]\b", re.I)


def is_relay(ref):
    return ref_prefix(ref) == "K"


def is_coil_pin(node):
    return bool(re.fullmatch(r"A[12]|COIL\w*|[+-]", pin_name(node), re.I))


def is_triac(ref, components):
    t = part_text(ref, components)
    return "TRIAC" in t or bool(re.search(r"\bBT[AB]?\d{2,3}|\bBT1\d{2}|OFF-STATE VOLTAGE", t))


# Solid-state relays: an LED input on the logic side, a triac/MOSFET output on the mains side.
SSR_PART = re.compile(r"\bSSR\b|SOLID.?STATE|\bG3M[BC]|\bG3NA|\bAQ[GH]\d|\bS[12]0[1-9]S|\bCPC1\d{3}", re.I)
SSR_CONTROL_PIN = re.compile(r"^([+-]|DC[+-]?|IN[+-]?|CTRL|CONTROL|A|K|LED[+-]?)$", re.I)


def is_ssr(ref, components):
    return not is_exposed(ref) and bool(SSR_PART.search(part_text(ref, components)))


def is_ac_input(node):
    """AC input pin of a power module (e.g. HLK-PM01 'AC/L', 'AC/N')."""
    return bool(re.match(r"^AC", pin_name(node), re.I)) and node["type"] == "power_in"


def mains_nets(components, nets):
    """Nets that carry mains voltage: named like mains, PSU AC inputs, relay contacts,
    triac main terminals - then spread through fuses, solid-state relay outputs and
    every pin of a connector that touches them."""
    found = set()
    for name, nodes in nets.items():
        if name.startswith("unconnected"):
            continue
        # A power module's AC input is mains even when the net is named like ground (e.g. neutral "GNDREF").
        if any(is_ac_input(n) for n in nodes):
            found.add(name)
            continue
        if is_ground(name) or is_power_net(name):
            continue
        if MAINS_NAME.search(short(name)):
            found.add(name)
            continue
        for n in nodes:
            if (is_relay(n["ref"]) and not is_coil_pin(n)) \
                    or (is_triac(n["ref"], components) and pin_name(n).upper() not in ("G", "GATE")):
                found.add(name)
                break
    by_ref = nets_by_ref(nets)

    def skip(net):
        return is_ground(net) or is_power_net(net) or net.startswith("unconnected")

    def mains_side_only(net, ref):
        """Net of an SSR output: everything else on it is a connector, fuse or another switch."""
        others = [m["ref"] for m in nets[net] if m["ref"] != ref]
        return others and all(is_exposed(o) or is_fuse(o, components) or is_ssr(o, components) or is_relay(o)
                              for o in others)

    changed = True
    while changed:
        changed = False
        for ref, ref_nets in by_ref.items():
            if not ref_nets & found:
                continue
            new = []
            if is_exposed(ref):                             # a connector with one mains pin is a mains connector
                new = [net for net in ref_nets - found if not skip(net)]
            elif is_fuse(ref, components) and len(ref_nets) == 2:   # mains passes through a fuse
                new = [net for net in ref_nets - found if not skip(net)]
            elif is_ssr(ref, components):                   # SSR output side switches mains to the load
                for net in sorted(ref_nets - found):
                    pins = [m for m in nets[net] if m["ref"] == ref]
                    if not skip(net) and not any(SSR_CONTROL_PIN.match(pin_name(p)) for p in pins) \
                            and mains_side_only(net, ref):
                        new.append(net)
            if new:
                found.update(new)
                changed = True
    return found


def interface_points(components, nets):
    """Where signals enter/leave the board: connector pins, or (for a sub-module
    with no connectors) named nets that dangle off the sheet. Mains nets are
    left to the mains rule."""
    points = defaultdict(list)          # label -> [net names]
    mains = mains_nets(components, nets)
    for name, nodes in nets.items():
        if name.startswith("unconnected") or is_ground(name) or is_power_net(name) or name in mains:
            continue
        for n in nodes:
            mechanical = re.match(r"^(MP|SH|SHIELD|MH)\d*$", pin_name(n), re.I)
            if is_exposed(n["ref"]) and ref_prefix(n["ref"]) != "TP" and not mechanical:
                if name not in points[n["ref"]]:
                    points[n["ref"]].append(name)
    if points:
        return points, False
    for name, nodes in nets.items():
        if (not name.startswith(("Net-", "unconnected")) and not is_ground(name)
                and not is_power_net(name) and len(nodes) == 1):
            points[f"port {short(name)}"].append(name)
    return points, True


def protection_near(net, nets, components, by_ref, skip_ref):
    """Protection parts on this net, or one series part away from it."""
    found = [n["ref"] for n in nets[net] if n["ref"] != skip_ref and is_protection(n["ref"], components)]
    for n in nets[net]:
        if ref_prefix(n["ref"]) in SERIES_PREFIXES:
            for other in sorted(by_ref[n["ref"]] - {net}):
                if not is_ground(other):
                    found += [m["ref"] for m in nets[other] if is_protection(m["ref"], components)]
    return found


def rule_signal_protection(components, nets):
    findings = []
    by_ref = nets_by_ref(nets)
    points, is_module = interface_points(components, nets)
    module_low = []
    for label, net_names in points.items():
        direct, series, clamps = [], [], []
        used_nets, clamped_nets = 0, 0
        unclamped = []                  # (net, parts it connects to) for lines without clamps
        for net in net_names:
            others = [n for n in nets[net] if n["ref"] != label]
            if not others:
                continue
            used_nets += 1
            unclamped_direct = [f"{n['ref']}.{pin_name(n)}" for n in others
                                if is_active_pin(n) and n["type"] != "power_in" and not is_exposed(n["ref"])]
            series += [n["ref"] for n in others if ref_prefix(n["ref"]) in SERIES_PREFIXES]
            here = protection_near(net, nets, components, by_ref, label)
            if here:
                clamped_nets += 1
                clamps += here
            else:
                direct += unclamped_direct
                unclamped.append((nice_net(net), [n["ref"] for n in others]))
        name = label if is_module else f"{label} ({components.get(label, {}).get('value', '')})"
        if used_nets == 0:
            continue
        if clamped_nets == used_nets:
            findings.append(("OK", f"{name} signals have clamp/ESD protection ({short_list(clamps)})", ""))
        elif clamped_nets and not direct:
            lines = ", ".join(f"{net} -> {short_list(refs, 3)}" for net, refs in unclamped[:4])
            more = f" (+{len(unclamped) - 4} more)" if len(unclamped) > 4 else ""
            findings.append(("LOW", f"{name}: only {clamped_nets} of {used_nets} signal lines have clamps "
                             f"({short_list(clamps)}). Unclamped: {lines}{more}",
                             "Add clamp diodes or a TVS array covering every signal pin on the connector."))
        elif direct:
            findings.append(("MEDIUM", f"{name} is wired straight into chip pins {short_list(direct)}",
                             "Noise, ESD or an injected signal hits the chip directly. Add a series resistor "
                             "and clamp diodes/TVS at the connector."))
        elif series and is_module:
            module_low.append((short(label), series))
        elif series:
            findings.append(("LOW", f"{name} passes through {short_list(series)} only - no clamp diodes",
                             "The series part limits current but won't stop ESD or overvoltage. "
                             "Add clamp diodes or a TVS at the connector."))
    if module_low:
        ports = [p.replace("port ", "") for p, _ in module_low]
        parts = [r for _, s in module_low for r in s]
        findings.append(("LOW", f"Module ports {short_list(ports, 8)} go through {short_list(parts)} with no clamp diodes",
                         "Fine if the parent board protects its connectors; otherwise add clamps here."))
    return findings


def rule_power_input(components, nets):
    findings = []
    by_ref = nets_by_ref(nets)
    for name, nodes in nets.items():
        if not is_power_net(name) or is_ground(name):
            continue
        entry = [n["ref"] for n in nodes if is_exposed(n["ref"]) and ref_prefix(n["ref"]) != "TP"]
        if not entry:
            continue
        fuses = [n["ref"] for n in nodes if is_fuse(n["ref"], components)]
        diodes = [n["ref"] for n in nodes if is_protection(n["ref"], components)]
        chips = sorted({n["ref"] for n in nodes if is_active_pin(n) and not is_exposed(n["ref"])})
        # On-board parts that produce this rail: regulator outputs, or a transistor switching it.
        sources = {n["ref"] for n in nodes if not is_exposed(n["ref"])
                   and (n["type"] == "power_out" or ref_prefix(n["ref"]) == "Q"
                        # regulator output pins that the symbol left as "passive"
                        or (re.fullmatch(r"V?OUT(PUT)?[PS]?|VO", pin_name(n), re.I)
                            and re.search(r"REGULATOR|LDO|CONVERTER|BUCK|BOOST", part_text(n["ref"], components)))
                        # a dev board's 3V3 pin is the output of its own regulator
                        or (is_devboard(n["ref"], components)
                            and re.search(r"3V3|3\.3V", f"{pin_name(n)} {short(name)}", re.I)))}
        # Switching regulators: chip SW/LX pin -> inductor -> this rail
        for n in nodes:
            if ref_prefix(n["ref"]) == "L":
                for other in sorted(by_ref[n["ref"]] - {name}):
                    sources |= {m["ref"] for m in nets[other]
                                if ref_prefix(m["ref"]) == "U" and re.fullmatch(r"SW\d?|LX\d?|PH", pin_name(m), re.I)}
        sources = sorted(sources)
        # A connector whose pins are "power_in" draws power from us, so this rail is an output.
        connector_draws = all(n["type"] == "power_in" for n in nodes
                              if is_exposed(n["ref"]) and ref_prefix(n["ref"]) != "TP")
        if connector_draws and not sources:
            via = [n["ref"] for n in nodes if ref_prefix(n["ref"]) in ("L", "FB", "R")]
            findings.append(("OK", f"Power output {short(name)} to {short_list(entry)} is generated on the board"
                             + (f" (via {short_list(via)})" if via else ""), ""))
            continue
        if sources:
            # The board makes this rail and sends it OUT to the connector.
            if all(ref_prefix(s) in ("U", "Q", "IC") for s in sources):
                findings.append(("OK", f"Power output {short(name)} to {short_list(entry)} comes through "
                                 f"{short_list(sources)} (switch/regulator, can limit a short)", ""))
            else:
                loads = [c for c in chips if c not in sources]
                findings.append(("LOW", f"Rail {short(name)} (made by {short_list(sources)}) is brought out on "
                                 f"{short_list(entry)}" + (f" and also feeds {short_list(loads)}" if loads else ""),
                                 "A short or injected voltage on that pin hits the rail directly. "
                                 "Consider a PTC, series resistor or load switch on connector power pins."))
            continue
        where = f"{short(name)} from {short_list(entry)}"
        if fuses or diodes:
            findings.append(("OK", f"Power input {where} has protection ({short_list(fuses + diodes)})", ""))
        elif chips:
            findings.append(("MEDIUM", f"Power input {where} feeds {short_list(chips)} directly - "
                             "no fuse, reverse-polarity diode or TVS",
                             "A wrong adapter, reversed plug or deliberate voltage spike reaches the chips. "
                             "Add a series diode/P-FET, a TVS and a fuse or PTC."))
        else:
            findings.append(("LOW", f"Power input {where} has no fuse, reverse-polarity diode or TVS",
                             "Add reverse-polarity and overvoltage protection at the power entry."))
    return findings


def rule_decoupling(components, nets):
    findings = []
    mains = mains_nets(components, nets)    # mains inputs need fuses/MOVs, not 100nF caps
    for name, nodes in nets.items():
        if is_ground(name) or name.startswith("unconnected") or name in mains:
            continue
        supplied = sorted({n["ref"] for n in nodes
                           if ref_prefix(n["ref"]) not in SERIES_PREFIXES + ("J", "P", "TP")
                           and (n["type"] == "power_in" or POWER_PIN.match(pin_name(n)))})
        if not supplied:
            continue
        caps = [n["ref"] for n in nodes if ref_prefix(n["ref"]) == "C"]
        filters = [n["ref"] for n in nodes if ref_prefix(n["ref"]) in ("L", "FB")]
        if caps:
            extra = f" and filter {short_list(filters)}" if filters else ""
            findings.append(("OK", f"Supply {nice_net(name)} to {short_list(supplied)} is decoupled by "
                             f"{short_list(caps)}{extra}", ""))
        elif all(ref_prefix(s) == "MODULE" or is_devboard(s, components) for s in supplied):
            findings.append(("LOW", f"Supply {nice_net(name)} to {short_list(supplied)} has no decoupling capacitor",
                             "Modules usually carry their own caps, but a 100nF here makes glitching harder."))
        else:
            findings.append(("MEDIUM", f"Supply {nice_net(name)} to {short_list(supplied)} has no decoupling capacitor",
                             "Supply glitches and noise reach the chip unfiltered (easier fault injection). "
                             "Add a 100nF cap close to each supply pin."))
    return findings


def connector_name(ref, components):
    v = components.get(ref, {}).get("value", "")
    return f"{v} ({ref})" if v and not re.match(r"^(Conn|PRG|Screw_Terminal)", v, re.I) else ref


LOAD_WORDS = re.compile(r"\b(SSR|RELAY|HEATER|HEAT|MOTOR|PUMP|VALVE|SOLENOID|LOCK|COMPRESSOR|MAGNETRON|"
                        r"DOOR|OPENER|STRIKE|LATCH|BOILER|KETTLE|OVEN|GRINDER|ROASTER)\b", re.I)


def external_loads(components, nets, skip=()):
    """Headers that drive an external power stage (e.g. an SSR for a heater). `skip`: mains connectors,
    which the mains rule already covers."""
    by_ref = nets_by_ref(nets)
    found = []
    for ref, comp in sorted(components.items()):
        if not is_exposed(ref) or ref in skip:
            continue
        sigs = sorted({short(n) for n in by_ref[ref] if LOAD_WORDS.search(short(n).replace("_", " "))})
        if LOAD_WORDS.search(comp["value"].replace("_", " ")) or sigs:
            found.append(f"{connector_name(ref, components)}" + (f" ({', '.join(sigs)})" if sigs else ""))
    if not found:
        return []
    return [("MEDIUM", "Firmware drives an external power load (relay/SSR/heater/motor) through " + "; ".join(found)
             + " - no hardware interlock on this board",
             "If the firmware hangs, is buggy or is compromised, the load can stay on (e.g. a heater running away). "
             "Add an independent hardware cutoff: thermal fuse/thermostat in the load path or a watchdog-driven "
             "enable.")]


def rule_mains(components, nets):
    """Mains entry protection, isolation, and which mains loads the firmware controls (cyber-physical)."""
    mains = mains_nets(components, nets)
    if not mains:
        return external_loads(components, nets)
    findings = []
    by_ref = nets_by_ref(nets)
    connectors = sorted({n["ref"] for net in mains for n in nets[net] if is_exposed(n["ref"])})

    # 1. Mains entry: connector named like a mains input, or sharing a net with a fuse.
    def on_fuse_net(ref):
        return any(is_fuse(n["ref"], components) for net in by_ref[ref] for n in nets[net])
    entry = [c for c in connectors
             if re.search(r"(\d{3}V|MAINS|AC|LINE).*IN|IN.*(\d{3}V|MAINS|AC)", components[c]["value"], re.I)]
    entry = entry or [c for c in connectors if on_fuse_net(c)]
    entry_nets = {net for c in entry for net in by_ref[c]}
    for net in list(entry_nets):            # look one fuse beyond the connector too
        for n in nets[net]:
            if is_fuse(n["ref"], components):
                entry_nets |= by_ref[n["ref"]]
    near = {n["ref"] for net in entry_nets for n in nets[net]}
    fuses = sorted(r for r in near if is_fuse(r, components))
    surge = sorted(r for r in near if is_protection(r, components) or
                   re.search(r"VARISTOR|\bMOV\b|S\d+K\d+", part_text(r, components)))
    where = ", ".join(connector_name(c, components) for c in entry) or "mains"
    if entry:
        findings.append(("OK", f"Mains input {where} is fused ({short_list(fuses)})", "") if fuses else
                        ("MEDIUM", f"Mains input {where} has no fuse",
                         "A fault or deliberate short becomes a fire risk. Add a fuse right at the mains entry."))
        findings.append(("OK", f"Mains input {where} has surge protection ({short_list(surge)})", "") if surge else
                        ("LOW", f"Mains input {where} has no surge protection (MOV/TVS)",
                         "Mains surges can destroy the electronics (denial of service). Add a varistor or TVS."))

    # 2. Isolation between mains and the low-voltage logic.
    # Board-mount AC/DC modules (HLK-PM01, Mean Well IRM...) are isolated by design.
    isolated_psu = sorted(r for r in components
                          if re.search(r"ISOLATED|HLK-?\d*PM|\bIRM-?\d|AC/?DC .*MODULE|AC-DC .*MODULE",
                                       part_text(r, components))
                          and any(re.match(r"^AC", pin_name(n), re.I) for net in by_ref[r] for n in nets[net] if n["ref"] == r))
    optos = sorted(r for r in components if re.search(r"OPTO|PC817|MOC30|MOC31|TLP\d|6N13|H11", part_text(r, components)))
    ssrs = sorted(r for r in components if is_ssr(r, components))   # opto-isolated inside
    if isolated_psu or optos or ssrs:
        parts = ([f"isolated supply {short_list(isolated_psu)}"] if isolated_psu else []) + \
                ([f"optocouplers {short_list(optos)}"] if optos else []) + \
                ([f"solid-state relays {short_list(ssrs)}"] if ssrs else [])
        findings.append(("OK", "Logic is isolated from mains by " + " and ".join(parts), ""))
    else:
        findings.append(("MEDIUM", "No isolated supply or optocouplers found between mains and the logic",
                         "A mains fault (or a probe on the low-voltage side) can put mains voltage on the logic "
                         "and connectors. Use an isolated PSU and optocouplers/relays as the barrier."))

    # 3. Who switches the mains loads: firmware (MCU-driven relays/triacs) or hardware interlocks.
    # Shared live/neutral wires touch everything, so only follow each connector's own wires.
    rails = {net for net in mains if MAINS_NAME.search(short(net))
             or any(re.match(r"^AC", pin_name(n), re.I) and n["type"] == "power_in" for n in nets[net])}

    def coil_nets(k):
        return {net for net in by_ref[k] for n in nets[net] if n["ref"] == k and is_coil_pin(n)}
    interlock_relays = {k for k in components if is_relay(k) and coil_nets(k) and coil_nets(k) <= mains}
    switch_inputs, loads, gated, ungated = [], [], [], []
    interlock_name = {}                      # interlock relay -> the switch connector driving it
    for c in connectors:
        if c in entry:
            continue
        own = [net for net in by_ref[c] if net not in rails]
        coils = sorted({n["ref"] for net in own for n in nets[net]
                        if n["ref"] in interlock_relays and is_coil_pin(n)})
        if coils:
            switch_inputs.append(f"{connector_name(c, components)} -> {short_list(coils, 3)}")
            for k in coils:
                interlock_name[k] = connector_name(c, components)
    for c in connectors:
        if c in entry or any(c in s for s in switch_inputs):
            continue
        own = [net for net in by_ref[c] if net not in rails]
        drivers = sorted({n["ref"] for net in own for n in nets[net]
                          if ((is_relay(n["ref"]) and not is_coil_pin(n) and n["ref"] not in interlock_relays)
                              or is_triac(n["ref"], components)
                              or (is_ssr(n["ref"], components) and not SSR_CONTROL_PIN.match(pin_name(n))))})
        if not drivers:
            continue
        # Is the driver's supply side fed through an interlock relay's contacts?
        guards = sorted({n["ref"] for d in drivers for net in by_ref[d] - set(own) - rails for n in nets[net]
                         if n["ref"] in interlock_relays and not is_coil_pin(n)}
                        | {n["ref"] for net in own for n in nets[net]
                           if n["ref"] in interlock_relays and not is_coil_pin(n)})
        name = f"{connector_name(c, components)} via {short_list(drivers, 3)}"
        loads.append(name)
        if guards:
            gated.append(f"{name}, gated by " + ", ".join(interlock_name.get(g, g) for g in guards))
        else:
            ungated.append(name)
    if loads:
        msg = "Firmware-controlled mains loads: " + "; ".join(loads)
        if switch_inputs:
            findings.append(("OK", "Hardware interlocks that work without firmware: " + "; ".join(switch_inputs), ""))
            if gated:
                findings.append(("OK", "Loads blocked in hardware by an interlock: " + "; ".join(gated), ""))
            if ungated:
                findings.append(("INFO", "Loads switched by firmware alone (no interlock in their path): "
                                 + "; ".join(ungated),
                                 "Confirm none of these can create a dangerous state (e.g. motor or drain running "
                                 "with the door open) if the firmware misbehaves."))
        else:
            findings.append(("MEDIUM", msg + " - no hardware interlocks found",
                             "If the firmware is buggy or compromised it can drive these loads unsafely. "
                             "Add hardware interlocks (door switch, water-level switch, thermal fuse) in series "
                             "with the dangerous loads."))
    # Headers that drive a power stage off the board (e.g. a heater SSR) on top of the mains loads.
    return findings + external_loads(components, nets, skip=connectors)


def is_crystal(ref, components):
    t = part_text(ref, components)
    return (ref_prefix(ref) in ("X", "Y", "XTAL", "OSC", "XO")
            and ("HZ" in t or "CRYSTAL" in t or "XTAL" in t or "OSC" in t or "RESONATOR" in t))


def is_trimmer(ref, components):
    t = part_text(ref, components)
    return ref_prefix(ref) in ("RV", "VR", "POT", "CV", "VC", "TC", "TRIM") or "TRIM" in t or " POT" in f" {t}"


def rule_clock(components, nets):
    findings = []
    by_ref = nets_by_ref(nets)
    for ref in sorted(r for r in components if is_crystal(r, components)):
        clock_nets = [n for n in by_ref[ref] if not is_ground(n)]
        nodes = [n for net in clock_nets for n in nets[net] if n["ref"] != ref]
        exposed = [n["ref"] for n in nodes if is_exposed(n["ref"])]
        trims = [n["ref"] for n in nodes if is_trimmer(n["ref"], components)]
        chips = sorted({n["ref"] for n in nodes if is_active_pin(n)})
        name = f"Crystal {ref} ({components[ref]['value']})" + (f" for {short_list(chips)}" if chips else "")
        if exposed:
            findings.append(("MEDIUM", f"{name} - clock line reaches {short_list(exposed)}",
                             "An attacker could inject a faster/glitched clock. Keep oscillator traces off connectors and test points."))
        else:
            tuned = f" (frequency tunable via {short_list(trims)} - see Trimmers)" if trims else ""
            findings.append(("OK", f"{name} is not reachable from any connector or test point{tuned}", ""))
    return findings


def rule_trimmers(components, nets):
    trims = [r for r in components if is_trimmer(r, components)]
    internal = [r for r in trims if re.search(r"\d", components[r]["value"])]
    panel = [r for r in trims if r not in internal]

    # Note which trimmers tune a crystal (they shift the board's timing).
    by_ref = nets_by_ref(nets)
    tunes = {}
    for x in (r for r in components if is_crystal(r, components)):
        for net in by_ref[x]:
            if not is_ground(net):
                for n in nets[net]:
                    if n["ref"] in internal:
                        tunes[n["ref"]] = x

    def describe(r):
        extra = f", tunes crystal {tunes[r]}" if r in tunes else ""
        return f"{r} ({components[r]['value']}{extra})"

    findings = []
    if internal:
        findings.append(("INFO", "Internal trimmers " +
                         ", ".join(describe(r) for r in sorted(internal)) +
                         " set calibration and can be turned by anyone who opens the case",
                         "Seal them with lacquer/tamper paint, or swap for fixed parts after calibration."))
    if panel:
        names = sorted({components[r]["value"] for r in panel})
        findings.append(("OK", f"{len(panel)} front-panel controls ({', '.join(names)}) - user-adjustable by design", ""))
    return findings


DIGITAL_RULES = [
    ("Debug interfaces", rule_debug_ports),
    ("Wireless interfaces (remote attack surface)", rule_wireless),
    ("Cellular modem (remote attack surface)", rule_cellular),
    ("SIM card", rule_sim),
    ("Boot-mode pins", rule_boot_pins),
    ("Write protection", rule_write_protect),
    ("Power test points", rule_power_testpoints),
    ("Exposed SPI/I2C buses", rule_exposed_buses),
    ("USB ESD protection", rule_usb_esd),
]

ANALOG_RULES = [
    ("Signal input/output protection", rule_signal_protection),
    ("Power input protection", rule_power_input),
    ("Supply decoupling (glitch resistance)", rule_decoupling),
    ("Mains & actuator safety (cyber-physical)", rule_mains),
    ("Clock / crystal", rule_clock),
    ("Trimmers and adjustable parts", rule_trimmers),
]

# ---------------------------------------------------------------------------
# 5. Report
# ---------------------------------------------------------------------------

ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3, "OK": 4}
WEIGHT = {"HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 0.5, "OK": 0}

# Attacker access levels, from easiest to hardest
EXTERNAL = "External - just plug something into a connector, no need to open the case"
BOARD = "Board access - case opened, probes or wires on the PCB"

# Cybersecurity view of each rule: how an attacker uses it, what it costs, and
# where it sits in common frameworks (STRIDE threat categories, MITRE CWE IDs).
THREATS = {
    "Debug interfaces": dict(
        attack="Attach a USB-UART, JTAG, SWD or ICSP adapter to dump the firmware, pull out keys and "
               "passwords, get a root shell, or flash modified firmware (e.g. a backdoor).",
        access=BOARD, cia="CIA",
        stride="Information disclosure, Tampering, Elevation of privilege",
        cwe="CWE-1191 (debug interface with improper access control), CWE-1263 (physical access)"),
    "Wireless interfaces (remote attack surface)": dict(
        attack="Connect to the Bluetooth/Wi-Fi/radio link from nearby - no physical access needed - and send "
               "commands, replay traffic, or exploit bugs in the firmware's command handling to take over the device.",
        access="Remote - within radio range, no physical access needed", cia="CIA",
        stride="Spoofing, Tampering, Information disclosure, Elevation of privilege",
        cwe="CWE-306 (missing authentication for critical function), CWE-319 (cleartext transmission)"),
    "Cellular modem (remote attack surface)": dict(
        attack="Reach the device from anywhere through the mobile network - no physical access or radio range "
               "needed: probe services on its IP address, send SMS commands, or (on 2G) run a fake base station "
               "to intercept and inject traffic.",
        access="Cellular - from anywhere over the mobile network (internet, SMS), no physical access needed",
        cia="CIA",
        stride="Spoofing, Tampering, Information disclosure, Denial of service, Elevation of privilege",
        cwe="CWE-306 (missing authentication for critical function), CWE-319 (cleartext transmission), "
            "CWE-923 (communication channel to an unverified endpoint)"),
    "SIM card": dict(
        attack="Take the SIM out and put it in a phone or modem: use the device's data plan, or connect to the "
               "backend as if you were this device when the backend trusts the SIM as its identity.",
        access=BOARD, cia="CIA",
        stride="Spoofing, Information disclosure",
        cwe="CWE-1263 (improper physical access control), CWE-290 (authentication bypass by spoofing)"),
    "Boot-mode pins": dict(
        attack="Hold the boot pin/switch to put the chip in recovery or USB-boot mode, skipping the normal "
               "boot chain to read the storage or load attacker firmware.",
        access=BOARD, cia="CI",
        stride="Tampering, Elevation of privilege, Information disclosure",
        cwe="CWE-1263 (improper physical access control)"),
    "Write protection": dict(
        attack="Rewrite the boot EEPROM or config memory over its bus to change boot settings, plant "
               "persistent malicious config, or brick the device.",
        access=BOARD, cia="IA",
        stride="Tampering, Denial of service",
        cwe="CWE-1233 (security-sensitive hardware control without lock protection)"),
    "Power test points": dict(
        attack="Voltage glitching: dip the supply for nanoseconds at the right moment so the CPU skips an "
               "instruction - e.g. a signature check, read-out-protection check or password compare.",
        access=BOARD, cia="CI",
        stride="Tampering, Elevation of privilege",
        cwe="CWE-1247 (no protection against voltage/clock glitches), CWE-1332 (fault -> instruction skip)"),
    "Exposed SPI/I2C buses": dict(
        attack="Sniff or inject bus traffic with a logic analyser / Bus Pirate: read sensor data or keys in "
               "an EEPROM, or impersonate a peripheral.",
        access=EXTERNAL, cia="CI",
        stride="Information disclosure, Spoofing, Tampering",
        cwe="CWE-319 (cleartext transmission of sensitive data), CWE-1263 (physical access)"),
    "USB ESD protection": dict(
        attack="Discharge ESD or a surge device ('USB killer') into the port to damage the chip behind it.",
        access=EXTERNAL, cia="A",
        stride="Denial of service",
        cwe="CWE-1384 (improper handling of physical/environmental conditions)"),
    "Signal input/output protection": dict(
        attack="Push ESD, overvoltage or crafted signals into a connector to damage or latch up the chip, "
               "or cause faults that change its behaviour. Unprotected outputs can also be tapped.",
        access=EXTERNAL, cia="IA",
        stride="Denial of service, Tampering",
        cwe="CWE-1384 (improper handling of physical/environmental conditions)"),
    "Power input protection": dict(
        attack="Reverse the plug, apply overvoltage or a surge on the power input to destroy the board. "
               "A controllable bench supply on that input also makes voltage glitching easy.",
        access=EXTERNAL, cia="IA",
        stride="Denial of service, Tampering",
        cwe="CWE-1384 (physical/environmental conditions), CWE-1247 (voltage glitches)"),
    "Supply decoupling (glitch resistance)": dict(
        attack="Without local capacitors, supply glitches and EM pulses reach the chip unfiltered, so fault "
               "injection works more reliably.",
        access=BOARD, cia="CI",
        stride="Tampering, Elevation of privilege",
        cwe="CWE-1247 (voltage/clock glitches), CWE-1332 (fault -> instruction skip)"),
    "Mains & actuator safety (cyber-physical)": dict(
        attack="On a mains appliance a firmware compromise becomes a physical one: malicious or buggy "
               "firmware (e.g. reflashed through an exposed programming port or a connected Wi-Fi module) "
               "can run the heater dry, unlock the door mid-cycle or stall the motor. Weak mains-entry "
               "protection also lets surges destroy the device.",
        access=BOARD, cia="IA",
        stride="Tampering, Denial of service",
        cwe="CWE-693 (protection mechanism failure), CWE-1384 (physical/environmental conditions)"),
    "Clock / crystal": dict(
        attack="Clock glitching: inject a short or fast clock edge so the chip mis-executes instructions. "
               "Turning a crystal trimmer shifts the device's timing.",
        access=BOARD, cia="I",
        stride="Tampering",
        cwe="CWE-1247 (no protection against voltage/clock glitches)"),
    "Trimmers and adjustable parts": dict(
        attack="Physical tampering: turning a calibration part quietly shifts gain, thresholds, voltages or "
               "frequency without leaving obvious traces.",
        access=BOARD, cia="IA",
        stride="Tampering",
        cwe="CWE-1263 (improper physical access control)"),
}

# On analog-only boards there is no processor or firmware to attack, so some
# threats look different. These replace the default text for those boards.
ANALOG_THREATS = {
    "Clock / crystal": dict(
        attack="No processor here to glitch. The risk is tampering: turning a crystal trimmer shifts the "
               "oscillator frequency (e.g. colour or carrier timing), degrading or breaking the output.",
        cia="IA", stride="Tampering, Denial of service"),
    "Supply decoupling (glitch resistance)": dict(
        attack="Noise or a surge injected on the supply couples into the analog signal path, distorting "
               "or disrupting the output.",
        cia="IA", stride="Tampering, Denial of service"),
    "Signal input/output protection": dict(
        attack="Push ESD or overvoltage into an input/output to damage or latch up the chip, or inject "
               "an unwanted signal. Unbuffered outputs can also be tapped to monitor the signal.",
        cia="CIA", stride="Denial of service, Tampering, Information disclosure"),
}

PARENT = "Via parent board - these are module ports, not connectors; exposure depends on that board"
REMOTE = "Remote - within radio range, no physical access needed"
CELLULAR = "Cellular - from anywhere over the mobile network (internet, SMS), no physical access needed"
ACCESS_LEVELS = (CELLULAR, REMOTE, EXTERNAL, PARENT, BOARD)

CIA_NAMES = {"C": "Confidentiality", "I": "Integrity", "A": "Availability"}


def threat_for(title, ctx):
    """THREATS entry adjusted for this board (analog-only? sub-module?)."""
    t = dict(THREATS.get(title, {}))
    if not t:
        return t
    if ctx["analog"]:
        t.update(ANALOG_THREATS.get(title, {}))
    if ctx["module"] and t.get("access") == EXTERNAL:
        t["access"] = PARENT
    return t


def wrap(label, text, indent=6):
    pad = " " * indent
    return textwrap.fill(text, width=100, initial_indent=f"{pad}{label:<10}: ",
                         subsequent_indent=pad + " " * 12)


# ---------------------------------------------------------------------------
# 6. Build the report once, then print it as text, JSON or HTML
# ---------------------------------------------------------------------------

SAFETY_CHECK = "Mains & actuator safety (cyber-physical)"


def assess(results, ctx):
    """results: list of (rule title, level, msg, fix). Returns the overall assessment."""
    issues = [r for r in results if r[1] != "OK"]
    score = sum(WEIGHT[r[1]] for r in issues)
    worst = min((ORDER[r[1]] for r in issues), default=ORDER["OK"])
    rating = {0: "HIGH", 1: "MEDIUM", 2: "LOW"}.get(worst, "MINIMAL")

    by_access = []
    for access in ACCESS_LEVELS:
        mine = [r for r in issues if threat_for(r[0], ctx).get("access") == access]
        if access in (PARENT, REMOTE, CELLULAR) and not mine:
            continue
        hits = [r for r in mine if r[1] != "INFO"]
        by_access.append({"access": access, "label": access.split(" - ")[0], "issues": len(hits),
                          "info": len(mine) - len(hits), "checks": sorted({r[0] for r in mine})})

    cia = {name: sorted({r[0] for r in issues if r[1] != "INFO" and c in threat_for(r[0], ctx).get("cia", "")})
           for c, name in CIA_NAMES.items()}

    fix_first, seen = [], set()
    # Within a level, physical-safety findings (heater, motor, door lock) come first: on an appliance
    # they are what turns a hack into a fire or an injury.
    def priority(r):
        return (ORDER[r[1]], r[0] != SAFETY_CHECK)
    for title, level, msg, fix in sorted((r for r in issues if r[1] in ("HIGH", "MEDIUM")), key=priority):
        if (title, fix) in seen:
            continue
        seen.add((title, fix))
        fix_first.append({"check": title, "level": level, "message": msg, "fix": fix})
        if len(fix_first) == 5:
            break

    return {"overall_risk": rating, "score": score, "by_access": by_access, "cia": cia,
            "fix_first": fix_first, "scope": scope_text(ctx)}


def scope_text(ctx):
    if ctx["analog"]:
        unseen = ("the enclosure, PCB layout, or the parent board this module plugs into" if ctx["module"]
                  else "the enclosure or PCB layout")
        return (f"This is a netlist-only review of an analog board (no firmware to attack). It can't "
                f"see {unseen}. Treat findings as places to check on the physical board.")
    return ("This is a netlist-only review. It can't see firmware settings (secure boot, read-out "
            "protection, disabled consoles), the enclosure, or PCB layout. Treat findings as places "
            "to check, and confirm them against the firmware and the physical board.")


def build_report(path, components, nets):
    digital = digital_signals(nets)
    ctx = {"analog": not digital, "module": interface_points(components, nets)[1]}
    sections, results = [], []
    for section, rules in (("DIGITAL CHECKS", DIGITAL_RULES), ("ANALOG CHECKS", ANALOG_RULES)):
        checks = []
        for title, rule in rules:
            findings = sorted(rule(components, nets), key=lambda f: ORDER[f[0]])
            results += [(title, *f) for f in findings]
            threat = None
            t = threat_for(title, ctx)
            if t and any(f[0] != "OK" for f in findings):
                threat = {"attack": t["attack"], "attacker": t["access"],
                          "impact": [CIA_NAMES[c] for c in t["cia"]], "stride": t["stride"], "cwe": t["cwe"]}
            checks.append({"title": title,
                           "findings": [{"level": lv, "message": msg, "fix": fix} for lv, msg, fix in findings],
                           "threat": threat})
        sections.append({"name": section, "checks": checks})
    return {
        "tool": "circuit.py",
        "netlist": os.path.basename(path),
        "components": len(components),
        "nets": len(nets),
        "board_profile": {"digital_signals": len(digital), "analog_only": ctx["analog"], "module": ctx["module"]},
        "sections": sections,
        "assessment": assess(results, ctx),
        "summary": {k: n for k in ORDER if (n := sum(1 for r in results if r[1] == k))},
    }


# ---- Text ------------------------------------------------------------------

def print_threat(t):
    print("   Cybersecurity view:")
    print(wrap("Attack", t["attack"]))
    print(wrap("Attacker", t["attacker"]))
    print(wrap("Impact", ", ".join(t["impact"])))
    print(wrap("STRIDE", t["stride"]))
    print(wrap("CWE", t["cwe"]))


def print_assessment(a, profile):
    print("######## SECURITY ASSESSMENT ########\n")
    print(f"Overall risk: {a['overall_risk']}   (score {a['score']:g} - HIGH=10, MEDIUM=5, LOW=2, INFO=0.5 each)\n")

    print("Who can exploit it (by attacker access):")
    for row in a["by_access"]:
        print(f"   {row['label']:<16}: {row['issues']} issue(s)" +
              (f" + {row['info']} info" if row["info"] else "") +
              (f"  [{', '.join(row['checks'])}]" if row["checks"] else ""))
    print()

    print("What's at risk (CIA triad):")
    for name, areas in a["cia"].items():
        print(f"   {name:<16}: " + (", ".join(areas) if areas else "no issues found"))
    print()

    print("Fix first (highest risk):")
    for n, f in enumerate(a["fix_first"], 1):
        print(textwrap.fill(f"{n}. [{f['level']}] {f['message']}", width=100,
                            initial_indent="   ", subsequent_indent="      "))
        if f["fix"]:
            print(textwrap.fill(f"-> {f['fix']}", width=100, initial_indent="      ", subsequent_indent="         "))
    if not a["fix_first"]:
        print("   Nothing urgent - only low-risk or informational items.")
    print()

    print("Scope / limits:")
    if profile["analog_only"]:
        print(textwrap.fill(a["scope"], width=100, initial_indent="   ", subsequent_indent="   ") + "\n")
    else:
        print("   This is a netlist-only review. It can't see firmware settings (secure boot, read-out")
        print("   protection, disabled consoles), the enclosure, or PCB layout. Treat findings as places")
        print("   to check, and confirm them against the firmware and the physical board.\n")


def print_text(report):
    print(f"Loaded {report['components']} components and {report['nets']} nets")
    profile = report["board_profile"]
    if not profile["analog_only"]:
        print(f"Board profile: {profile['digital_signals']} digital-looking signals found.\n")
    else:
        print("Board profile: no digital interfaces detected (looks analog-only).")
        print("               Digital checks will mostly say 'nothing found' - see the analog checks.\n")

    for section in report["sections"]:
        print(f"######## {section['name']} ########\n")
        for check in section["checks"]:
            print(f"== {check['title']} ==")
            if not check["findings"]:
                print("   nothing found")
            for f in check["findings"]:
                print(f"   [{f['level']:6}] {f['message']}")
                if f["fix"]:
                    print(f"            -> {f['fix']}")
            if check["threat"]:
                print_threat(check["threat"])
            print()

    print_assessment(report["assessment"], profile)

    counts = report["summary"]
    if counts:
        print("Summary: " + ", ".join(f"{k}={n}" for k, n in counts.items()))
    else:
        print("Summary: no security findings.")


# ---- HTML ------------------------------------------------------------------

HTML_STYLE = """
:root {
  --bg: #f6f6f3; --card: #ffffff; --text: #1c1c1e; --muted: #66666d; --border: #e2e2dc;
  --high: #b42318; --high-bg: #fdecea; --medium: #b54708; --medium-bg: #fef3e2;
  --low: #8a6a00; --low-bg: #fbf5d8; --info: #1f5fa8; --info-bg: #e8f0fb;
  --ok: #2b7a3a; --ok-bg: #e7f4ea; --minimal: #2b7a3a; --minimal-bg: #e7f4ea;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #141416; --card: #1d1d20; --text: #ececee; --muted: #a0a0a8; --border: #2f2f34;
    --high: #ff8a80; --high-bg: #3a1d1b; --medium: #ffb066; --medium-bg: #3a2a17;
    --low: #e6cc5c; --low-bg: #343016; --info: #8ab8ff; --info-bg: #1b2a40;
    --ok: #7fd18e; --ok-bg: #1a3020; --minimal: #7fd18e; --minimal-bg: #1a3020;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
main { max-width: 980px; margin: 0 auto; padding: 32px 16px 64px; }
h1 { font-size: 26px; margin: 0 0 4px; letter-spacing: -0.01em; }
h2 { font-size: 13px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); margin: 36px 0 12px; }
h3 { font-size: 15px; margin: 0 0 10px; }
.meta { color: var(--muted); margin: 0 0 24px; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 18px 20px; }
.risk { display: flex; flex-wrap: wrap; gap: 20px; align-items: center; justify-content: space-between; }
.risk-level { font-size: 34px; font-weight: 700; line-height: 1; }
.risk-label { color: var(--muted); font-size: 13px; margin-bottom: 6px; }
.pills { display: flex; flex-wrap: wrap; gap: 6px; }
.pill { display: inline-block; font-size: 12px; font-weight: 600; padding: 2px 9px; border-radius: 999px;
  white-space: nowrap; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 16px; }
@media (max-width: 720px) { .grid { grid-template-columns: 1fr; } }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
td { padding: 6px 0; border-top: 1px solid var(--border); vertical-align: top; }
tr:first-child td { border-top: 0; }
td.num { text-align: right; white-space: nowrap; padding-left: 12px; font-variant-numeric: tabular-nums; }
.sub { color: var(--muted); font-size: 12.5px; }
ol.fixes { margin: 0; padding-left: 22px; }
ol.fixes li { margin: 0 0 12px; }
ol.fixes li:last-child { margin-bottom: 0; }
.fix { color: var(--muted); font-size: 14px; margin-top: 2px; }
.toolbar { display: flex; justify-content: flex-end; margin: 28px 0 -20px; font-size: 14px; color: var(--muted); }
.toolbar label { cursor: pointer; user-select: none; }
details.check { background: var(--card); border: 1px solid var(--border); border-radius: 12px; margin-bottom: 10px; }
details.check > summary { list-style: none; cursor: pointer; padding: 13px 18px; display: flex; gap: 12px;
  align-items: center; justify-content: space-between; flex-wrap: wrap; font-weight: 600; }
details.check > summary::-webkit-details-marker { display: none; }
details.check > summary::before { content: "\\25B8"; color: var(--muted); margin-right: -4px; transition: transform .15s; }
details.check[open] > summary::before { transform: rotate(90deg); }
details.check > summary .name { flex: 1; min-width: 200px; }
.body { padding: 0 18px 16px; }
ul.findings { list-style: none; margin: 0; padding: 0; }
ul.findings li { display: flex; gap: 12px; padding: 10px 0; border-top: 1px solid var(--border); }
ul.findings li .pill { flex: none; width: 74px; text-align: center; height: fit-content; }
.msg { overflow-wrap: anywhere; }
.empty { color: var(--muted); font-size: 14px; padding: 4px 0; }
.threat { margin-top: 12px; padding: 12px 14px; border-radius: 8px; background: var(--bg); font-size: 14px; }
.threat dl { display: grid; grid-template-columns: 90px 1fr; gap: 6px 12px; margin: 0; }
.threat dt { color: var(--muted); }
.threat dd { margin: 0; }
@media (max-width: 520px) { .threat dl { grid-template-columns: 1fr; gap: 0; } .threat dd { margin-bottom: 8px; } }
.scope { color: var(--muted); font-size: 14px; margin-top: 36px; }
.lv-HIGH { color: var(--high); background: var(--high-bg); }
.lv-MEDIUM { color: var(--medium); background: var(--medium-bg); }
.lv-LOW { color: var(--low); background: var(--low-bg); }
.lv-INFO { color: var(--info); background: var(--info-bg); }
.lv-OK { color: var(--ok); background: var(--ok-bg); }
.lv-MINIMAL { color: var(--minimal); background: var(--minimal-bg); }
.risk-level.lv-HIGH, .risk-level.lv-MEDIUM, .risk-level.lv-LOW, .risk-level.lv-MINIMAL { background: none; }
body.hide-ok li.f-OK, body.hide-ok details.clean { display: none; }
"""


def render_html(report):
    e = html.escape
    a = report["assessment"]
    profile = report["board_profile"]

    def pill(level, text=None):
        return f'<span class="pill lv-{e(level)}">{e(text or level)}</span>'

    kind = "analog-only board" if profile["analog_only"] else f"{profile['digital_signals']} digital signals"
    out = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        f"<title>Security report - {e(report['netlist'])}</title><style>{HTML_STYLE}</style></head><body><main>",
        "<h1>Hardware security report</h1>",
        f"<p class='meta'>{e(report['netlist'])} &middot; {report['components']} components &middot; "
        f"{report['nets']} nets &middot; {e(kind)}</p>",
        "<div class='card risk'><div><div class='risk-label'>Overall risk</div>",
        f"<div class='risk-level lv-{e(a['overall_risk'])}'>{e(a['overall_risk'])}</div>",
        f"<div class='sub' style='margin-top:6px'>score {a['score']:g} &middot; HIGH=10, MEDIUM=5, LOW=2, INFO=0.5</div>"
        "</div><div class='pills'>",
        "".join(pill(k, f"{n} {k}") for k, n in report["summary"].items()) or pill("OK", "no findings"),
        "</div></div>",
    ]

    # Who can exploit it / what's at risk
    rows = "".join(
        f"<tr><td><strong>{e(r['label'])}</strong><div class='sub'>{e(', '.join(r['checks']) or 'nothing found')}"
        f"</div></td><td class='num'>{r['issues']} issue(s)" + (f" + {r['info']} info" if r["info"] else "")
        + "</td></tr>" for r in a["by_access"])
    cia = "".join(f"<tr><td><strong>{e(name)}</strong><div class='sub'>{e(', '.join(areas) or 'no issues found')}"
                  f"</div></td><td class='num'>{len(areas)}</td></tr>" for name, areas in a["cia"].items())
    out += ["<div class='grid'>",
            f"<div class='card'><h3>Who can exploit it</h3><table>{rows}</table></div>",
            f"<div class='card'><h3>What's at risk (CIA)</h3><table>{cia}</table></div></div>"]

    out.append("<h2>Fix first</h2><div class='card'>")
    if a["fix_first"]:
        out.append("<ol class='fixes'>" + "".join(
            f"<li>{pill(f['level'])} <span class='msg'>{e(f['message'])}</span>"
            + (f"<div class='fix'>&rarr; {e(f['fix'])}</div>" if f["fix"] else "") + "</li>"
            for f in a["fix_first"]) + "</ol>")
    else:
        out.append("<p class='empty'>Nothing urgent - only low-risk or informational items.</p>")
    out.append("</div>")

    out.append("<div class='toolbar'><label><input type='checkbox' id='show-ok'> Show passed checks</label></div>")
    for section in report["sections"]:
        out.append(f"<h2>{e(section['name'].title())}</h2>")
        for check in section["checks"]:
            levels = [f["level"] for f in check["findings"]]
            issues = [lv for lv in levels if lv != "OK"]
            counts = {lv: issues.count(lv) for lv in ORDER if lv in issues}
            badges = "".join(pill(lv, f"{n} {lv}") for lv, n in counts.items()) or \
                pill("OK", "passed" if levels else "nothing found")
            is_open = " open" if any(lv in ("HIGH", "MEDIUM") for lv in levels) else ""
            clean = "" if issues else " clean"
            out.append(f"<details class='check{clean}'{is_open}><summary><span class='name'>{e(check['title'])}"
                       f"</span><span class='pills'>{badges}</span></summary><div class='body'>")
            if check["findings"]:
                out.append("<ul class='findings'>" + "".join(
                    f"<li class='f-{e(f['level'])}'>{pill(f['level'])}<div><div class='msg'>{e(f['message'])}</div>"
                    + (f"<div class='fix'>&rarr; {e(f['fix'])}</div>" if f["fix"] else "") + "</div></li>"
                    for f in check["findings"]) + "</ul>")
            else:
                out.append("<p class='empty'>Nothing found.</p>")
            t = check["threat"]
            if t:
                out.append("<div class='threat'><dl>" + "".join(
                    f"<dt>{label}</dt><dd>{e(value)}</dd>" for label, value in (
                        ("Attack", t["attack"]), ("Attacker", t["attacker"]), ("Impact", ", ".join(t["impact"])),
                        ("STRIDE", t["stride"]), ("CWE", t["cwe"]))) + "</dl></div>")
            out.append("</div></details>")

    out += [f"<p class='scope'><strong>Scope:</strong> {e(a['scope'])}</p>",
            "<p class='scope'>Generated by circuit.py.</p></main>",
            "<script>(function(){var b=document.getElementById('show-ok');"
            "function u(){document.body.classList.toggle('hide-ok',!b.checked);}"
            "b.addEventListener('change',u);u();})();</script></body></html>"]
    return "\n".join(out)


# ---------------------------------------------------------------------------
# 7. Command line
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Hardware-security checker for KiCad netlists (File -> Export -> Netlist, KiCad format).")
    ap.add_argument("netlist", help="path to the .net file")
    ap.add_argument("--json", metavar="FILE",
                    help="also save the report as JSON (use '-' to print only JSON to the screen)")
    ap.add_argument("--html", metavar="FILE", help="also save the report as an HTML page")
    args = ap.parse_args()
    path = args.netlist

    try:
        components, nets = load_netlist(path)
    except FileNotFoundError:
        sys.exit(f"Error: file not found: {path}")
    except (ValueError, IndexError) as err:
        sys.exit(f"Error: could not read {path}: {err}")
    if not components or not nets:
        sys.exit(f"Error: {path} has no components or nets, so nothing can be checked.\n"
                 "The export probably failed - e.g. KiCad couldn't find the project's symbol libraries. "
                 "Open the schematic in KiCad, fix any missing symbols, and export the netlist again.")

    report = build_report(path, components, nets)
    if args.json == "-":
        print(json.dumps(report, indent=2))
    else:
        print_text(report)

    for target, content in ((args.json, lambda: json.dumps(report, indent=2) + "\n"),
                            (args.html, lambda: render_html(report))):
        if target and target != "-":
            try:
                with open(target, "w", encoding="utf-8") as f:
                    f.write(content())
            except OSError as err:
                sys.exit(f"Error: could not write {target}: {err}")
            print(f"Report saved to {target}", file=sys.stderr)


if __name__ == "__main__":
    main()
