#!/usr/bin/env python3
"""
circuit.py - a tiny hardware-security checker for KiCad netlists.

Usage:
    python3 circuit.py path/to/board.net

It reads a KiCad netlist (File -> Export -> Netlist, "KiCad" format),
builds a list of components and nets, then runs simple security rules.
No extra libraries needed - just Python 3.8+.
"""

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


def is_switch(ref):
    return ref_prefix(ref) in SWITCH_PREFIXES


def is_power_net(name):
    n = short(name).upper()
    # Status/sense signals named after a rail (e.g. VCC_SENSE, PWR_GOOD) are not rails.
    if re.search(r"SENSE|ERR|DETECT|GOOD|_EN\b|\bPG\b", n):
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


def meaning_of(node, components):
    part = components.get(node["ref"], {}).get("value", "")
    pins = next((p for chip, p in KNOWN_PINS.items() if chip in part), {})
    for key, meaning in pins.items():
        if key in node["function"]:
            return meaning
    return None


# ---------------------------------------------------------------------------
# 4. Rules - each one returns a list of findings
# ---------------------------------------------------------------------------

PROG_PIN = re.compile(r"\b(ICSP\w*|PGC\d?|PGD\d?|SWDIO|SWCLK|TCK|TMS|TDI|TDO|nTRST|MCLR|UPDI|PDI_?DATA)\b", re.I)


def rule_debug_ports(components, nets):
    findings = []
    pattern = re.compile(r"UART|_TX|_RX|TXD|RXD|SWD|SWCLK|SWDIO|JTAG|TCK|TMS|TDI|TDO|UPDI|CONSOLE|DEBUG", re.I)
    for name, nodes in nets.items():
        meanings = [m for m in (meaning_of(n, components) for n in nodes)
                    if m and re.search(r"UART|UPDI|debug", m) and "Boot-mode" not in m]
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
        if exposed:
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
    return findings


WIRELESS = re.compile(r"\b(BT|BLE|BLUETOOTH|WI-?FI|WIFI|WLAN|ESP\d*\w*|LORA\w*|ZIGBEE|GSM|LTE|NB-?IOT|NRF\d+\w*|"
                      r"HC-?0[56]|RFM\d+\w*|CC\d{4}|SIM\d{3,4}\w*|XBEE)\b", re.I)


def rule_wireless(components, nets):
    """Radios (or headers for radio modules) give a remote attack surface."""
    radios = defaultdict(set)              # part/header -> signals it uses
    for ref, comp in components.items():
        if WIRELESS.search(f"{comp['value']} {comp['part']} {comp['description']}"):
            radios[ref]
    for name, nodes in nets.items():
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


def rule_boot_pins(components, nets):
    findings = []
    for name, nodes in nets.items():
        boot_node = next((n for n in nodes if re.search(r"BOOT|STRAP", n["function"] + name, re.I)
                          or "Boot-mode" in (meaning_of(n, components) or "")), None)
        if not boot_node or name.startswith("unconnected"):
            continue
        reach = [n["ref"] for n in nodes if is_exposed(n["ref"]) or is_switch(n["ref"])]
        # One step through a transistor, e.g. the DTR/RTS auto-programming circuit on ESP32 boards
        by_ref = nets_by_ref(nets)
        for n in nodes:
            if ref_prefix(n["ref"]) == "Q" or "TRANSISTOR" in part_text(n["ref"], components):
                for other in by_ref[n["ref"]] - {name}:
                    if is_ground(other) or is_power_net(other):
                        continue
                    hits = sorted({m["ref"] for m in nets[other] if is_exposed(m["ref"])})
                    reach += [f"{h} (via {n['ref']}, {short(other)})" for h in hits]
        reach = list(dict.fromkeys(reach))
        label = meaning_of(boot_node, components) or "boot-mode pin"
        if reach:
            findings.append(("MEDIUM", f"Boot pin {short(name)} ({label}) can be driven from {', '.join(reach)}",
                             "Fine for dev boards. On products, remove the switch or lock boot mode with OTP/secure boot."))
    return findings


def rule_write_protect(components, nets):
    findings = []
    for name, nodes in nets.items():
        wp_pins = [n for n in nodes if re.fullmatch(r"N?WP|WRITE_PROT\w*", pin_name(n), re.I)]
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
        if not others:
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


def mains_nets(components, nets):
    """Nets that carry mains voltage: named like mains, PSU AC inputs, relay contacts,
    triac main terminals - then spread to every pin of a connector that touches them."""
    found = set()
    for name, nodes in nets.items():
        if is_ground(name) or is_power_net(name) or name.startswith("unconnected"):
            continue
        if MAINS_NAME.search(short(name)):
            found.add(name)
            continue
        for n in nodes:
            if (re.match(r"^AC", pin_name(n), re.I) and n["type"] == "power_in") \
                    or (is_relay(n["ref"]) and not is_coil_pin(n)) \
                    or (is_triac(n["ref"], components) and pin_name(n).upper() not in ("G", "GATE")):
                found.add(name)
                break
    by_ref = nets_by_ref(nets)
    changed = True
    while changed:                       # a connector with one mains pin is a mains connector
        changed = False
        for ref, ref_nets in by_ref.items():
            if is_exposed(ref) and ref_nets & found:
                for net in ref_nets - found:
                    if not (is_ground(net) or is_power_net(net) or net.startswith("unconnected")):
                        found.add(net)
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
            for other in by_ref[n["ref"]] - {net}:
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
                            and re.search(r"REGULATOR|LDO|CONVERTER|BUCK|BOOST", part_text(n["ref"], components))))}
        # Switching regulators: chip SW/LX pin -> inductor -> this rail
        for n in nodes:
            if ref_prefix(n["ref"]) == "L":
                for other in by_ref[n["ref"]] - {name}:
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
        elif all(ref_prefix(s) == "MODULE" for s in supplied):
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
                        r"DOOR|OPENER|STRIKE|LATCH)\b", re.I)


def external_loads(components, nets):
    """No mains on the board, but headers that drive an external power stage (e.g. an SSR for a heater)."""
    by_ref = nets_by_ref(nets)
    found = []
    for ref, comp in sorted(components.items()):
        if not is_exposed(ref):
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
    isolated_psu = sorted(r for r in components if "ISOLATED" in part_text(r, components)
                          and any(re.match(r"^AC", pin_name(n), re.I) for net in by_ref[r] for n in nets[net] if n["ref"] == r))
    optos = sorted(r for r in components if re.search(r"OPTO|PC817|MOC30|MOC31|TLP\d|6N13|H11", part_text(r, components)))
    if isolated_psu or optos:
        parts = ([f"isolated supply {short_list(isolated_psu)}"] if isolated_psu else []) + \
                ([f"optocouplers {short_list(optos)}"] if optos else [])
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
                              or is_triac(n["ref"], components))})
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
    return findings


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
ACCESS_LEVELS = (REMOTE, EXTERNAL, PARENT, BOARD)

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


def print_threat(title, ctx):
    t = threat_for(title, ctx)
    if not t:
        return
    print("   Cybersecurity view:")
    print(wrap("Attack", t["attack"]))
    print(wrap("Attacker", t["access"]))
    print(wrap("Impact", ", ".join(CIA_NAMES[c] for c in t["cia"])))
    print(wrap("STRIDE", t["stride"]))
    print(wrap("CWE", t["cwe"]))


def print_assessment(results, ctx):
    """results: list of (rule title, level, msg, fix)."""
    issues = [r for r in results if r[1] not in ("OK",)]
    print("######## SECURITY ASSESSMENT ########\n")

    score = sum(WEIGHT[r[1]] for r in issues)
    worst = min((ORDER[r[1]] for r in issues), default=ORDER["OK"])
    rating = {0: "HIGH", 1: "MEDIUM", 2: "LOW"}.get(worst, "MINIMAL")
    print(f"Overall risk: {rating}   (score {score:g} - HIGH=10, MEDIUM=5, LOW=2, INFO=0.5 each)\n")

    print("Who can exploit it (by attacker access):")
    for access in ACCESS_LEVELS:
        mine = [r for r in issues if threat_for(r[0], ctx).get("access") == access]
        if access in (PARENT, REMOTE) and not mine:
            continue
        hits = [r for r in mine if r[1] != "INFO"]
        infos = len(mine) - len(hits)
        print(f"   {access.split(' - ')[0]:<16}: {len(hits)} issue(s)" +
              (f" + {infos} info" if infos else "") +
              (f"  [{', '.join(sorted({r[0] for r in mine}))}]" if mine else ""))
    print()

    print("What's at risk (CIA triad):")
    for c, name in CIA_NAMES.items():
        areas = sorted({r[0] for r in issues if r[1] != "INFO" and c in threat_for(r[0], ctx).get("cia", "")})
        print(f"   {name:<16}: " + (", ".join(areas) if areas else "no issues found"))
    print()

    print("Fix first (highest risk):")
    top = sorted((r for r in issues if r[1] in ("HIGH", "MEDIUM")), key=lambda r: ORDER[r[1]])
    seen = set()
    n = 0
    for title, level, msg, fix in top:
        key = (title, fix)
        if key in seen:
            continue
        seen.add(key)
        n += 1
        print(textwrap.fill(f"{n}. [{level}] {msg}", width=100, initial_indent="   ", subsequent_indent="      "))
        if fix:
            print(textwrap.fill(f"-> {fix}", width=100, initial_indent="      ", subsequent_indent="         "))
        if n == 5:
            break
    if n == 0:
        print("   Nothing urgent - only low-risk or informational items.")
    print()

    print("Scope / limits:")
    if ctx["analog"]:
        unseen = ("the enclosure, PCB layout, or the parent board this module plugs into" if ctx["module"]
                  else "the enclosure or PCB layout")
        print(textwrap.fill(f"This is a netlist-only review of an analog board (no firmware to attack). It can't "
                            f"see {unseen}. Treat findings as places to check on the physical board.",
                            width=100, initial_indent="   ", subsequent_indent="   ") + "\n")
    else:
        print("   This is a netlist-only review. It can't see firmware settings (secure boot, read-out")
        print("   protection, disabled consoles), the enclosure, or PCB layout. Treat findings as places")
        print("   to check, and confirm them against the firmware and the physical board.\n")


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)

    try:
        components, nets = load_netlist(sys.argv[1])
    except FileNotFoundError:
        sys.exit(f"Error: file not found: {sys.argv[1]}")
    except (ValueError, IndexError) as e:
        sys.exit(f"Error: could not read {sys.argv[1]}: {e}")
    if not components or not nets:
        sys.exit(f"Error: {sys.argv[1]} has no components or nets, so nothing can be checked.\n"
                 "The export probably failed - e.g. KiCad couldn't find the project's symbol libraries. "
                 "Open the schematic in KiCad, fix any missing symbols, and export the netlist again.")
    print(f"Loaded {len(components)} components and {len(nets)} nets")

    digital = digital_signals(nets)
    if digital:
        print(f"Board profile: {len(digital)} digital-looking signals found.\n")
    else:
        print("Board profile: no digital interfaces detected (looks analog-only).")
        print("               Digital checks will mostly say 'nothing found' - see the analog checks.\n")

    ctx = {"analog": not digital, "module": interface_points(components, nets)[1]}
    counts = defaultdict(int)
    results = []
    for section, rules in (("DIGITAL CHECKS", DIGITAL_RULES), ("ANALOG CHECKS", ANALOG_RULES)):
        print(f"######## {section} ########\n")
        for title, rule in rules:
            findings = sorted(rule(components, nets), key=lambda f: ORDER[f[0]])
            print(f"== {title} ==")
            if not findings:
                print("   nothing found")
            for level, msg, fix in findings:
                counts[level] += 1
                results.append((title, level, msg, fix))
                print(f"   [{level:6}] {msg}")
                if fix:
                    print(f"            -> {fix}")
            if any(f[0] != "OK" for f in findings):
                print_threat(title, ctx)
            print()

    print_assessment(results, ctx)

    if counts:
        print("Summary: " + ", ".join(f"{k}={counts[k]}" for k in ORDER if counts[k]))
    else:
        print("Summary: no security findings.")


if __name__ == "__main__":
    main()