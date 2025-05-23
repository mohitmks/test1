import json
import datetime
import re
import os
import logging
import glob
import shutil
import argparse
import difflib
from genie.testbed import load
from rich.text import Text
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

console = Console()

def filter_config_lines(config_lines):
    """
    Returns a new list of config lines, excluding timestamp, command, and other noisy lines.
    """
    filtered = []
    skip_patterns = [
        re.compile(r'^!Command: show running-config'),           # command banner
        re.compile(r'^!Running configuration last done at:'),    # last done timestamp
        re.compile(r'^!Time:'),                                  # time line
        re.compile(r'^!'),                                       # any line that's just '!'
        # Add your own patterns as needed
    ]
    for line in config_lines:
        if any(pat.match(line.strip()) for pat in skip_patterns):
            continue
        filtered.append(line)
    return filtered

def get_device_os(device):
    return (getattr(device, "os", "") or "").lower()

def ensure_baseline_dir(device_name):
    base_dir = os.path.join("baselines", device_name)
    os.makedirs(base_dir, exist_ok=True)
    return base_dir

def baseline_filename(device_name, timestamp=None):
    base_dir = ensure_baseline_dir(device_name)
    if timestamp is None:
        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    return os.path.join(base_dir, f"{device_name}_baseline_{timestamp}.json")

def latest_baseline_filename(device_name):
    base_dir = ensure_baseline_dir(device_name)
    return os.path.join(base_dir, f"{device_name}_baseline_latest.json")

def connect_device(testbed_file, device_name):
    try:
        testbed = load(testbed_file)
    except Exception as e:
        log.error(f"❌ Failed to load testbed file: {e}")
        return None
    device = testbed.devices.get(device_name)
    if not device:
        log.error(f"Device {device_name} not found in testbed.")
        return None
    try:
        device.connect(log_stdout=False)
        return device
    except Exception as e:
        log.error(f"❌ Failed to connect to device {device_name}: {e}")
        return None

def get_version_info(device):
    os_hint = get_device_os(device)
    try:
        output = device.execute('show version')
        model = serial = "Unknown"
        if os_hint == "nxos":
            # Try several patterns for model
            model_match = re.search(r'^\s*Model\s*number\s*[:=]\s*(\S+)', output, re.MULTILINE)
            if not model_match:
                model_match = re.search(r'^cisco\s+(\S+)\s+Chassis', output, re.MULTILINE)
            if not model_match:
                model_match = re.search(r'Model:\s*(\S+)', output)
            model = model_match.group(1) if model_match else "Unknown"

            # Try several patterns for serial
            serial_match = re.search(r'(?:System )?serial number\s*[:=]\s*(\S+)', output, re.IGNORECASE)
            if not serial_match:
                serial_match = re.search(r'Processor board ID (\S+)', output)
            serial = serial_match.group(1) if serial_match else "Unknown"

            # Fallback to show inventory if unknown
            if model == "Unknown" or serial == "Unknown":
                try:
                    inv = device.execute('show inventory')
                    for match in re.finditer(r'NAME: "Chassis".*?PID: *(\S+).*?SN: *(\S+)', inv, re.DOTALL | re.IGNORECASE):
                        model = match.group(1)
                        serial = match.group(2)
                        break
                except Exception as e:
                    log.warning(f"DEBUG: Failed to parse show inventory: {e}")

            version_match = re.search(r'NXOS:\s+version\s+(\S+)', output)
            os_version = version_match.group(1) if version_match else "Unknown"
            uptime_match = re.search(r'(\S+)\s+uptime is\s+(.+)', output)
            uptime = uptime_match.group(2) if uptime_match else "Unknown"
            return {
                "model": model,
                "serial": serial,
                "uptime": uptime,
                "os_version": os_version
            }
        else:
            try:
                parsed = device.parse('show version')
                version_info = parsed.get('version', {})
            except Exception:
                version_info = {}
            serial_match = re.search(r'Processor board ID (\S+)', output)
            uptime_match = re.search(r'(\S+) uptime is (.+)', output)
            return {
                "model": version_info.get('chassis', 'Unknown'),
                "serial": version_info.get('chassis_sn') or (serial_match and serial_match.group(1) or "Unknown"),
                "uptime": version_info.get('uptime') or (uptime_match and uptime_match.group(2) or "Unknown"),
                "os_version": version_info.get('version', 'Unknown')
            }
    except Exception:
        return {
            "model": "Unknown",
            "serial": "Unknown",
            "uptime": "Unknown",
            "os_version": "Unknown"
        }

def get_memory_utilization(device):
    os_hint = get_device_os(device)
    try:
        if os_hint == "nxos":
            output = device.execute('show system resources')
            match = re.search(r'Memory usage:\s+([\d,]+)K total,\s+([\d,]+)K used', output)
            if match:
                total = int(match.group(1).replace(",", ""))
                used = int(match.group(2).replace(",", ""))
                percent = (used / total) * 100 if total else 0
                return f"{percent:.2f}%"
            match2 = re.search(r'Memory usage:\s+(\d+)%', output)
            if match2:
                return f"{match2.group(1)}%"
        else:
            output = device.execute('show memory statistics')
            for line in output.splitlines():
                if 'Processor' in line:
                    parts = line.split()
                    total = int(parts[2])
                    used = int(parts[4])
                    return f"{(used / total) * 100:.2f}%"
    except Exception as e:
        log.warning(f"DEBUG: Memory Utilization Exception: {e}")
    return "Unknown"

def get_cpu_utilization(device):
    os_hint = get_device_os(device)
    try:
        if os_hint == "nxos":
            output = device.execute('show system resources')
            match = re.search(r'CPU states\s*:\s*([\d.]+)% user,\s*([\d.]+)% kernel', output)
            if match:
                user = float(match.group(1))
                kernel = float(match.group(2))
                percent = user + kernel
                return f"{percent:.2f}%"
            match2 = re.search(r'CPU usage:\s+(\d+)%', output)
            if match2:
                return f"{match2.group(1)}%"
        else:
            try:
                cpu = device.parse('show processes cpu')
                cpu_val = cpu.get('five_sec_cpu_total')
                if cpu_val is not None:
                    return f"{cpu_val}%"
            except Exception:
                pass
            try:
                output = device.execute('show processes cpu | include CPU utilization')
                match = re.search(r'CPU utilization for five seconds: (\d+)%', output)
                if match:
                    return f"{match.group(1)}%"
            except Exception:
                pass
    except Exception:
        pass
    return "Unknown"

def get_vrf_list(device):
    os_hint = get_device_os(device)
    vrfs = []
    if os_hint == "nxos":
        try:
            output = device.execute('show vrf')
            for line in output.splitlines():
                line = line.strip()
                if line and not line.lower().startswith("vrf-name") and not line.startswith("---"):
                    fields = line.split()
                    if len(fields) >= 1:
                        name = fields[0]
                        if name not in vrfs:
                            vrfs.append(name)
        except Exception as e:
            log.warning(f"NX-OS fallback: Failed to parse VRF list from CLI: {e}")
    else:
        try:
            vrf_dict = device.parse('show vrf').get('vrf', {})
            vrfs = list(vrf_dict.keys())
        except Exception:
            try:
                vrf_dict = device.parse('show ip vrf').get('vrf', {})
                vrfs = list(vrf_dict.keys())
            except Exception as e:
                log.warning(f"IOS fallback: Failed to parse VRF list: {e}")
    if 'default' not in vrfs:
        vrfs = ['default'] + vrfs
    return vrfs

def get_interfaces(device):
    """
    Collect all up Layer 3 interfaces with IP and their VRF assignment.
    Supports NX-OS and IOS/IOS-XE, using Genie then CLI fallback.
    Returns a list of dicts with interface, ip_address, vrf.
    """
    interfaces_data = []
    os_hint = get_device_os(device)
    try:
        if os_hint == "nxos":
            # Genie parse for NX-OS (show ip interface brief vrf all)
            try:
                ip_brief = device.parse('show ip interface brief vrf all')
                for vrf_name, vrf_dict in ip_brief.get('vrfs', {}).items():
                    for intf, data in vrf_dict.get('interfaces', {}).items():
                        ip_addr = data.get('ip_address', '')
                        status = data.get('interface_status', '')
                        if ip_addr and ip_addr.lower() != 'unassigned' and "up" in status.lower():
                            interfaces_data.append({
                                "interface": intf,
                                "ip_address": ip_addr,
                                "vrf": vrf_name
                            })
                if interfaces_data:
                    return interfaces_data
            except Exception as e:
                log.warning(f"NX-OS Genie failed: {e}")
            # CLI fallback for NX-OS
            try:
                output = device.execute('show ip interface brief vrf all')
                blocks = re.split(r'IP Interface Status for VRF "', output)
                for block in blocks:
                    if not block.strip():
                        continue
                    vrf_match = re.match(r'([^"]+)"\(\d+\)', block)
                    vrf_name = vrf_match.group(1) if vrf_match else "default"
                    lines = block.strip().splitlines()
                    for line in lines[2:]:
                        parts = line.split()
                        if len(parts) < 3:
                            continue
                        intf, ip_addr, status = parts[0], parts[1], parts[2]
                        if (
                            ip_addr.lower() not in ['unassigned', 'unknown', 'none']
                            and "up" in status.lower()
                        ):
                            interfaces_data.append({
                                "interface": intf,
                                "ip_address": ip_addr,
                                "vrf": vrf_name
                            })
                return interfaces_data
            except Exception as e:
                interfaces_data.append({"error": f"Failed to parse interfaces: {e}"})
            return interfaces_data
        else:
            # IOS/IOS-XE: Use 'show ip vrf interfaces' for proper VRF mapping
            try:
                try:
                    vrf_intf_output = device.execute('show ip vrf interfaces')
                except Exception:
                    vrf_intf_output = device.execute('show ip vrf int')  # alternate form

                for line in vrf_intf_output.splitlines():
                    # Match: Interface   IP-Address      VRF         Protocol
                    m = re.match(r'^(\S+)\s+([\d.]+)?\s+(\S+)\s+(\S+)', line)
                    if m:
                        intf = m.group(1)
                        ip = m.group(2) or ""
                        vrf = m.group(3)
                        proto = m.group(4)
                        if proto.lower() == "up" and ip and ip.lower() != "unassigned":
                            interfaces_data.append({
                                "interface": intf,
                                "ip_address": ip,
                                "vrf": vrf
                            })
                # If above fails (empty), fallback to Genie parse
                if not interfaces_data:
                    try:
                        parsed = device.parse('show ip interface brief')
                        for intf, data in parsed.get('interface', {}).items():
                            ip_addr = data.get('ip_address', '')
                            status = data.get('status', '').lower()
                            if ip_addr and ip_addr.lower() != 'unassigned' and "up" in status:
                                interfaces_data.append({
                                    "interface": intf,
                                    "ip_address": ip_addr,
                                    "vrf": "default"
                                })
                    except Exception:
                        pass
                return interfaces_data
            except Exception as e:
                interfaces_data.append({"error": f"Failed to parse interfaces: {e}"})
        return interfaces_data
    except Exception as e:
        interfaces_data.append({"error": f"Failed to parse interfaces (outer): {e}"})
    return interfaces_data

def get_bgp_summary(device):
    peers_flat = []
    vrf_list = get_vrf_list(device)
    global_as = "Unknown"
    os_hint = get_device_os(device)

    try:
        if os_hint == "nxos":
            bgp_info_global = device.parse("show bgp summary")
            global_as = bgp_info_global.get("local_as")
            if not global_as:
                output = device.execute("show bgp summary")
                match = re.search(r'local AS number (\d+)', output)
                if not match:
                    match = re.search(r'BGP router identifier \S+, local AS number (\d+)', output)
                if match:
                    global_as = int(match.group(1))
        else:
            bgp_info_global = device.parse("show ip bgp summary")
            global_as = bgp_info_global.get("local_as")
            if not global_as:
                output = device.execute("show ip bgp summary")
                match = re.search(r'local AS number (\d+)', output)
                if not match:
                    match = re.search(r'BGP router identifier \S+, local AS number (\d+)', output)
                if match:
                    global_as = int(match.group(1))
    except Exception:
        pass

    neighbor_local_as_map = get_neighbor_local_as(device)

    for vrf in vrf_list:
        if os_hint == "nxos":
            cmd = "show bgp summary" if vrf == 'default' else f"show bgp vrf {vrf} summary"
        else:
            cmd = "show ip bgp summary" if vrf == 'default' else f"show ip bgp vpnv4 vrf {vrf} summary"

        try:
            bgp_info = device.parse(cmd)
            if os_hint == "nxos":
                if vrf == "default":
                    local_as = bgp_info.get('local_as')
                    peers = bgp_info.get('neighbor', {})
                else:
                    vrf_data = bgp_info.get('vrf', {}).get(vrf, {})
                    local_as = vrf_data.get('local_as')
                    peers = vrf_data.get('neighbor', {})
            else:
                if vrf == 'default':
                    local_as = bgp_info.get('local_as') or bgp_info.get('vrf', {}).get('default', {}).get('local_as')
                    peers = bgp_info.get('neighbor', {})
                    if not peers and 'vrf' in bgp_info and 'default' in bgp_info['vrf']:
                        peers = bgp_info['vrf']['default'].get('neighbor', {})
                else:
                    vrf_data = bgp_info.get('vrf', {}).get(vrf, {})
                    local_as = vrf_data.get('local_as')
                    peers = vrf_data.get('neighbor', {})

            if not local_as or local_as == "Unknown":
                local_as = global_as if global_as else "Unknown"

            try:
                summary_output = device.execute(cmd)
            except Exception:
                summary_output = ""

            for peer_ip, peer_data in peers.items():
                af = peer_data.get('address_family', {})
                af_key = next(iter(af), '')
                af_data = af.get(af_key, {})
                state_pfxrcd = af_data.get('state_pfxrcd', '')
                if state_pfxrcd == '':
                    state = "Unknown"
                    routes = "Unknown"
                else:
                    try:
                        int(state_pfxrcd)
                        state = 'Established'
                        routes = state_pfxrcd
                    except (ValueError, TypeError):
                        state = state_pfxrcd
                        if 'Admin' in state:
                            routes = "0 (Admin Shutdown)"
                        else:
                            routes = "0 (Not Established)"
                peer_local_as = neighbor_local_as_map.get(peer_ip, local_as)
                remote_as = peer_data.get('remote_as')
                if not remote_as or remote_as == "Unknown":
                    remote_as = get_peer_as_from_summary(summary_output, peer_ip)
                peers_flat.append({
                    "vrf": vrf,
                    "peer_ip": peer_ip,
                    "local_as": peer_local_as,
                    "remote_as": remote_as,
                    "routes": routes,
                    "uptime": af_data.get('up_down') or "never",
                    "state": state,
                })
        except Exception:
            pass

    return peers_flat

# --- Include these helpers as well! ---
def get_neighbor_local_as(device):
    # Your implementation here (should look for local AS per neighbor via CLI or parse)
    return {}

def get_peer_as_from_summary(summary_output, peer_ip):
    """
    Given the CLI output of the BGP summary and a peer IP, extract the remote AS.
    """
    for line in summary_output.splitlines():
        # Skip header and empty lines
        if line.strip().startswith("Neighbor") or not line.strip():
            continue
        # Match line with peer_ip at the start
        if line.strip().startswith(peer_ip):
            parts = line.split()
            if len(parts) > 2:
                return parts[2]
    return "Unknown"

def get_hsrp_status(device):
    """
    Collect HSRP status for IOS/IOS-XE and NX-OS, using Genie then CLI fallback.
    Returns a list of dicts with interface, group, priority, state, vip.
    """
    hsrp_list = []
    # Genie parser first
    try:
        output = device.parse('show standby brief')
        for intf, groups in output['interfaces'].items():
            for group, data in groups.items():
                hsrp_list.append({
                    "interface": intf,
                    "group": str(group),
                    "priority": str(data.get("priority", "")),
                    "state": data.get("state") or data.get("hsrp_state") or "",
                    "vip": data.get("virtual_ip_address", ""),
                })
        if hsrp_list:
            return hsrp_list
    except Exception:
        pass
    # CLI fallback
    try:
        cli = device.execute('show standby brief')
        for line in cli.splitlines():
            if (not line.strip() or line.startswith("Interface")
                or line.startswith("---") or line.startswith("P indicates")):
                continue
            parts = line.split()
            if len(parts) >= 7:
                interface = parts[0]
                group = parts[1]
                priority = parts[2]
                offset = 1 if parts[3] == 'P' else 0
                state = parts[3+offset]
                # active = parts[4+offset]
                # standby = parts[5+offset]
                vip = parts[6+offset]
                hsrp_list.append({
                    "interface": interface,
                    "group": group,
                    "priority": priority,
                    "state": state,
                    "vip": vip,
                })
            elif len(parts) >= 6:
                interface = parts[0]
                group = parts[1]
                priority = parts[2]
                state = parts[3]
                # active = parts[4]
                # standby = parts[5]
                vip = parts[6] if len(parts) > 6 else ""
                hsrp_list.append({
                    "interface": interface,
                    "group": group,
                    "priority": priority,
                    "state": state,
                    "vip": vip,
                })
        return hsrp_list
    except Exception as e:
        hsrp_list.append({"error": f"HSRP fallback parse error: {e}"})
        return hsrp_list
    return hsrp_list

def get_route_summary(device):
    route_summary = {}
    vrf_list = get_vrf_list(device)
    os_hint = get_device_os(device)
    for vrf in vrf_list:
        try:
            if os_hint == "nxos":
                cmd = f'show ip route summary vrf {vrf}' if vrf != 'default' else 'show ip route summary'
                output = device.execute(cmd)
                match = re.search(r'Total number of routes:\s*(\d+)', output)
                count = int(match.group(1)) if match else 0
                route_summary[vrf] = count
            else:
                cmd = f'show ip route vrf {vrf}' if vrf != 'default' else 'show ip route'
                output = device.execute(cmd)
                count = 0
                for line in output.splitlines():
                    line = line.strip()
                    if not line or line.startswith("Codes:") or line.startswith("Gateway of last resort"):
                        continue
                    if re.match(r'^[A-Z* ]+\s+\d+\.\d+\.\d+\.\d+\/\d+', line):
                        count += 1
                route_summary[vrf] = count
        except Exception as e:
            route_summary[vrf] = f"Error: {e}"
    return route_summary

def get_running_config(device):
    os_hint = get_device_os(device)
    try:
        return device.execute("show running-config")
    except Exception as e:
        log.warning(f"Failed to collect running-config: {e}")
        return ""

def compare_baseline(old, new):
    differences = []
    old_ver, new_ver = old.get("version_info", {}), new.get("version_info", {})
    for k in ["model", "serial", "os_version"]:
        if old_ver.get(k) != new_ver.get(k):
            differences.append(f"Version info '{k}' changed: {old_ver.get(k)} → {new_ver.get(k)}")
    if old_ver.get("uptime") != new_ver.get("uptime"):
        differences.append(f"Uptime changed: {old_ver.get('uptime')} → {new_ver.get('uptime')}")
    for k in ["memory_utilization", "cpu_utilization"]:
        if old.get(k) != new.get(k):
            field_name = k.replace('_', ' ').title()
            differences.append(f"{field_name} changed: {old.get(k)} → {new.get(k)}")
    old_ints = {(i["interface"], i.get("vrf", "")): i["ip_address"] for i in old.get("interfaces", [])}
    new_ints = {(i["interface"], i.get("vrf", "")): i["ip_address"] for i in new.get("interfaces", [])}
    added = [f"{k[0]} ({v}) [vrf:{k[1]}]" for k, v in new_ints.items() if k not in old_ints]
    removed = [f"{k[0]} ({v}) [vrf:{k[1]}]" for k, v in old_ints.items() if k not in new_ints]
    changed = [f"{k[0]}: {old_ints[k]} → {new_ints[k]} [vrf:{k[1]}]" for k in old_ints if k in new_ints and old_ints[k] != new_ints[k]]
    if added:
        differences.append(f"Interfaces added: {', '.join(added)}")
    if removed:
        differences.append(f"Interfaces removed: {', '.join(removed)}")
    if changed:
        differences.append(f"Interfaces changed IP: {', '.join(changed)}")
    old_bgp = {(p['vrf'], p['peer_ip']): p for p in old.get('bgp_peers', [])}
    new_bgp = {(p['vrf'], p['peer_ip']): p for p in new.get('bgp_peers', [])}
    added_peers = set(new_bgp) - set(old_bgp)
    removed_peers = set(old_bgp) - set(new_bgp)
    for p in added_peers:
        differences.append(f"BGP peer added in VRF {p[0]}: {p[1]}")
    for p in removed_peers:
        differences.append(f"BGP peer removed from VRF {p[0]}: {p[1]}")
    for p in set(new_bgp) & set(old_bgp):
        for key in ["state", "routes", "local_as", "remote_as"]:
            if new_bgp[p].get(key) != old_bgp[p].get(key):
                differences.append(
                    f"BGP peer {p[1]} in VRF {p[0]} {key} changed: {old_bgp[p].get(key)} → {new_bgp[p].get(key)}"
                )
    def hsrp_key(entry):
        return (entry.get('interface'), entry.get('group'))
    old_hsrp = {hsrp_key(h): h for h in old.get('hsrp', []) if not h.get("error")}
    new_hsrp = {hsrp_key(h): h for h in new.get('hsrp', []) if not h.get("error")}
    added_hsrp = set(new_hsrp) - set(old_hsrp)
    removed_hsrp = set(old_hsrp) - set(new_hsrp)
    for h in added_hsrp:
        differences.append(f"HSRP group added: Interface {h[0]} Group {h[1]}")
    for h in removed_hsrp:
        differences.append(f"HSRP group removed: Interface {h[0]} Group {h[1]}")
    for h in set(new_hsrp) & set(old_hsrp):
        for key in ["priority", "state", "vip"]:
            if new_hsrp[h].get(key) != old_hsrp[h].get(key):
                differences.append(
                    f"HSRP {h[0]} group {h[1]} {key} changed: {old_hsrp[h].get(key)} → {new_hsrp[h].get(key)}"
                )
    for vrf in new.get("route_summary", {}):
        old_count = old.get("route_summary", {}).get(vrf)
        new_count = new.get("route_summary", {})[vrf]
        if old_count != new_count:
            differences.append(f"Route count changed in VRF {vrf}: {old_count} → {new_count}")
    return differences

def compare_running_config(old_config, new_config, context_lines=2):
    if not old_config or not new_config:
        return []
    old_filtered = filter_config_lines(old_config)
    new_filtered = filter_config_lines(new_config)
    old_lines = old_filtered.splitlines()
    new_lines = new_filtered.splitlines()
    diff = list(
        difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile="baseline",
            tofile="current",
            lineterm="",
            n=context_lines
        )
    )
    return diff if diff else None

def print_running_config_diff(diff_lines):
    if not diff_lines:
        panel = Panel(
            "[bold green]No config drift detected in running-config.[/bold green]",
            title="Running-config Drift",
            border_style="green",
        )
        console.print(panel)
        return

    diff_text = Text()
    max_len = 0
    for line in diff_lines:
        # Count printable length (no color codes)
        plain_line = line
        max_len = max(max_len, len(plain_line))
        if line.startswith("+") and not line.startswith("+++"):
            diff_text.append(line + "\n", style="green")
        elif line.startswith("-") and not line.startswith("---"):
            diff_text.append(line + "\n", style="red")
        elif line.startswith("@@"):
            diff_text.append(line + "\n", style="yellow")
        else:
            diff_text.append(line + "\n")

    # Add a small margin for panel borders and padding
    panel_width = max_len + 4

    panel = Panel(
        diff_text,
        title="Running-config Drift",
        border_style="yellow",
        width=panel_width,  # Set dynamically to content
    )
    console.print(panel)

def print_diff_table(differences):
    table = Table(title="🛑 Differences Detected", style="bold red")
    table.add_column("Item", style="yellow")
    table.add_column("Baseline", style="dim")
    table.add_column("Current", style="bold")
    for diff in differences:
        if diff.startswith("(Note)"):
            diff = diff[len("(Note)"):].strip()
        if "→" in diff:
            left, right = diff.split("→", 1)
            if ":" in left:
                item, baseline = left.split(":", 1)
                item = item.strip()
                baseline = baseline.strip()
            else:
                item = left.strip()
                baseline = ""
            current = right.strip()
        else:
            item = diff
            baseline = ""
            current = ""
        table.add_row(item, baseline, current)
    console.print(table)
# ... all your existing imports and code remain unchanged ...

def print_hsrp_summary(hsrp_list):
    """
    Pretty-prints an HSRP group summary table.
    If no HSRP groups are present, shows a friendly message in the table.
    """
    table = Table(title="===== HSRP Status =====", show_header=True, header_style="bold magenta")
    table.add_column("Interface", style="cyan")
    table.add_column("Group", style="blue")
    table.add_column("Priority", style="magenta")
    table.add_column("State", style="green")
    table.add_column("VIP", style="yellow")

    # No HSRP groups or only empty entries
    if not hsrp_list or all(not h.get("interface") for h in hsrp_list):
        table.add_row("No HSRP groups found or configured.", "", "", "", "")
    else:
        for h in hsrp_list:
            table.add_row(
                str(h.get("interface", "")),
                str(h.get("group", "")),
                str(h.get("priority", "")),
                str(h.get("state", "")),
                str(h.get("vip", "")),
            )
    console.print(table)

def print_summary(data):
    v = data.get("version_info", {})
    summary = Table(title="📋 Device Summary", style="bold green")
    summary.add_column("Field", style="cyan", no_wrap=True)
    summary.add_column("Value", style="magenta")
    summary.add_row("🖥️ Model", v.get('model', 'Unknown'))
    summary.add_row("🔢 Serial Number", v.get('serial', 'Unknown'))
    summary.add_row("⏱️ Uptime", v.get('uptime', 'Unknown'))
    summary.add_row("🛠️ OS Version", v.get('os_version', 'Unknown'))
    summary.add_row("💾 Memory Utilization", data.get('memory_utilization', 'Unknown'))
    summary.add_row("🧮 CPU Utilization", data.get('cpu_utilization', 'Unknown'))
    console.print(summary)

    # Print BGP Peers Table
    bgp_all_peers = data.get('bgp_peers', [])
    if bgp_all_peers:
        peer_table = Table(title="===== BGP Peers =====", style="bold cyan")
        peer_table.add_column("VRF", style="cyan")
        peer_table.add_column("Peer IP", style="green")
        peer_table.add_column("Local AS", style="blue")
        peer_table.add_column("Peer AS", style="bright_magenta")
        peer_table.add_column("Routes", style="magenta")
        peer_table.add_column("Uptime", style="green")
        peer_table.add_column("State", style="yellow")
        for peer in bgp_all_peers:
            peer_table.add_row(
                str(peer.get("vrf", "")),
                str(peer.get("peer_ip", "")),
                str(peer.get("local_as", "")),
                str(peer.get("remote_as", "")),
                str(peer.get("routes", "")),
                str(peer.get("uptime", "")),
                str(peer.get("state", "")),
            )
        console.print(peer_table)

    # Print HSRP Status Table (uses new, robust function)
    hsrp_list = data.get('hsrp', [])
    print_hsrp_summary(hsrp_list)

    # Print Interfaces Table
    interfaces = data.get('interfaces', [])
    table = Table(title="🌐 Layer 3 Interfaces Up with IP", style="bold blue")
    table.add_column("Interface", style="green")
    table.add_column("IP Address", style="magenta")
    table.add_column("VRF", style="cyan")
    if not interfaces:
        table.add_row("N/A", "N/A", "N/A")
    else:
        for intf in interfaces:
            table.add_row(
                intf.get('interface', 'N/A'),
                intf.get('ip_address', 'N/A'),
                intf.get('vrf', 'N/A')
            )
    console.print(table)

    # Print Route Summary Table
    route_summary = data.get('route_summary', {})
    table = Table(title="🗺️ Route Summary", style="bold purple")
    table.add_column("VRF", style="cyan")
    table.add_column("Total Routes", style="magenta")
    for vrf, count in route_summary.items():
        table.add_row(vrf, str(count))
    console.print(table)

# ... rest of your script remains unchanged ...
def print_summary_message(device_name, filename, mode):
    if mode == "1":
        console.print(f"\n[bold green]✅ Baseline collection complete![/bold green]")
        console.print(f"Results saved to: [bold]{filename}[/bold]")
        console.print("\n[bold cyan]Tip:[/bold cyan] To compare post-change, run:")
        console.print(f"  python baseline.py --device {device_name} --mode 2\n")
    elif mode == "2":
        console.print(f"\n[bold green]✅ Post-change comparison complete![/bold green]")
        console.print("\n[bold cyan]Tip:[/bold cyan] Review the differences above. If critical, consider reverting or further troubleshooting.")
    elif mode == "3":
        console.print(f"\n[bold green]✅ Snapshot comparison complete![/bold green]")
        console.print("\n[bold cyan]Tip:[/bold cyan] Review the differences above. To collect new baselines, use mode 1.")

def main():
    parser = argparse.ArgumentParser(
        description="Collect and compare Cisco switch/router baselines.",
        epilog=(
            "Examples:\n"
            "  python baseline.py --device C9300-SW1 --mode 1\n"
            "  python baseline.py --device N9K-01 --mode 2 --no-color\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--device", help="Device name (from testbed file)")
    parser.add_argument("--testbed", help="Testbed YAML file (default: testbed.yaml)")
    parser.add_argument("--mode", help="1=pre, 2=post, 3=compare snapshots")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--quiet", action="store_true", help="Suppress all output except errors")
    args = parser.parse_args()

    if args.no_color:
        console.no_color = True

    if args.mode:
        mode = args.mode
    else:
        console.print("\n[bold yellow]Choose mode:[/bold yellow]")
        console.print(" 1) Pre-change run (collect baseline data)")
        console.print(" 2) Post-change run (collect data and compare to baseline)")
        console.print(" 3) Compare two saved snapshots")
        mode = input("Enter choice (1, 2, or 3): ").strip()

    if mode == "1" or mode == "2":
        device_name = args.device or input("Enter device hostname: ").strip()
        testbed_file = args.testbed or input("Enter testbed YAML filename [testbed.yaml]: ").strip()
        if not testbed_file:
            testbed_file = "testbed.yaml"

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
            disable=args.no_color or args.quiet
        ) as progress:
            task = progress.add_task(f"[cyan]Collecting data for device {device_name}...", total=8)
            device = connect_device(testbed_file, device_name)
            if not device:
                print("Connection failed. Exiting.")
                return

            data = {}
            data['version_info'] = get_version_info(device); progress.advance(task)
            data['memory_utilization'] = get_memory_utilization(device); progress.advance(task)
            data['cpu_utilization'] = get_cpu_utilization(device); progress.advance(task)
            data['interfaces'] = get_interfaces(device); progress.advance(task)
            data['bgp_peers'] = get_bgp_summary(device); progress.advance(task)
            data['hsrp'] = get_hsrp_status(device); progress.advance(task)
            data['route_summary'] = get_route_summary(device); progress.advance(task)
            data['running_config'] = get_running_config(device); progress.advance(task)

        if mode == "1":
            log.info(f"Collecting baseline data for device {device_name}...")
            timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            filename = baseline_filename(device_name, timestamp)
            latest_filename = latest_baseline_filename(device_name)
            with open(filename, 'w') as f:
                json.dump(data, f, indent=4)
            shutil.copyfile(filename, latest_filename)
            log.info(f"Baseline data saved to {filename} and as 'latest' in {latest_filename}")

            if not args.quiet:
                print_summary(data)
                print_summary_message(device_name, filename, mode)
        elif mode == "2":
            log.info(f"Collecting current data for device {device_name} for comparison...")
            baseline = None
            try:
                latest_filename = latest_baseline_filename(device_name)
                with open(latest_filename, 'r') as f:
                    baseline = json.load(f)
            except Exception as e:
                print("Baseline data not found or failed to load. Cannot perform comparison.")
                return
            differences = compare_baseline(baseline, data)
            if differences and not args.quiet:
                print("\nDifferences detected between baseline and current data:")
                print_diff_table(differences)
            elif not args.quiet:
                print("\nNo differences detected between baseline and current data.")

            if not args.quiet:
                rc_diff = compare_running_config(baseline.get("running_config", ""), data.get("running_config", ""))
                print_running_config_diff(rc_diff)
                print_summary(data)
                print_summary_message(device_name, "<latest>", mode)

    elif mode == "3":
        base_dir = "baselines"
        if not os.path.exists(base_dir):
            print("\n❌ No baseline directory found.")
            return

        devices = sorted([d for d in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, d))])
        if not devices:
            print("\n❌ No device baselines found.")
            return

        print("\nAvailable devices:")
        for idx, dev in enumerate(devices, 1):
            print(f" {idx}) {dev}")
        choice = input("Select device by number: ").strip()
        try:
            device_name = devices[int(choice) - 1]
        except (ValueError, IndexError):
            print("\n❌ Invalid selection. Exiting.")
            return

        device_path = os.path.join(base_dir, device_name)
        snapshots = sorted(glob.glob(os.path.join(device_path, f"{device_name}_baseline_*.json")))
        if len(snapshots) < 2:
            print(f"\n❌ Not enough snapshots for {device_name} to compare (need at least 2).")
            return

        print(f"\nAvailable snapshots for {device_name}:")
        for idx, snap in enumerate(snapshots, 1):
            print(f" {idx}) {os.path.basename(snap)}")

        s1 = input("Select first snapshot by number: ").strip()
        s2 = input("Select second snapshot by number: ").strip()

        try:
            file1 = snapshots[int(s1) - 1]
            file2 = snapshots[int(s2) - 1]
        except (ValueError, IndexError):
            print("\n❌ Invalid snapshot selection. Exiting.")
            return

        try:
            with open(file1, 'r') as f1, open(file2, 'r') as f2:
                snapshot1 = json.load(f1)
                snapshot2 = json.load(f2)

            differences = compare_baseline(snapshot1, snapshot2)
            if differences:
                print("\nDifferences detected between the two snapshots:")
                print_diff_table(differences)
            else:
                print("\n✅ No differences detected between the two snapshots.")

            rc_diff = compare_running_config(snapshot1.get("running_config", ""), snapshot2.get("running_config", ""))
            print_running_config_diff(rc_diff)

            print("\nSnapshot 1 Summary:")
            print_summary(snapshot1)
            print("\nSnapshot 2 Summary:")
            print_summary(snapshot2)
            print_summary_message(device_name, file1, mode="3")

        except Exception as e:
            print(f"\n❌ Failed to load or compare snapshots: {e}")

    else:
        print("Invalid mode selected. Exiting.")

if __name__ == "__main__":
    main()
