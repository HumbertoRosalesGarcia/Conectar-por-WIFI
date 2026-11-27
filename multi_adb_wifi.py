import os
import sys
import socket
import struct
import subprocess
import concurrent.futures
import asyncio
import threading
import queue
import urllib.request
import urllib.parse
import re
import time
import json
import ctypes
import atexit
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import string
import random
import qrcode
from PIL import Image, ImageTk
from zeroconf import Zeroconf, ServiceBrowser
try:
    import windnd
except ImportError:
    windnd = None
try:
    import winsound
except ImportError:
    winsound = None

# ==============================================================================
# REGISTRO DE SUBPROCESOS: AL CERRAR EL PROGRAMA SE TERMINAN TODOS
# (ventanas de Scrcpy, puentes de audio/micrófono, comandos adb en curso, etc.)
# ==============================================================================

_OriginalPopen = subprocess.Popen
_CHILD_PROCS = set()
_CHILD_PROCS_LOCK = threading.Lock()
_APP_SHUTTING_DOWN = threading.Event()
_KILL_JOB = None  # (kernel32, handle) del Job Object de Windows


def _create_kill_on_close_job():
    """Crea un Job Object de Windows con KILL_ON_JOB_CLOSE: si este programa termina
    por cualquier motivo (incluso cerrado a la fuerza), Windows cierra los procesos asignados."""
    if os.name != "nt":
        return None
    try:
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateJobObjectW.restype = wintypes.HANDLE
        k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        k32.SetInformationJobObject.restype = wintypes.BOOL
        k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        k32.AssignProcessToJobObject.restype = wintypes.BOOL
        k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]

        class _BASIC(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                        ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD),
                        ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t),
                        ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t),
                        ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class _IO(ctypes.Structure):
            _fields_ = [(n, ctypes.c_uint64) for n in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class _EXTENDED(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", _BASIC),
                        ("IoInfo", _IO),
                        ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]

        job = k32.CreateJobObjectW(None, None)
        if not job:
            return None
        info = _EXTENDED()
        info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
            k32.CloseHandle(job)
            return None
        return (k32, job)
    except Exception:
        return None


def _is_scrcpy_command(args, kwargs):
    cmd = kwargs.get("args", args[0] if args else None)
    try:
        first = cmd if isinstance(cmd, str) else cmd[0]
        return "scrcpy" in os.path.basename(str(first)).lower()
    except Exception:
        return False


def _kill_process_tree(proc):
    """Termina un subproceso junto con los procesos hijos que haya lanzado."""
    try:
        if proc.poll() is not None:
            return
    except Exception:
        pass
    if os.name == "nt":
        try:
            _OriginalPopen(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           creationflags=subprocess.CREATE_NO_WINDOW).wait(timeout=4)
        except Exception:
            pass
    try:
        proc.kill()
    except Exception:
        pass


class _TrackedPopen(_OriginalPopen):
    """Popen que registra cada subproceso lanzado por el programa para cerrarlo al salir."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if kwargs.get("shell"):
            # Comandos de shell (p. ej. abrir el Explorador de Windows) no pertenecen a la app
            return
        with _CHILD_PROCS_LOCK:
            for p in list(_CHILD_PROCS):
                if p.returncode is not None:
                    _CHILD_PROCS.discard(p)
            _CHILD_PROCS.add(self)
        if _KILL_JOB and _is_scrcpy_command(args, kwargs):
            try:
                k32, job = _KILL_JOB
                k32.AssignProcessToJobObject(job, int(self._handle))
            except Exception:
                pass
        if _APP_SHUTTING_DOWN.is_set():
            _kill_process_tree(self)


def terminate_all_child_processes():
    """Cierra todas las ventanas de Scrcpy y demás subprocesos abiertos por el programa.
    No detiene el servidor global de adb."""
    global _KILL_JOB
    _APP_SHUTTING_DOWN.set()
    with _CHILD_PROCS_LOCK:
        procs = list(_CHILD_PROCS)
        _CHILD_PROCS.clear()
    workers = [threading.Thread(target=_kill_process_tree, args=(p,), daemon=True) for p in procs]
    for w in workers:
        w.start()
    deadline = time.time() + 5
    for w in workers:
        w.join(max(0.0, deadline - time.time()))
    if _KILL_JOB:
        try:
            k32, job = _KILL_JOB
            k32.CloseHandle(job)  # Windows cierra cualquier Scrcpy que siga vivo
        except Exception:
            pass
        _KILL_JOB = None


_KILL_JOB = _create_kill_on_close_job()
subprocess.Popen = _TrackedPopen
atexit.register(terminate_all_child_processes)

# ==============================================================================
# CONSTANTES Y BASE DE DATOS LOCAL DE DISPOSITIVOS CONOCIDOS / ESTÁTICOS
# ==============================================================================

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_LOCAL_KNOWN_DEVICES = os.path.join(_SCRIPT_DIR, "known_devices.json")
if os.path.exists(_LOCAL_KNOWN_DEVICES):
    KNOWN_DEVICES_FILE = _LOCAL_KNOWN_DEVICES
else:
    KNOWN_DEVICES_FILE = r"C:\Users\Administrador\AppData\Local\Programs\known_devices.json"
SCRCPY_EXE = r"C:\scrcpy\scrcpy.exe"
MIC_APK_PATH = os.path.join(_SCRIPT_DIR, "MicrofonoADB.apk")
MIC_APK_PACKAGE = "com.humber.micaudio"
MIC_APK_REMOTE_PORT = 17321
KDS_SOUNDS_DIR = os.path.join(_SCRIPT_DIR, "kds_sounds")
KDS_SOUND_FILES = {
    "service_bell": os.path.join(KDS_SOUNDS_DIR, "kds_alert_service_bell.wav"),
    "double_chime": os.path.join(KDS_SOUNDS_DIR, "kds_alert_double_chime.wav"),
    "kitchen_timer": os.path.join(KDS_SOUNDS_DIR, "kds_alert_kitchen_timer.wav"),
}

# Prefijos OUI conocidos para resolución instantánea sin peticiones HTTP externas
KNOWN_OUIS = {
    "CC:4B:73": "PAX Terminal",
    "C0:84:7D": "PAX Terminal",
    "70:3E:97": "PAX Terminal",
    "DC:2E:97": "LANDI POS",
    "B2:9E:85": "Samsung Tablet",
    "86:E1:DA": "Samsung Tablet",
    "F4:02:23": "Android Device",
    "DC:4F:22": "Espressif Inc.",
    "24:62:AB": "Espressif Inc.",
    "40:F5:20": "Espressif Inc.",
    "9C:9C:1F": "Espressif Inc.",
    "F4:CF:A2": "Espressif Inc.",
    "2C:F4:32": "Espressif Inc.",
    "E0:98:06": "Espressif Inc.",
    "08:33:ED": "Router Wi-Fi",
    "44:48:B9": "Router Wi-Fi",
    "B4:B0:24": "TP-Link",
    "E4:C3:2A": "TP-Link",
    "B0:2A:43": "Google Home / Cast",
    "D4:F5:47": "Google Device",
    "68:50:8C": "Sunmi POS",
    "CC:8C:BF": "Tuya Smart",
    "9C:AE:D3": "Epson Printer",
    "40:2F:86": "LG Electronics",
    "B8:8C:29": "Midea AC",
}

MAC_VENDOR_CACHE = {}

def load_known_devices():
    if os.path.exists(KNOWN_DEVICES_FILE):
        try:
            with open(KNOWN_DEVICES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                for ip, info in data.items():
                    mac = info.get("mac", "")
                    name = info.get("name", "")
                    if mac and name and mac != "Local":
                        MAC_VENDOR_CACHE[mac.upper()] = name
                return data
        except Exception:
            pass
    return {}

def save_known_device(ip, name="", mac="", is_static=False, last_port="", network=""):
    data = load_known_devices()
    existing = data.get(ip, {})
    existing["name"] = name or existing.get("name", "")
    existing["mac"] = mac or existing.get("mac", "")
    if is_static or existing.get("is_static", False):
        existing["is_static"] = True
    if last_port:
        existing["last_port"] = last_port
    if network:
        existing["network"] = network
    elif "network" not in existing:
        if ip in ("192.168.1.38", "192.168.1.39", "192.168.1.78", "192.168.1.200", "192.168.1.201", "192.168.1.211"):
            existing["network"] = "Sitio de Trabajo"
        else:
            existing["network"] = "Casa (Familia Rosales Martinez)"
    data[ip] = existing
    try:
        with open(KNOWN_DEVICES_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

# ==============================================================================
# RESOLUCIÓN HARDWARE ARP NATIVA (WINDOWS SendARP)
# ==============================================================================

send_arp_fn = ctypes.windll.iphlpapi.SendARP

_CACHED_WIFI_IP = ""
_LAST_WIFI_IP_CHECK = 0.0

def is_valid_lan_ipv4(ip_str):
    """Valida que la IP pertenezca a una red LAN real (descarta loopback, APIPA, Tailscale CGNAT y gadget paxusb)."""
    if not ip_str or not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", str(ip_str).strip()):
        return False
    parts = [int(x) for x in str(ip_str).strip().split(".")]
    if any(p > 255 for p in parts):
        return False
    a, b, c, d = parts
    if a == 127 or a == 0:
        return False
    if a == 169 and b == 254:
        return False
    # Ignorar rango CGNAT / Tailscale (100.64.0.0/10) y red USB gadget de PAX (192.168.44.x)
    if a == 100 and 64 <= b <= 127:
        return False
    if a == 192 and b == 168 and c == 44:
        return False
    return (a == 192 and b == 168) or (a == 10) or (a == 172 and 16 <= b <= 31)

def get_wifi_adapter_ip(force=False):
    """Detecta la IP LAN/Wi-Fi real del PC en cualquier red o subred sin depender de 192.168.1.x."""
    global _CACHED_WIFI_IP, _LAST_WIFI_IP_CHECK
    now = time.time()
    if not force and _CACHED_WIFI_IP and (now - _LAST_WIFI_IP_CHECK < 5.0):
        return _CACHED_WIFI_IP

    candidates = []
    # 1. Ruta de salida activa hacia Internet (no emite paquetes UDP reales)
    for target_probe in ("8.8.8.8", "1.1.1.1"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((target_probe, 80))
            ip = s.getsockname()[0]
            s.close()
            if is_valid_lan_ipv4(ip):
                _CACHED_WIFI_IP = ip
                _LAST_WIFI_IP_CHECK = now
                return ip
        except Exception:
            pass

    # 2. Interfaces configuradas en Windows (netsh wlan / ipconfig)
    cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    try:
        out = subprocess.run(["netsh", "interface", "ip", "show", "addresses"], capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=2).stdout
        cur_is_wifi = False
        for line in out.splitlines():
            low = line.lower()
            if "wi-fi" in low or "wifi" in low or "wlan" in low or "inal" in low:
                cur_is_wifi = True
            elif "configuraci" in low or "configuration" in low:
                cur_is_wifi = False
            m_ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if m_ip and ("ip" in low or "direcci" in low) and "dns" not in low and "puerta" not in low and "gateway" not in low and "máscara" not in low and "mask" not in low:
                cand = m_ip.group(1)
                if is_valid_lan_ipv4(cand):
                    if cur_is_wifi:
                        _CACHED_WIFI_IP = cand
                        _LAST_WIFI_IP_CHECK = now
                        return cand
                    candidates.append(cand)
    except Exception:
        pass

    # 3. Hostname IPs locales válidas (evitando .1 de adaptadores virtuales como VirtualBox/VMware)
    try:
        for cand in socket.gethostbyname_ex(socket.gethostname())[2]:
            if is_valid_lan_ipv4(cand) and not cand.endswith(".1"):
                candidates.append(cand)
    except Exception:
        pass

    if candidates:
        _CACHED_WIFI_IP = candidates[0]
        _LAST_WIFI_IP_CHECK = now
        return _CACHED_WIFI_IP

    _LAST_WIFI_IP_CHECK = now
    return _CACHED_WIFI_IP or "127.0.0.1"

def get_mac_sendarp(ip_str):
    """Obtiene la dirección MAC Layer-2 consultando primero la tabla ARP en memoria y solo si es necesario con SendARP."""
    ip_clean = str(ip_str).strip()
    cache = get_local_arp_cache()
    if ip_clean in cache:
        return cache[ip_clean]
    try:
        dest = struct.unpack('<I', socket.inet_aton(ip_clean))[0]
        mac_buf = (ctypes.c_ubyte * 6)()
        mac_len = ctypes.c_ulong(6)
        if send_arp_fn(dest, 0, ctypes.byref(mac_buf), ctypes.byref(mac_len)) == 0:
            return ":".join(f"{b:02X}" for b in mac_buf)
    except Exception:
        pass
    return None

def get_local_arp_cache():
    """Lee pasivamente la tabla ARP que Windows ya mantiene en memoria. Cero paquetes por el aire."""
    cache = {}
    cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    try:
        res = subprocess.run(["arp", "-a"], capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=1.5)
        for line in res.stdout.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+)", line)
            if m:
                ip, mac_raw = m.group(1), m.group(2).replace("-", ":").upper()
                if not mac_raw.startswith("FF:FF") and not mac_raw.startswith("01:00") and mac_raw != "00:00:00:00:00:00":
                    cache[ip] = mac_raw
    except Exception:
        pass
    return cache

def fast_subnet_arp_scan(subnet):
    """Lee caché ARP local; si la red es nueva o tiene pocos equipos en caché, despierta ARP en 0.4s sin saturar."""
    results = get_local_arp_cache()
    subnet_prefix = f"{subnet}."
    existing_in_subnet = [ip for ip in results.keys() if ip.startswith(subnet_prefix)]
    if subnet and subnet != "127.0.0" and len(existing_in_subnet) < 3:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setblocking(False)
            for i in range(1, 255):
                try:
                    s.sendto(b"", (f"{subnet}.{i}", 9))
                except Exception:
                    pass
            s.close()
            time.sleep(0.35)
            results = get_local_arp_cache()
        except Exception:
            pass
    return results

SUBNET_SLICE_SIZE = 64
def scan_subnet_slice(subnet, slice_idx):
    """Desactivado en bucle de fondo para no emitir ráfagas broadcast de ARP por Wi-Fi."""
    return get_local_arp_cache()

# ==============================================================================
# RESOLUCIÓN DINÁMICA DE TARGET ADB / SCRCPY (TODOS LOS PUERTOS Y PROTOCOLOS)
# ==============================================================================


_ANDROID_LS_LINE_RE = re.compile(
    r"^([drwxsStTlcbps\-]{10})[.+]?\s+"
    r"(?:\d+\s+)??"
    r"\S+\s+\S+\s+"
    r"(?:(\d+)(?:,\s*\d+)?\s+)?"
    r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})\s+"
    r"(.+)$"
)


def parse_android_ls_line(line):
    """Parsea una línea de `ls -la` compatible con Toolbox (Android 6.x como E800) y Toybox (Android 7+)."""
    clean = str(line or "").strip()
    m = _ANDROID_LS_LINE_RE.match(clean)
    if not m:
        return None
    perms, size_str_raw, dt, raw_name = m.groups()
    is_link = perms.startswith("l")
    name = raw_name.split(" -> ", 1)[0] if (is_link and " -> " in raw_name) else raw_name
    if name in (".", ".."):
        return None
    is_dir = perms.startswith("d")
    size = int(size_str_raw) if (size_str_raw and size_str_raw.isdigit()) else 0
    return {
        "name": name,
        "is_dir": is_dir,
        "is_link": is_link,
        "size": size,
        "date": dt,
    }


def get_device_mounted_drive(device_name="", ip_or_serial=""):
    """Detecta la letra de unidad asignada por AndroidDrive (ej. 'E:', 'G:') para este dispositivo."""
    if os.name != "nt":
        return None
    try:
        k32 = ctypes.windll.kernel32
        buf = ctypes.create_unicode_buffer(1024)
        n = k32.GetLogicalDriveStringsW(1024, buf)
        drives = [d for d in buf[:n].split("\x00") if d and k32.GetDriveTypeW(d) == 3]
        if not drives:
            return None

        def _probe_drive(root_path):
            vol = ctypes.create_unicode_buffer(256)
            fs = ctypes.create_unicode_buffer(256)
            ok = k32.GetVolumeInformationW(root_path, vol, 256, None, None, None, fs, 256)
            if ok:
                return root_path.rstrip("\\"), vol.value.strip(), fs.value.strip().lower()
            return None

        # Consultar unidades en paralelo (evita bloqueos o timeouts de PowerShell/WMI con múltiples dispositivos)
        win_fs = {"ntfs", "fat", "fat32", "exfat", "refs", "cdfs", "udf"}
        android_disks = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(12, len(drives))) as ex:
            for info in ex.map(_probe_drive, drives):
                if not info:
                    continue
                dev_id, vol, fs = info
                if dev_id and vol and fs not in win_fs:
                    android_disks.append((dev_id, vol.lower(), re.sub(r"[\s_\-]+", "", vol.lower())))

        dev_name_low = str(device_name or "").lower()
        dev_compact = re.sub(r"[\s_\-\[\]]+", "", dev_name_low)
        for prefix in ("pax", "sunmi", "landi", "samsung", "dispositivo", "estatica", "estática", "estatico", "estático"):
            dev_compact = dev_compact.replace(prefix, "")

        noise_words = {"dispositivo", "android", "samsung", "pax", "sunmi", "landi", "estatica", "estática", "estatico", "estático", "usb", "wifi"}
        name_words = [w for w in re.split(r"[\s\-_\[\]]+", dev_name_low) if len(w) >= 2 and w not in noise_words]
        ip_serial_low = str(ip_or_serial or "").strip().lower()

        if dev_compact:
            for dev_id, _vol_low, vol_compact in android_disks:
                if dev_compact == vol_compact or (len(dev_compact) >= 3 and dev_compact in vol_compact):
                    return dev_id

        for dev_id, vol_low, vol_compact in android_disks:
            if name_words and any(w in vol_low or w in vol_compact for w in name_words):
                return dev_id
            if ip_serial_low and ip_serial_low in vol_low:
                return dev_id
    except Exception:
        pass
    return None

def resolve_active_adb_target(serial_or_ip, dev=None):
    """
    Determina con precisión absoluta el identificador (-s) que ADB y scrcpy reconocen
    para este dispositivo en este momento:
    - Serial USB directo (ej. R52N90AHV9W)
    - IP:Puerto estándar (ej. 192.168.1.79:5555, 192.168.1.38:5555)
    - IP:Puerto dinámico Wi-Fi (ej. 192.168.1.78:45249 en Landi C20DS)
    - Serial mDNS TLS (ej. adb-25B6CCU00340-q0IVTD._adb-tls-connect._tcp)
    """
    cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    target_str = str(serial_or_ip or "").strip()

    try:
        res = subprocess.run(["adb", "devices", "-l"], capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=3)
    except Exception:
        return target_str

    active_devices = []
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("List of"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            ep = parts[0]
            model = ""
            for p in parts[2:]:
                if p.startswith("model:"):
                    model = p.split(":", 1)[1]
            active_devices.append((ep, model))

    # 0. Si dev es un renglón Wi-Fi explícito, buscar primero si su IP ya está conectada en ADB
    if dev and not dev.get("is_usb") and dev.get("ip"):
        wifi_ip = str(dev["ip"]).strip()
        for ep, _ in active_devices:
            if ep.startswith(f"{wifi_ip}:"):
                return ep

    # 1. Coincidencia exacta con el target solicitado
    for ep, _ in active_devices:
        if ep == target_str:
            return ep

    # Extraer IP de búsqueda
    ip_to_match = ""
    if dev and dev.get("ip") and not dev.get("is_usb"):
        ip_to_match = str(dev["ip"]).strip()
    elif re.search(r"\b(\d+\.\d+\.\d+\.\d+)\b", target_str):
        ip_to_match = re.search(r"\b(\d+\.\d+\.\d+\.\d+)\b", target_str).group(1)

    # 2. Si tenemos IP, buscar si algún dispositivo activo en ADB coincide con esa IP
    if ip_to_match:
        # A) Coincidencia directa IP:puerto
        for ep, _ in active_devices:
            if ep.startswith(f"{ip_to_match}:"):
                return ep

        # B) Coincidencia a través de adb mdns services
        try:
            m_res = subprocess.run(["adb", "mdns", "services"], capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=2)
            for m_line in m_res.stdout.splitlines():
                m_parts = m_line.split()
                if len(m_parts) >= 3 and m_parts[-1].startswith(f"{ip_to_match}:"):
                    svc_name = m_parts[0]
                    for ep, _ in active_devices:
                        if ep.startswith(svc_name) or svc_name in ep:
                            return ep
        except Exception:
            pass

    # 3. Coincidencia por modelo reportado en adb
    dev_model = dev.get("name", "") if dev else ""
    if dev_model:
        for ep, model in active_devices:
            if model and (model.lower() in dev_model.lower() or dev_model.lower() in model.lower()):
                return ep

    # 4. Coincidencia por serial guardado en el objeto dev
    if dev and dev.get("serial"):
        for ep, _ in active_devices:
            if ep == dev["serial"]:
                return ep

    return target_str

# ==============================================================================
# SERVICIO DE MONTAJE DE ALMACENAMIENTO EN "ESTE EQUIPO" (DOKAN / ANDROIDDRIVE)
# ==============================================================================

def ensure_storage_mount():
    # Desactivado para evitar alertas modales molestas de AndroidDrive cuando dispositivos reconectan
    pass

# ==============================================================================
# DETECCIÓN DE PANTALLAS Y CONTROL REMOTO (SCRCPY EN VENTANA NORMAL)
# ==============================================================================

def get_device_displays(serial_or_ip, device_name="", dev=None):
    """Detecta cuántas pantallas tiene el dispositivo (ej. E700 -> [0], E800 -> [0, 1])."""
    if "e800" in (device_name or "").lower():
        return [0, 1]
    resolved_target = resolve_active_adb_target(serial_or_ip, dev=dev)
    cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    try:
        res = subprocess.run(["adb", "-s", str(resolved_target), "shell", "dumpsys", "display"],
                             capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=2)
        matches = re.findall(r'DisplayDeviceInfo\{[^}]+uniqueId="local:(\d+)"', res.stdout)
        if matches:
            displays = sorted(list(set(int(m) for m in matches)))
            return displays
        count = len(re.findall(r"DisplayDeviceInfo\{", res.stdout))
        return list(range(max(1, count)))
    except Exception:
        if "e800" in str(serial_or_ip).lower():
            return [0, 1]
        return [0]

def ensure_device_internet_stability(target):
    """
    Garantiza que el dispositivo Android mantenga su conexión a Internet activa, rápida y estable
    mientras se proyecta la pantalla por Wi-Fi o USB:
    1. Desactiva wifi_watchdog_poor_network_test (que erróneamente marca 'Sin Internet' al subir la latencia de Wi-Fi).
    2. Desactiva wifi_suspend_optimizations_enabled (evita que el Wi-Fi se duerma al apagar pantalla).
    3. Fija wifi_sleep_policy a 2 (NEVER suspender Wi-Fi al apagar la pantalla).
    4. Desactiva network_avoid_bad_wifi (evita desconexión automática por congestión momentánea).
    5. Desactiva auto-switch a datos móviles de Samsung (Intelligent Wi-Fi) por jitter de video scrcpy.
    """
    def _bg():
        cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        cmd_str = (
            "settings put global wifi_watchdog_poor_network_test_enabled 0; "
            "settings put global wifi_suspend_optimizations_enabled 0; "
            "settings put global wifi_sleep_policy 2; "
            "settings put global network_avoid_bad_wifi 0; "
            "settings put global sem_wifi_switch_to_better_wifi_enabled 0; "
            "settings put global wifi_switch_to_mobile_data_super_aggressive_mode_on 0"
        )
        try:
            subprocess.run(["adb", "-s", str(target), "shell", cmd_str],
                           capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=3)
        except Exception:
            pass
    threading.Thread(target=_bg, daemon=True).start()

# ==============================================================================
# AUDIO POR MICRÓFONO (ANDROID 11+ NATIVO / ANDROID < 11 VÍA MicrofonoADB.apk)
# ==============================================================================

_DEV_SDK_CACHE = {}
_DEV_MIC_PKG_CACHE = {}
_DEV_PROBE_INFLIGHT = set()
_DEV_MIC_CACHE_LOCK = threading.Lock()
_ACTIVE_LEGACY_MIC_COUNTS = {}
_ACTIVE_LEGACY_MIC_PLAYERS = set()
_ACTIVE_LEGACY_MIC_LOCK = threading.Lock()


def _mic_cache_keys(serial_or_ip, dev=None):
    keys = []
    if dev:
        for k in (dev.get("key"), dev.get("ip"), dev.get("serial")):
            if k and str(k) not in keys:
                keys.append(str(k))
    if serial_or_ip:
        s = str(serial_or_ip).strip()
        if s and s not in keys:
            keys.append(s)
        if ":" in s and not s.startswith("USB:"):
            host = s.split(":", 1)[0]
            if host and host not in keys:
                keys.append(host)
    return keys


def sync_dev_mic_caches(dev):
    """Copia en memoria los valores cacheados de Android SDK e instalación de MicrofonoADB."""
    if not dev:
        return
    with _DEV_MIC_CACHE_LOCK:
        for k in _mic_cache_keys(dev.get("serial"), dev=dev):
            if k in _DEV_SDK_CACHE:
                dev["android_sdk"] = _DEV_SDK_CACHE[k]
                break
        for k in _mic_cache_keys(dev.get("serial"), dev=dev):
            if k in _DEV_MIC_PKG_CACHE:
                dev["mic_apk_installed"] = _DEV_MIC_PKG_CACHE[k]
                break


def get_device_android_sdk(serial_or_ip, dev=None, force_refresh=False):
    """Obtiene y cachea ro.build.version.sdk del dispositivo conectado por ADB."""
    keys = _mic_cache_keys(serial_or_ip, dev=dev)
    if not force_refresh:
        with _DEV_MIC_CACHE_LOCK:
            for k in keys:
                if k in _DEV_SDK_CACHE:
                    return _DEV_SDK_CACHE[k]

    resolved_target = resolve_active_adb_target(serial_or_ip, dev=dev)
    if not resolved_target:
        return None
    cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    try:
        res = subprocess.run(
            ["adb", "-s", str(resolved_target), "shell", "getprop", "ro.build.version.sdk"],
            capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=2.5
        )
        raw = (res.stdout or "").strip()
        if raw.isdigit():
            sdk = int(raw)
            with _DEV_MIC_CACHE_LOCK:
                for k in set(keys + _mic_cache_keys(resolved_target, dev=dev)):
                    _DEV_SDK_CACHE[k] = sdk
            if dev is not None:
                dev["android_sdk"] = sdk
            return sdk
    except Exception:
        pass
    return None


def is_mic_apk_installed(serial_or_ip, dev=None, force_refresh=False):
    """Verifica si com.humber.micaudio (MicrofonoADB.apk) está instalado en el dispositivo."""
    keys = _mic_cache_keys(serial_or_ip, dev=dev)
    if not force_refresh:
        with _DEV_MIC_CACHE_LOCK:
            for k in keys:
                if k in _DEV_MIC_PKG_CACHE:
                    return _DEV_MIC_PKG_CACHE[k]

    resolved_target = resolve_active_adb_target(serial_or_ip, dev=dev)
    if not resolved_target:
        return False
    cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    try:
        res = subprocess.run(
            ["adb", "-s", str(resolved_target), "shell", "pm", "path", MIC_APK_PACKAGE],
            capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=2.5
        )
        # Solo interpretar respuesta válida del comando pm (evita falsos negativos si ADB falló)
        out = (res.stdout or "").strip()
        err = (res.stderr or "").strip().lower()
        if "device offline" in err or "not found" in err:
            return None
        installed = ("package:" in out)
        with _DEV_MIC_CACHE_LOCK:
            for k in set(keys + _mic_cache_keys(resolved_target, dev=dev)):
                _DEV_MIC_PKG_CACHE[k] = installed
        if dev is not None:
            dev["mic_apk_installed"] = installed
        return installed
    except Exception:
        return None


def install_mic_apk_on_device(serial_or_ip, dev=None):
    """Instala MicrofonoADB.apk en un dispositivo Android < 11 y otorga el permiso RECORD_AUDIO."""
    if not os.path.exists(MIC_APK_PATH):
        return False, f"No se encontró el archivo APK en:\n{MIC_APK_PATH}"

    resolved_target = resolve_active_adb_target(serial_or_ip, dev=dev)
    if not resolved_target:
        return False, "No se pudo resolver el objetivo ADB activo."

    cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    try:
        res = subprocess.run(
            ["adb", "-s", str(resolved_target), "install", "-r", "-g", MIC_APK_PATH],
            capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=30
        )
        out_all = f"{res.stdout or ''}\n{res.stderr or ''}".strip()
        if res.returncode != 0 and ("-g" in out_all or "unknown option" in out_all.lower()):
            res = subprocess.run(
                ["adb", "-s", str(resolved_target), "install", "-r", MIC_APK_PATH],
                capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=30
            )
            out_all = f"{res.stdout or ''}\n{res.stderr or ''}".strip()

        if res.returncode != 0 or "Success" not in out_all:
            return False, out_all or f"Código de salida ADB: {res.returncode}"

        try:
            subprocess.run(
                ["adb", "-s", str(resolved_target), "shell", "pm", "grant", MIC_APK_PACKAGE, "android.permission.RECORD_AUDIO"],
                capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=5
            )
        except Exception:
            pass

        with _DEV_MIC_CACHE_LOCK:
            for k in _mic_cache_keys(resolved_target, dev=dev):
                _DEV_MIC_PKG_CACHE[k] = True
        if dev is not None:
            dev["mic_apk_installed"] = True
        return True, "MicrofonoADB instalado correctamente."
    except subprocess.TimeoutExpired:
        return False, "Tiempo de espera agotado al instalar MicrofonoADB.apk."
    except Exception as e:
        return False, str(e)


class _WAVEFORMATEX(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("wFormatTag", ctypes.c_ushort),
        ("nChannels", ctypes.c_ushort),
        ("nSamplesPerSec", ctypes.c_uint32),
        ("nAvgBytesPerSec", ctypes.c_uint32),
        ("nBlockAlign", ctypes.c_ushort),
        ("wBitsPerSample", ctypes.c_ushort),
        ("cbSize", ctypes.c_ushort),
    ]


class _WAVEHDR(ctypes.Structure):
    _fields_ = [
        ("lpData", ctypes.c_char_p),
        ("dwBufferLength", ctypes.c_uint32),
        ("dwBytesRecorded", ctypes.c_uint32),
        ("dwUser", ctypes.c_size_t),
        ("dwFlags", ctypes.c_uint32),
        ("dwLoops", ctypes.c_uint32),
        ("lpNext", ctypes.c_void_p),
        ("reserved", ctypes.c_size_t),
    ]


class WinmmPcmPlayer:
    """Reproductor de audio PCM 16-bit de baja latencia usando winmm.dll nativo de Windows."""
    WAVE_MAPPER = 0xFFFFFFFF
    WAVE_FORMAT_PCM = 1
    CALLBACK_EVENT = 0x00050000
    WHDR_DONE = 0x00000001

    def __init__(self, sample_rate=44100, channels=1, bits_per_sample=16, num_buffers=8):
        self.winmm = ctypes.WinDLL("winmm", use_last_error=False)
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=False)

        self.winmm.waveOutOpen.argtypes = [
            ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint, ctypes.POINTER(_WAVEFORMATEX),
            ctypes.c_size_t, ctypes.c_size_t, ctypes.c_uint32
        ]
        self.winmm.waveOutOpen.restype = ctypes.c_uint
        self.winmm.waveOutPrepareHeader.argtypes = [ctypes.c_void_p, ctypes.POINTER(_WAVEHDR), ctypes.c_uint]
        self.winmm.waveOutPrepareHeader.restype = ctypes.c_uint
        self.winmm.waveOutWrite.argtypes = [ctypes.c_void_p, ctypes.POINTER(_WAVEHDR), ctypes.c_uint]
        self.winmm.waveOutWrite.restype = ctypes.c_uint
        self.winmm.waveOutUnprepareHeader.argtypes = [ctypes.c_void_p, ctypes.POINTER(_WAVEHDR), ctypes.c_uint]
        self.winmm.waveOutUnprepareHeader.restype = ctypes.c_uint
        self.winmm.waveOutReset.argtypes = [ctypes.c_void_p]
        self.winmm.waveOutReset.restype = ctypes.c_uint
        self.winmm.waveOutClose.argtypes = [ctypes.c_void_p]
        self.winmm.waveOutClose.restype = ctypes.c_uint

        self.kernel32.CreateEventW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p]
        self.kernel32.CreateEventW.restype = ctypes.c_void_p
        self.kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.kernel32.WaitForSingleObject.restype = ctypes.c_uint32
        self.kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        self.kernel32.CloseHandle.restype = ctypes.c_int

        block_align = channels * (bits_per_sample // 8)
        wfx = _WAVEFORMATEX()
        wfx.wFormatTag = self.WAVE_FORMAT_PCM
        wfx.nChannels = channels
        wfx.nSamplesPerSec = sample_rate
        wfx.nAvgBytesPerSec = sample_rate * block_align
        wfx.nBlockAlign = block_align
        wfx.wBitsPerSample = bits_per_sample
        wfx.cbSize = 0

        self.event = self.kernel32.CreateEventW(None, 0, 0, None)
        self.hwo = ctypes.c_void_p()
        res = self.winmm.waveOutOpen(
            ctypes.byref(self.hwo),
            self.WAVE_MAPPER,
            ctypes.byref(wfx),
            self.event or 0,
            0,
            self.CALLBACK_EVENT if self.event else 0,
        )
        if res != 0:
            if self.event:
                self.kernel32.CloseHandle(self.event)
                self.event = None
            raise OSError(f"waveOutOpen failed with code {res}")

        self.slots = [{"buf": None, "hdr": _WAVEHDR(), "in_use": False} for _ in range(num_buffers)]
        self._closed = False
        self._lock = threading.Lock()
        with _ACTIVE_LEGACY_MIC_LOCK:
            _ACTIVE_LEGACY_MIC_PLAYERS.add(self)

    def write(self, data):
        if self._closed or not data:
            return
        while not self._closed:
            with self._lock:
                if self._closed or not self.hwo:
                    return
                slot = None
                for s in self.slots:
                    if not s["in_use"]:
                        slot = s
                        break
                    if s["hdr"].dwFlags & self.WHDR_DONE:
                        self.winmm.waveOutUnprepareHeader(self.hwo, ctypes.byref(s["hdr"]), ctypes.sizeof(_WAVEHDR))
                        s["in_use"] = False
                        s["buf"] = None
                        slot = s
                        break
                if slot is not None:
                    c_buf = ctypes.create_string_buffer(data, len(data))
                    hdr = slot["hdr"]
                    ctypes.memset(ctypes.byref(hdr), 0, ctypes.sizeof(_WAVEHDR))
                    hdr.lpData = ctypes.cast(c_buf, ctypes.c_char_p)
                    hdr.dwBufferLength = len(data)
                    res_p = self.winmm.waveOutPrepareHeader(self.hwo, ctypes.byref(hdr), ctypes.sizeof(_WAVEHDR))
                    if res_p != 0:
                        raise OSError(f"waveOutPrepareHeader failed: {res_p}")
                    slot["buf"] = c_buf
                    slot["in_use"] = True
                    res_w = self.winmm.waveOutWrite(self.hwo, ctypes.byref(hdr), ctypes.sizeof(_WAVEHDR))
                    if res_w != 0:
                        self.winmm.waveOutUnprepareHeader(self.hwo, ctypes.byref(hdr), ctypes.sizeof(_WAVEHDR))
                        slot["in_use"] = False
                        slot["buf"] = None
                        raise OSError(f"waveOutWrite failed: {res_w}")
                    return
            if self.event:
                self.kernel32.WaitForSingleObject(self.event, 50)
            else:
                time.sleep(0.01)

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self.hwo:
                try:
                    self.winmm.waveOutReset(self.hwo)
                except Exception:
                    pass
                for s in self.slots:
                    if s["in_use"]:
                        try:
                            self.winmm.waveOutUnprepareHeader(self.hwo, ctypes.byref(s["hdr"]), ctypes.sizeof(_WAVEHDR))
                        except Exception:
                            pass
                        s["in_use"] = False
                        s["buf"] = None
                try:
                    self.winmm.waveOutClose(self.hwo)
                except Exception:
                    pass
                self.hwo = None
            if self.event:
                try:
                    self.kernel32.CloseHandle(self.event)
                except Exception:
                    pass
                self.event = None
        with _ACTIVE_LEGACY_MIC_LOCK:
            _ACTIVE_LEGACY_MIC_PLAYERS.discard(self)


def close_all_legacy_mic_players():
    with _ACTIVE_LEGACY_MIC_LOCK:
        players = list(_ACTIVE_LEGACY_MIC_PLAYERS)
    for p in players:
        try:
            p.close()
        except Exception:
            pass
    stop_all_kds_alarm_sound_bridges()


_ACTIVE_KDS_BRIDGES = {}
_ACTIVE_KDS_SCRCPY_PROCS = {}
_ACTIVE_KDS_LOCK = threading.Lock()


def play_kds_alert_sound(sound_key="service_bell"):
    """Reproduce de forma asíncrona en el PC el archivo WAV original del timbre KDS."""
    if winsound is None or os.name != "nt":
        return False
    wav_path = KDS_SOUND_FILES.get(sound_key) or KDS_SOUND_FILES.get("service_bell")
    if not wav_path or not os.path.exists(wav_path):
        return False
    try:
        winsound.PlaySound(wav_path, winsound.SND_FILENAME | winsound.SND_ASYNC | winsound.SND_NODEFAULT)
        return True
    except Exception:
        return False


def has_open_scrcpy_window_for(device_name=""):
    """Verifica en <0.2ms mediante Win32 EnumWindows si hay una ventana de scrcpy abierta para el dispositivo."""
    if os.name != "nt":
        return False
    needle = (device_name or "").strip().lower()
    if not needle:
        return False
    found = [False]
    try:
        u32 = ctypes.windll.user32
        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)

        def _cb(hwnd, _lparam):
            if u32.IsWindowVisible(hwnd):
                length = u32.GetWindowTextLengthW(hwnd)
                if length > 0:
                    buf = ctypes.create_unicode_buffer(length + 1)
                    u32.GetWindowTextW(hwnd, buf, length + 1)
                    title = buf.value.lower()
                    if needle in title and ("control remoto" in title or "pantalla cliente" in title or "scrcpy" in title):
                        found[0] = True
                        return 0
            return 1

        u32.EnumWindows(WNDENUMPROC(_cb), 0)
    except Exception:
        pass
    return found[0]


def stop_all_kds_alarm_sound_bridges():
    with _ACTIVE_KDS_LOCK:
        procs = list(_ACTIVE_KDS_BRIDGES.values())
        _ACTIVE_KDS_BRIDGES.clear()
        _ACTIVE_KDS_SCRCPY_PROCS.clear()
    for p in procs:
        try:
            p.terminate()
        except Exception:
            pass


def start_kds_alarm_sound_bridge(resolved_target, scrcpy_proc=None, device_name="", dev=None):
    """
    Escucha en tiempo real por ADB los eventos de alarma KDS (KdsAlertPlayer / USAGE_ALARM)
    en dispositivos sin micrófono físico (como SUNMI D2s_KDS_STGL) y reproduce el mismo WAV en el PC.
    """
    target_str = str(resolved_target or "").strip()
    if not target_str:
        return

    with _ACTIVE_KDS_LOCK:
        if scrcpy_proc is not None:
            _ACTIVE_KDS_SCRCPY_PROCS.setdefault(target_str, set()).add(scrcpy_proc)
        existing = _ACTIVE_KDS_BRIDGES.get(target_str)
        if existing is not None and existing.poll() is None:
            return

    cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

    def _worker():
        log_proc = None
        try:
            actual_target = str(resolve_active_adb_target(target_str, dev=dev) or target_str)
            log_proc = subprocess.Popen(
                ["adb", "-s", actual_target, "logcat", "-T", "1", "-s", "KdsAlertPlayer:D"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=cflags,
            )
            with _ACTIVE_KDS_LOCK:
                prev = _ACTIVE_KDS_BRIDGES.get(target_str)
                if prev is not None and prev.poll() is None and prev is not log_proc:
                    try:
                        log_proc.terminate()
                    except Exception:
                        pass
                    return
                _ACTIVE_KDS_BRIDGES[target_str] = log_proc

            t_start = time.monotonic()
            state = {"last_kds_ts": 0.0, "last_sound": "service_bell"}

            def _watchdog():
                while log_proc.poll() is None:
                    time.sleep(1.5)
                    with _ACTIVE_KDS_LOCK:
                        if target_str not in _ACTIVE_KDS_SCRCPY_PROCS:
                            continue
                        pset = _ACTIVE_KDS_SCRCPY_PROCS.get(target_str, set())
                        alive = {p for p in pset if p.poll() is None}
                        _ACTIVE_KDS_SCRCPY_PROCS[target_str] = alive
                        has_proc = bool(alive)
                    if not has_proc:
                        try:
                            log_proc.terminate()
                        except Exception:
                            pass
                        break

            threading.Thread(target=_watchdog, daemon=True).start()

            for raw_line in log_proc.stdout:
                if time.monotonic() - t_start < 0.40:
                    continue
                line = raw_line.strip()
                if not line:
                    continue
                low = line.lower()
                if "kdsalertplayer" in low and any(k in low for k in ("sonó", "sono", "service_bell", "double_chime", "kitchen_timer")):
                    if "double_chime" in low or "doble" in low:
                        s_key = "double_chime"
                    elif "kitchen_timer" in low or "timer" in low or "alarma" in low:
                        s_key = "kitchen_timer"
                    else:
                        s_key = "service_bell"
                    state["last_sound"] = s_key
                    state["last_kds_ts"] = time.monotonic()
                    play_kds_alert_sound(s_key)
                elif "af::trackhandle" in low and "opplayaudio:" in low and "usage:4" in low and "not muted" in low:
                    def _delayed_fallback():
                        time.sleep(0.16)
                        if time.monotonic() - state["last_kds_ts"] > 0.35:
                            state["last_kds_ts"] = time.monotonic()
                            play_kds_alert_sound(state["last_sound"])
                    threading.Thread(target=_delayed_fallback, daemon=True).start()
        except Exception:
            pass
        finally:
            with _ACTIVE_KDS_LOCK:
                if _ACTIVE_KDS_BRIDGES.get(target_str) is log_proc:
                    _ACTIVE_KDS_BRIDGES.pop(target_str, None)
            if log_proc is not None and log_proc.poll() is None:
                try:
                    log_proc.terminate()
                except Exception:
                    pass

    threading.Thread(target=_worker, daemon=True).start()


def start_android_legacy_mic_stream(resolved_target, scrcpy_proc, device_name=""):
    """Conecta por adb forward con MicrofonoADB en Android < 11 y reproduce su micrófono mientras scrcpy esté abierto."""
    cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

    def _worker():
        target_str = str(resolved_target)
        local_port = None
        sock = None
        player = None
        counted = False

        try:
            time.sleep(0.25)
            if scrcpy_proc is not None and scrcpy_proc.poll() is not None:
                return

            with _ACTIVE_LEGACY_MIC_LOCK:
                _ACTIVE_LEGACY_MIC_COUNTS[target_str] = _ACTIVE_LEGACY_MIC_COUNTS.get(target_str, 0) + 1
                counted = True

            # Asignar un puerto local TCP libre para túnel ADB
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tmp_s:
                tmp_s.bind(("127.0.0.1", 0))
                local_port = tmp_s.getsockname()[1]

            subprocess.run(
                ["adb", "-s", target_str, "forward", f"tcp:{local_port}", f"tcp:{MIC_APK_REMOTE_PORT}"],
                capture_output=True, text=True, creationflags=cflags, timeout=5
            )

            # Garantizar permiso e iniciar el servicio en primer plano mediante MainActivity transparente
            try:
                subprocess.run(
                    ["adb", "-s", target_str, "shell", "pm", "grant", MIC_APK_PACKAGE, "android.permission.RECORD_AUDIO"],
                    capture_output=True, creationflags=cflags, timeout=4
                )
            except Exception:
                pass

            subprocess.run(
                ["adb", "-s", target_str, "shell", "am", "start", "-n", f"{MIC_APK_PACKAGE}/.MainActivity"],
                capture_output=True, text=True, creationflags=cflags, timeout=6
            )

            # Reintentar conexión hasta que el servicio esté escuchando en loopback
            for _ in range(20):
                if scrcpy_proc is not None and scrcpy_proc.poll() is not None:
                    return
                try:
                    sock = socket.create_connection(("127.0.0.1", local_port), timeout=1.5)
                    break
                except Exception:
                    time.sleep(0.15)

            if sock is None:
                return

            sock.settimeout(3.0)
            hdr = b""
            while len(hdr) < 12:
                chunk = sock.recv(12 - len(hdr))
                if not chunk:
                    return
                hdr += chunk

            if hdr[:4] != b"MIC1":
                return
            sample_rate, channels, bits = struct.unpack("<IHH", hdr[4:12])
            if sample_rate <= 0 or channels not in (1, 2) or bits not in (8, 16):
                return

            player = WinmmPcmPlayer(sample_rate=sample_rate, channels=channels, bits_per_sample=bits)
            sock.settimeout(1.0)
            while scrcpy_proc is None or scrcpy_proc.poll() is None:
                try:
                    pcm = sock.recv(4096)
                    if not pcm:
                        break
                    player.write(pcm)
                except socket.timeout:
                    continue
                except Exception:
                    break
        except Exception:
            pass
        finally:
            if player is not None:
                player.close()
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
            if local_port is not None:
                try:
                    subprocess.run(
                        ["adb", "-s", target_str, "forward", "--remove", f"tcp:{local_port}"],
                        capture_output=True, creationflags=cflags, timeout=3
                    )
                except Exception:
                    pass
            if counted:
                should_stop_service = False
                with _ACTIVE_LEGACY_MIC_LOCK:
                    rem = max(0, _ACTIVE_LEGACY_MIC_COUNTS.get(target_str, 1) - 1)
                    if rem == 0:
                        _ACTIVE_LEGACY_MIC_COUNTS.pop(target_str, None)
                        should_stop_service = True
                    else:
                        _ACTIVE_LEGACY_MIC_COUNTS[target_str] = rem
                if should_stop_service:
                    try:
                        subprocess.run(
                            ["adb", "-s", target_str, "shell", "am", "force-stop", MIC_APK_PACKAGE],
                            capture_output=True, creationflags=cflags, timeout=4
                        )
                    except Exception:
                        pass

    threading.Thread(target=_worker, daemon=True).start()


def launch_remote_control(serial_or_ip, display_id=0, device_name="", dev=None, turn_screen_off=False, audio_source=None):
    """
    Lanza una ventana NORMAL de scrcpy (minimizables y maximizables, NO en pantalla completa)
    con optimizaciones de hardware para Allwinner/Rockchip, preservación de ancho de banda Wi-Fi
    y sin consolas negras.
    Compatible con CUALQUIER puerto (5555, dinámico Wi-Fi o TLS mDNS).
    turn_screen_off: Si es True, apaga la pantalla física del dispositivo manteniendo el control remoto total.
    audio_source: None (por defecto sin cambios), o 'mic' para escuchar por micrófono (Android 11+ nativo, < 11 vía MicrofonoADB.apk).
    """
    if not os.path.exists(SCRCPY_EXE):
        messagebox.showerror("Error", f"No se encontró el archivo scrcpy en: {SCRCPY_EXE}")
        return

    # Resolver el serial exacto activo en ADB para evitar "device not found"
    resolved_target = resolve_active_adb_target(serial_or_ip, dev=dev)

    # Blindar y estabilizar la conexión a Internet del dispositivo en segundo plano
    ensure_device_internet_stability(resolved_target)

    name_clean = device_name or (dev.get("name") if dev else "") or str(resolved_target)

    legacy_mic_target = None
    use_scrcpy_mic = False
    if audio_source == "mic":
        sdk = get_device_android_sdk(resolved_target, dev=dev)
        if sdk is not None and sdk < 30:
            installed = is_mic_apk_installed(resolved_target, dev=dev)
            if not installed:
                if not os.path.exists(MIC_APK_PATH):
                    messagebox.showwarning(
                        "APK no encontrado",
                        f"{name_clean} tiene Android < 11 (SDK {sdk}), pero no se encontró:\n{MIC_APK_PATH}"
                    )
                    return
                resp = messagebox.askyesno(
                    "Instalar MicrofonoADB",
                    f"{name_clean} usa Android < 11 (SDK {sdk}).\n\n"
                    "Para escuchar los sonidos físicos por el micrófono se requiere la mini app 'MicrofonoADB'.\n\n"
                    "¿Deseas instalarla automáticamente ahora y abrir la pantalla con micrófono?"
                )
                if not resp:
                    return
                ok_inst, err_inst = install_mic_apk_on_device(resolved_target, dev=dev)
                if not ok_inst:
                    messagebox.showerror("Error al instalar MicrofonoADB", f"No se pudo instalar en {name_clean}:\n{err_inst}")
                    return
            legacy_mic_target = resolved_target
        else:
            use_scrcpy_mic = True

    suffix_parts = []
    if turn_screen_off:
        suffix_parts.append("🕶 Pantalla Física Apagada")
    if audio_source == "mic":
        suffix_parts.append("🎙 Micrófono")
    suffix = f" [{' | '.join(suffix_parts)}]" if suffix_parts else ""

    if display_id == 0:
        win_title = f"{name_clean} (Control Remoto){suffix}"
    else:
        win_title = f"{name_clean} (Pantalla Cliente {display_id}){suffix}"

    is_kds_no_hw_mic = ("d2s" in name_clean.lower() or "kds" in name_clean.lower())

    cmd = [SCRCPY_EXE, "-s", str(resolved_target)]
    if legacy_mic_target:
        cmd.append("--no-audio")
    elif use_scrcpy_mic and not is_kds_no_hw_mic:
        cmd.append("--audio-source=mic")
    elif display_id > 0:
        cmd.append("--no-audio")
    if turn_screen_off:
        cmd.extend(["--turn-screen-off", "--stay-awake"])

    is_wifi = ":" in str(resolved_target)
    is_e700 = "e700" in name_clean.lower() or "uranus" in name_clean.lower()
    is_pax = any(p in name_clean.lower() for p in ["e700", "e800", "a80", "a920", "a930", "aries", "uranus", "paydroid", "pax"])

    if not is_e700 and not is_wifi:
        try:
            cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            m_res = subprocess.run(["adb", "-s", str(resolved_target), "shell", "getprop", "ro.product.model"],
                                   capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=2)
            model_out = m_res.stdout.lower()
            if "e700" in model_out:
                is_e700 = True
            if any(p in model_out for p in ["e700", "e800", "a80", "a920", "a930", "aries", "uranus", "paydroid", "pax"]):
                is_pax = True
        except Exception:
            pass

    if display_id > 0:
        # Pantalla secundaria (ej. pantalla cliente PAX E800 / E700)
        cmd.extend(["--display-id", str(display_id), "-m", "1024", "-b", "2M", "--max-fps", "30", "-p", str(27180 + display_id)])
    elif is_e700:
        # Terminal PAX E700: software encoder OMX para estabilidad de PayDroid
        cmd.extend(["--video-encoder=OMX.google.h264.encoder", "-m", "1024", "-b", "2M", "--max-fps", "25"])
    elif is_pax:
        # Terminales PAX (A80, E800, etc.): bitrate moderado para radio Wi-Fi 2.4GHz
        cmd.extend(["-m", "1024", "-b", "2M", "--max-fps", "25"])
    elif is_wifi:
        # Dispositivos Android estándar vía Wi-Fi (Samsung Galaxy, tablets, etc.):
        # Se fija resolución máx 1024, bitrate 2M y 30 FPS.
        # Esto reduce el consumo de espectro Wi-Fi en más del 65% respecto a 90/120Hz sin límite,
        # dejando el canal completamente libre para navegación fluida, descargas y llamadas en el teléfono.
        cmd.extend(["-m", "1024", "-b", "2M", "--max-fps", "30"])
    else:
        # Conexión directa por cable USB: alta tasa de transferencia sin interferencia con la radio Wi-Fi
        cmd.extend(["-m", "1280", "-b", "6M", "--max-fps", "60"])

    cmd.extend(["--window-title", win_title])

    cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

    def _launch_and_check():
        try:
            proc = subprocess.Popen(cmd, creationflags=cflags, stderr=subprocess.PIPE, text=True, errors="replace")
            if legacy_mic_target:
                start_android_legacy_mic_stream(legacy_mic_target, proc, device_name=name_clean)
            if display_id == 0 and (audio_source == "mic" or is_kds_no_hw_mic):
                start_kds_alarm_sound_bridge(resolved_target, scrcpy_proc=proc, device_name=name_clean)
            try:
                ret = proc.wait(timeout=2.0)
                if ret != 0 and not _APP_SHUTTING_DOWN.is_set():
                    err_lines = proc.stderr.read()
                    err_msg = err_lines.strip().splitlines()[-1] if err_lines.strip() else f"Código de salida: {ret}"
                    messagebox.showerror("Error en Pantalla", f"No se pudo proyectar la pantalla de {name_clean}:\n{err_msg}")
            except subprocess.TimeoutExpired:
                # En ejecución normal. Drenar stderr en segundo plano para evitar bloqueos
                def _drain(pipe):
                    try:
                        while pipe.read(1024):
                            pass
                    except Exception:
                        pass
                    finally:
                        try:
                            pipe.close()
                        except Exception:
                            pass
                threading.Thread(target=_drain, args=(proc.stderr,), daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error al Iniciar", f"No se pudo iniciar el control remoto: {e}")

    threading.Thread(target=_launch_and_check, daemon=True).start()

# ==============================================================================
# DESCUBRIMIENTO AUTOMÁTICO DE DISPOSITIVOS USB Y WI-FI EN TIEMPO REAL
# ==============================================================================

def get_current_wifi_ssid():
    cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    try:
        out = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=2).stdout
        m = re.search(r"^\s*SSID\s*:\s*(.+)$", out, re.MULTILINE)
        if m:
            return m.group(1).strip()
    except Exception:
        pass
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", "(Get-NetConnectionProfile).Name"], capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=2).stdout.strip()
        if out:
            return out.splitlines()[0].strip()
    except Exception:
        pass
    return ""

def get_default_gateway_for_subnet(subnet):
    """Detecta la puerta de enlace real de la subred actual (ej. .1, .254, hotspot, etc.)."""
    cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    try:
        out = subprocess.run(["route", "print", "0.0.0.0"], capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=1.5).stdout
        for line in out.splitlines():
            m = re.search(rf"0\.0\.0\.0\s+0\.0\.0\.0\s+({re.escape(subnet)}\.\d+)", line)
            if m:
                return m.group(1)
    except Exception:
        pass
    return f"{subnet}.1" if subnet and subnet != "127.0.0" else "127.0.0.1"

def get_network_info():
    local_ip = get_wifi_adapter_ip(force=True)
    parts = local_ip.split(".")
    subnet = ".".join(parts[:3]) if len(parts) == 4 else "192.168.1"
    gateway_ip = get_default_gateway_for_subnet(subnet)

    ssid = get_current_wifi_ssid()
    if ssid:
        if "familia" in ssid.lower() or "rosales" in ssid.lower():
            net_name = "Casa (Familia Rosales Martinez)"
        elif "trabajo" in ssid.lower() or "pos" in ssid.lower() or "oficina" in ssid.lower() or "<" in ssid or "*_*" in ssid or "-_-" in ssid:
            net_name = "Sitio de Trabajo"
        else:
            net_name = f"Wi-Fi: {ssid}"
    else:
        net_name = f"Red Local ({subnet}.0/24)"

    return local_ip, subnet, gateway_ip, net_name

def is_randomized_mac(mac):
    if not mac or len(mac) < 2:
        return False
    return mac[1].upper() in ("2", "6", "A", "E")

def lookup_mac_vendor_fast(mac):
    """Búsqueda ultra-rápida en caché local y prefijos OUI conocidos sin bloquear con HTTP."""
    if not mac or mac == "Local":
        return ""
    mac_up = mac.upper()
    if mac_up in MAC_VENDOR_CACHE:
        return MAC_VENDOR_CACHE[mac_up]
    oui = mac_up[:8]
    if oui in KNOWN_OUIS:
        return KNOWN_OUIS[oui]
    if is_randomized_mac(mac_up):
        return "Dispositivo Móvil Wi-Fi (MAC Privada)"
    return ""

def _async_fetch_vendor(mac, ip, callback=None):
    """Consulta asíncrona no bloqueante de vendor a api.macvendors.com."""
    try:
        url = f"https://api.macvendors.com/{urllib.parse.quote(mac)}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            vendor = resp.read().decode("utf-8", errors="ignore").strip()
            if vendor:
                MAC_VENDOR_CACHE[mac.upper()] = vendor
                save_known_device(ip, name=vendor, mac=mac)
                if callback:
                    callback(ip, vendor)
    except Exception:
        pass

def enable_tcpip_on_usb_devices():
    # No ejecutar de forma automática en segundo plano para evitar reiniciar adbd inesperadamente
    pass

_USB_PORT_PROBE_CACHE = {}

def get_usb_device_net_details(serial, cflags=0):
    """Consulta rápida (<0.15s) de las IPs reales activas en el dispositivo (wlan0, eth0, etc.) y modelo."""
    wlan_ip = ""
    all_ips = []
    model = ""
    try:
        cmd_str = "ip -4 -o addr show; echo __MOD__; getprop ro.product.model; echo __DHCP__; getprop dhcp.wlan0.ipaddress"
        res = subprocess.run(["adb", "-s", str(serial), "shell", cmd_str],
                             capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=2.5)
        out = res.stdout or ""
        parts_mod = out.split("__MOD__")
        addr_sec = parts_mod[0]
        rest = parts_mod[1] if len(parts_mod) > 1 else ""
        parts_dhcp = rest.split("__DHCP__")
        mod_val = parts_dhcp[0].strip().splitlines()[0].strip() if parts_dhcp[0].strip() else ""
        dhcp_val = parts_dhcp[1].strip().splitlines()[0].strip() if len(parts_dhcp) > 1 and parts_dhcp[1].strip() else ""
        if mod_val:
            model = mod_val

        wifi_cands = []
        eth_cands = []
        other_cands = []
        for l_iface in addr_sec.splitlines():
            m_i = re.search(r"^\d+:\s+([^\s:]+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)", l_iface.strip())
            if not m_i:
                continue
            if_name, ip_addr = m_i.group(1).lower(), m_i.group(2)
            # Ignorar loopback, gadget USB interno PAX (paxusb0), datos celulares o link-local
            if if_name.startswith(("lo", "paxusb", "rndis", "rmnet", "ccmni", "dummy")):
                continue
            if ip_addr.startswith(("127.", "169.254.", "192.168.44.")):
                continue
            if if_name.startswith("wlan"):
                wifi_cands.append(ip_addr)
            elif if_name.startswith("eth"):
                eth_cands.append(ip_addr)
            else:
                other_cands.append(ip_addr)

        if not wifi_cands and re.match(r"^\d+\.\d+\.\d+\.\d+$", dhcp_val) and not dhcp_val.startswith(("127.", "169.254.", "192.168.44.")):
            wifi_cands.append(dhcp_val)

        all_ips = wifi_cands + eth_cands + other_cands
        if all_ips:
            wlan_ip = all_ips[0]
    except Exception:
        pass
    return {"wlan_ip": wlan_ip, "all_ips": all_ips, "model": model}

def get_usb_device_ssid_and_mac(serial, cflags=0):
    """Obtiene el SSID Wi-Fi actual al que está conectado el terminal y su MAC wlan0."""
    ssid = ""
    mac = ""
    try:
        res = subprocess.run(
            ["adb", "-s", str(serial), "shell", "dumpsys wifi | grep -m1 mWifiInfo; echo __MAC__; cat /sys/class/net/wlan0/address 2>/dev/null"],
            capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=3.0
        )
        out = res.stdout or ""
        sec = out.split("__MAC__")
        wifi_sec = sec[0]
        m_s = re.search(r"SSID:\s*([^,\]]+)", wifi_sec)
        if m_s:
            cand_s = m_s.group(1).strip().strip('"')
            if cand_s and cand_s.lower() not in ("<unknown ssid>", "null", "0x"):
                ssid = cand_s
        if len(sec) > 1:
            m_m = re.search(r"([0-9a-fA-F:]{17})", sec[1])
            if m_m and m_m.group(1).lower() != "02:00:00:00:00:00":
                mac = m_m.group(1).upper()
        if not mac:
            m_m2 = re.search(r"MAC:\s*([0-9a-fA-F:]{17})", wifi_sec)
            if m_m2 and m_m2.group(1).lower() != "02:00:00:00:00:00":
                mac = m_m2.group(1).upper()
    except Exception:
        pass
    return ssid, mac

def apply_safe_wifi_adb_props_async(target, port=5555, cflags=0):
    """Aplica propiedades seguras nativas y configuración global sin bloquear ni reiniciar adbd."""
    def _bg():
        try:
            subprocess.run(
                ["adb", "-s", str(target), "shell",
                 f"setprop persist.pax.adb.tcp.port {port}; setprop persist.adb.tcp.port {port}; "
                 f"setprop persist.sys.adb.tcp.port {port}; setprop persist.sys.enable.tcpip true"],
                capture_output=True, text=True, creationflags=cflags, timeout=4
            )
        except Exception:
            pass
        try:
            subprocess.run(
                ["adb", "-s", str(target), "shell",
                 f"settings put global adb_port {port}; settings put global adb_wifi_enabled 1; settings put global adb_allowed_connection_time 0"],
                capture_output=True, text=True, creationflags=cflags, timeout=8
            )
        except Exception:
            pass
    threading.Thread(target=_bg, daemon=True).start()

def prepare_usb_device_for_wifi_adb(serial, cflags=0, port=5555, force_tcpip=False):
    """Configura persistencia de forma segura y activa el puerto TCP/IP en el terminal USB sin colgar adbd ni abortar por timeout de settings."""
    # 1. Solo setprop nativo rápido (NUNCA incluir settings put aquí para evitar TimeoutExpired de 3s, ni pax.ctrl.adbd.as.root)
    try:
        fast_props = (
            f"setprop persist.pax.adb.tcp.port {port}; "
            f"setprop persist.adb.tcp.port {port}; "
            f"setprop persist.sys.adb.tcp.port {port}; "
            f"setprop persist.sys.enable.tcpip true"
        )
        subprocess.run(["adb", "-s", str(serial), "shell", fast_props], capture_output=True, text=True, creationflags=cflags, timeout=5)
    except Exception:
        pass

    # 2. Comprobar si service.adb.tcp.port ya está activo en el puerto deseado
    need_tcpip = force_tcpip
    if not need_tcpip:
        try:
            cur_p = subprocess.run(["adb", "-s", str(serial), "shell", "getprop service.adb.tcp.port"],
                                   capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=2.5).stdout.strip()
            if cur_p != str(port):
                need_tcpip = True
        except Exception:
            need_tcpip = True

    tcpip_ok = not need_tcpip
    if need_tcpip:
        for attempt in range(2):
            try:
                t_res = subprocess.run(["adb", "-s", str(serial), "tcpip", str(port)],
                                       capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=6)
                out_t = (t_res.stdout + t_res.stderr).lower()
                if "restarting in tcp mode" in out_t or t_res.returncode == 0:
                    tcpip_ok = True
                    break
            except Exception:
                pass
            if attempt == 0:
                try:
                    subprocess.run(["adb", "reconnect", "offline"], capture_output=True, creationflags=cflags, timeout=2)
                    time.sleep(1.0)
                except Exception:
                    pass
        if tcpip_ok:
            time.sleep(2.4)

    # 3. settings put global en segundo plano (tarda 2.3-4s en Android/PayDroid)
    apply_safe_wifi_adb_props_async(serial, port=port, cflags=cflags)
    return tcpip_ok

def wake_device_to_pc_route(serial, pc_ip, cflags=0):
    """Emite ping desde el terminal hacia el PC vía USB para despertar el radio Wi-Fi y poblar la tabla ARP entre bandas 2.4GHz/5GHz."""
    if not pc_ip or pc_ip == "127.0.0.1":
        return False, ""
    try:
        res = subprocess.run(["adb", "-s", str(serial), "shell", f"ping -c 2 -W 1 {pc_ip}"],
                             capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=5)
        out = (res.stdout + res.stderr).strip()
        ok = (res.returncode == 0) or ("ttl=" in out.lower() and "0 received" not in out.lower() and "100% packet loss" not in out.lower())
        return ok, out
    except Exception as e:
        return False, str(e)

def connect_adb_endpoint_verified(ep, cflags=0, attempts=2):
    """Conecta ADB al endpoint IP:puerto y verifica handshake real en estado 'device' (no 'offline')."""
    last_out = ""
    is_unauth = False
    for att in range(attempts):
        try:
            subprocess.run(["adb", "disconnect", ep], capture_output=True, text=True, creationflags=cflags, timeout=2)
            time.sleep(0.2)
        except Exception:
            pass
        try:
            c_res = subprocess.run(["adb", "connect", ep], capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=11)
            last_out = (c_res.stdout + c_res.stderr).strip()
        except Exception as e:
            last_out = str(e)

        # Confirmar estado real durante ~3s
        saw_offline = False
        for _ in range(10):
            time.sleep(0.3)
            try:
                devs_out = subprocess.run(["adb", "devices"], capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=2).stdout
                for line in devs_out.splitlines():
                    if ep in line:
                        parts = line.split()
                        st = parts[1] if len(parts) >= 2 else ""
                        if st == "device":
                            return True, last_out, False
                        elif st == "unauthorized":
                            return False, "Requiere autorizar la PC en la pantalla del dispositivo.", True
                        elif st == "offline":
                            saw_offline = True
            except Exception:
                pass
        if saw_offline:
            try:
                subprocess.run(["adb", "disconnect", ep], capture_output=True, creationflags=cflags, timeout=2)
            except Exception:
                pass
        if att == 0:
            time.sleep(1.0)
    return False, last_out or f"Sin respuesta ADB en {ep}", is_unauth

def get_usb_connected_devices():
    """Detecta los dispositivos conectados directamente por cable USB reconocidos por ADB (online, offline o no autorizados)."""
    usb_devs = []
    cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    try:
        res = subprocess.run(["adb", "devices", "-l"], capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=3)
        active_wifi_eps = set()
        for l_chk in res.stdout.splitlines():
            p_chk = l_chk.strip().split()
            if len(p_chk) >= 2 and p_chk[1] == "device" and ":" in p_chk[0]:
                active_wifi_eps.add(p_chk[0])

        cur_pc_ip = get_wifi_adapter_ip()
        cur_subnet = ".".join(cur_pc_ip.split(".")[:3]) if "." in cur_pc_ip else ""

        for line in res.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("List of"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                serial = parts[0]
                status = parts[1]
                if ":" in serial or "_adb-tls" in serial:
                    continue

                if status not in ("device", "offline", "unauthorized"):
                    continue

                model = ""
                for p in parts[2:]:
                    if p.startswith("model:"):
                        model = p.split(":", 1)[1]

                if not model and serial == "1340003718":
                    model = "E700"
                elif not model and serial.startswith("1070"):
                    model = "E800"

                # SIEMPRE priorizar la IP real en vivo de wlan0/eth0 para soportar CUALQUIER red Wi-Fi
                wlan_ip = ""
                if status == "device":
                    net_det = get_usb_device_net_details(serial, cflags=cflags)
                    if net_det.get("wlan_ip"):
                        wlan_ip = net_det["wlan_ip"]
                    if net_det.get("model") and not model:
                        model = net_det["model"]

                # Solo usar referencia estática 192.168.1.204/205 si el USB está offline/no responde y seguimos en 192.168.1.x
                if not wlan_ip and cur_subnet == "192.168.1":
                    if serial == "1340003718":
                        wlan_ip = "192.168.1.205"
                    elif serial.startswith("1070"):
                        wlan_ip = "192.168.1.204"

                disp_name = f"PAX {model}" if (model.startswith("E") or model.startswith("A")) else (model or f"Android ({serial})")
                if "e800" in disp_name.lower():
                    displays = [0, 1]
                elif "e700" in disp_name.lower():
                    displays = [0]
                elif status == "device":
                    displays = get_device_displays(serial, device_name=disp_name)
                else:
                    displays = [0]

                is_5555_open = False
                if wlan_ip:
                    if f"{wlan_ip}:5555" in active_wifi_eps:
                        is_5555_open = True
                        _USB_PORT_PROBE_CACHE[wlan_ip] = (time.time(), True)
                    else:
                        now_ts = time.time()
                        cached = _USB_PORT_PROBE_CACHE.get(wlan_ip)
                        if cached and (now_ts - cached[0] < 30.0):
                            is_5555_open = cached[1]
                        else:
                            is_5555_open = bool(check_tcp_ports_fast(wlan_ip, [5555], timeout=1.0))
                            _USB_PORT_PROBE_CACHE[wlan_ip] = (now_ts, is_5555_open)

                is_online = (status == "device")
                is_off = (status == "offline")
                is_unauth = (status == "unauthorized")

                usb_devs.append({
                    "key": f"USB:{serial}",
                    "ip": f"USB (IP: {wlan_ip})" if wlan_ip else f"USB ({serial})",
                    "wlan_ip": wlan_ip,
                    "mac": "USB Directo",
                    "name": disp_name,
                    "port": "USB",
                    "serial": serial,
                    "is_adb_connected": is_online,
                    "is_offline": is_off,
                    "is_unauthorized": is_unauth,
                    "is_port_open": is_5555_open,
                    "is_local_or_router": False,
                    "is_static": False,
                    "is_usb": True,
                    "displays": displays
                })
    except Exception:
        pass
    return usb_devs

def _build_mdns_query(qname, qtype=12, qclass=0x0001, txid=0x1234):
    """Construye una consulta DNS-SD/mDNS estándar (RFC 6762 §6.7 Legacy Unicast)."""
    q = struct.pack("!HHHHHH", txid & 0xFFFF, 0x0000, 1, 0, 0, 0)
    for part in str(qname).strip(".").split("."):
        if part:
            b = part.encode("utf-8", errors="ignore")[:63]
            q += bytes([len(b)]) + b
    q += b"\x00" + struct.pack("!HH", qtype, qclass)
    return q


def _decode_dns_name(data, offset):
    """Decodifica un nombre DNS con soporte de punteros de compresión RFC 1035."""
    labels = []
    jumped = False
    orig_off = offset
    seen = set()
    n = len(data)
    while offset < n:
        if offset in seen:
            break
        seen.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= n:
                offset = n
                break
            ptr = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                orig_off = offset + 2
                jumped = True
            offset = ptr
        else:
            offset += 1
            if offset + length > n:
                break
            labels.append(data[offset:offset + length].decode("utf-8", errors="replace"))
            offset += length
    return ".".join(labels), (orig_off if jumped else offset)


def _parse_mdns_response(data):
    """Extrae registros PTR, SRV, A y TXT de una respuesta DNS/mDNS."""
    if not data or len(data) < 12:
        return []
    try:
        _, _, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    except Exception:
        return []
    off = 12
    n = len(data)
    for _ in range(qd):
        if off >= n:
            return []
        _, off = _decode_dns_name(data, off)
        off += 4
    records = []
    for _ in range(an + ns + ar):
        if off + 10 > n:
            break
        name, off = _decode_dns_name(data, off)
        if off + 10 > n:
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        if off + rdlen > n:
            break
        roff = off
        rdata = data[off:off + rdlen]
        off += rdlen
        if rtype == 12:  # PTR
            ptr, _ = _decode_dns_name(data, roff)
            records.append(("PTR", name, ptr))
        elif rtype == 33 and len(rdata) >= 6:  # SRV
            _prio, _weight, port = struct.unpack("!HHH", rdata[:6])
            target, _ = _decode_dns_name(data, roff + 6)
            records.append(("SRV", name, port, target))
        elif rtype == 1 and len(rdata) >= 4:  # A
            records.append(("A", name, socket.inet_ntoa(rdata[:4])))
        elif rtype == 16:  # TXT
            i = 0
            txts = []
            while i < len(rdata):
                ln = rdata[i]
                i += 1
                if i + ln <= len(rdata):
                    txts.append(rdata[i:i + ln].decode("utf-8", errors="replace"))
                i += ln
            records.append(("TXT", name, txts))
    return records


def query_unicast_mdns_adb(target_ips=None, service_type="_adb-tls-connect._tcp.local",
                           local_ip="", wait_s=0.65, bursts=2, stop_event=None,
                           use_multicast_broadcast=True, instance_name=""):
    """
    Consulta mDNS usando QU=1 (0x8001, RFC 6762 §5.4) + Legacy Unicast (RFC 6762 §6.7)
    desde un puerto origen efímero local -> obliga TANTO a native mdnsd (Android 11-13 y
    _adb-tls-connect) COMO a Java MdnsRecordRepository (Android 14-16 _adb-tls-pairing)
    a responder por UNICAST directo a nuestro socket exclusivo.
    Envía por 3 vías simultáneas en el mismo socket efímero:
      1) Multicast 224.0.0.251:5353
      2) Broadcast de subred <subnet>.255:5353
      3) Unicast directo <ip>:5353 a target_ips
    Retorna lista de dicts: [{"instance", "service", "ip", "port", "model"}].
    """
    ips = [str(ip).strip() for ip in (target_ips or []) if ip and is_valid_lan_ipv4(str(ip).strip())]
    u_local = local_ip if (local_ip and is_valid_lan_ipv4(local_ip)) else get_wifi_adapter_ip()
    if not ips and not use_multicast_broadcast:
        return []

    svc_clean = service_type.strip(".")
    svc_short = svc_clean[:-6] if svc_clean.lower().endswith(".local") else svc_clean
    # CRÍTICO para Android 14/15/16 (Java MdnsRecordRepository):
    # getReply() SOLO responde unicast (dest = src) si el bit QU (0x8000 -> qclass=0x8001) está activo.
    q_pkts = [
        _build_mdns_query(svc_clean, qtype=12, qclass=0x8001, txid=0),
        _build_mdns_query(svc_clean, qtype=12, qclass=0x0001, txid=random.randint(1, 65534)),
    ]
    if instance_name:
        full_inst = f"{str(instance_name).strip('.')}.{svc_clean}"
        # Consulta SRV directa con QU=1 -> en Android 14-16 dispara delayMs=0 (respuesta inmediata)
        q_pkts.insert(0, _build_mdns_query(full_inst, qtype=33, qclass=0x8001, txid=0))

    bcast_ip = ""
    if u_local and is_valid_lan_ipv4(u_local):
        bcast_ip = ".".join(u_local.split(".")[:3]) + ".255"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Evitar WinError 10054 (ICMP Port Unreachable) al sondear múltiples IPs en Windows
        if hasattr(socket, "SIO_UDP_CONNRESET"):
            try:
                sock.ioctl(socket.SIO_UDP_CONNRESET, False)
            except Exception:
                pass
        if use_multicast_broadcast:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            except Exception:
                pass
        if u_local and is_valid_lan_ipv4(u_local):
            try:
                sock.bind((u_local, 0))
            except Exception:
                sock.bind(("", 0))
            if use_multicast_broadcast:
                try:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(u_local))
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
                except Exception:
                    pass
        else:
            sock.bind(("", 0))
        sock.settimeout(0.18)

        found_map = {}  # (ip, port, instance) -> dict
        srv_requested = set()

        for b_idx in range(max(1, int(bursts))):
            if stop_event and stop_event.is_set():
                break
            if use_multicast_broadcast:
                for qp in q_pkts:
                    try:
                        sock.sendto(qp, ("224.0.0.251", 5353))
                    except Exception:
                        pass
                    if bcast_ip:
                        try:
                            sock.sendto(qp, (bcast_ip, 5353))
                        except Exception:
                            pass
            for ip in ips:
                if ip == u_local:
                    continue
                # Para consultas unicast masivas (/24), enviar los paquetes QU=1 (evita duplicar tráfico)
                uni_pkts = q_pkts[:2] if len(ips) > 30 else q_pkts
                for qp in uni_pkts:
                    try:
                        sock.sendto(qp, (ip, 5353))
                    except Exception:
                        pass

            deadline = time.time() + (wait_s if b_idx == 0 else max(wait_s, 0.75))
            while time.time() < deadline:
                if stop_event and stop_event.is_set():
                    break
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    continue
                sender_ip = addr[0]
                recs = _parse_mdns_response(data)
                if not recs:
                    continue

                ptr_names = []
                srv_by_name = {}
                txt_by_name = {}
                a_by_host = {}
                for rec in recs:
                    rt = rec[0]
                    if rt == "PTR":
                        ptr_names.append(rec[2])
                    elif rt == "SRV":
                        srv_by_name[rec[1].lower()] = (rec[1], int(rec[2]), rec[3])
                    elif rt == "TXT":
                        txt_by_name[rec[1].lower()] = rec[2]
                    elif rt == "A":
                        a_by_host[rec[1].lower()] = rec[2]

                # Si un equipo respondió solo PTR sin SRV embebido, solicitar SRV explícito con QU=1 (0x8001)
                for pname in ptr_names:
                    pl = pname.lower()
                    if svc_short.lower() not in pl:
                        continue
                    if pl not in srv_by_name and (sender_ip, pl) not in srv_requested:
                        srv_requested.add((sender_ip, pl))
                        srv_q = _build_mdns_query(pname, qtype=33, qclass=0x8001, txid=0)
                        try:
                            sock.sendto(srv_q, (sender_ip, 5353))
                            if use_multicast_broadcast:
                                sock.sendto(srv_q, ("224.0.0.251", 5353))
                                if bcast_ip:
                                    sock.sendto(srv_q, (bcast_ip, 5353))
                            deadline = max(deadline, time.time() + 0.5)
                        except Exception:
                            pass

                for sl_name, (orig_name, port, host_target) in srv_by_name.items():
                    if svc_short.lower() not in sl_name or not (1 <= port <= 65535):
                        continue
                    inst = orig_name.split(".", 1)[0]
                    resolved_ip = a_by_host.get(host_target.lower(), sender_ip)
                    if not is_valid_lan_ipv4(resolved_ip):
                        resolved_ip = sender_ip
                    model = ""
                    for kv in txt_by_name.get(sl_name, []):
                        if kv.lower().startswith("name="):
                            model = kv.split("=", 1)[1].strip()
                            break
                    key = (resolved_ip, port, inst)
                    found_map[key] = {
                        "instance": inst,
                        "service": svc_short,
                        "ip": resolved_ip,
                        "port": port,
                        "model": model,
                    }

            # Si buscamos una instancia exacta (QR) y ya apareció, salir de inmediato
            if instance_name and any(instance_name.lower() in v.get("instance", "").lower() for v in found_map.values()):
                break
            # Si consultamos IPs específicas y ya respondieron todas, salir sin esperar la 2da ráfaga
            wanted_ips = {x for x in ips if x != u_local}
            if wanted_ips and len(wanted_ips) <= 3 and wanted_ips.issubset({v["ip"] for v in found_map.values()}):
                break

        return list(found_map.values())
    except Exception:
        return []
    finally:
        try:
            sock.close()
        except Exception:
            pass


def get_adb_connected_and_mdns(subnet=None, local_ip=None, target_ips=None):
    connected_map = {}
    mdns_ports = {}
    cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

    try:
        res = subprocess.run(["adb", "mdns", "services"], capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=2)
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", parts[-1]):
                ip, port = parts[-1].split(":", 1)
                mdns_ports[ip] = (port, parts[0])
    except Exception:
        pass

    # Respaldo RFC 6762 §6.7 (multicast + broadcast + unicast desde puerto efímero)
    try:
        u_local = local_ip or get_wifi_adapter_ip()
        probe_ips = None
        if target_ips:
            probe_ips = list(target_ips)
        elif subnet and subnet != "127.0.0":
            # Primero 224.0.0.251 + .255 + IPs conocidas/ARP (~0.65s); si no halló nada, barrido unicast /24
            known_sub = [k_ip for k_ip in load_known_devices().keys() if k_ip.startswith(subnet + ".")]
            arp_sub = [a_ip for a_ip in get_local_arp_cache().keys() if a_ip.startswith(subnet + ".")]
            probe_ips = list(set(known_sub + arp_sub))
        if probe_ips is not None:
            svcs = query_unicast_mdns_adb(probe_ips, "_adb-tls-connect._tcp.local",
                                          local_ip=u_local, wait_s=0.60, bursts=2, use_multicast_broadcast=True)
            if not svcs and subnet and subnet != "127.0.0" and not target_ips:
                svcs = query_unicast_mdns_adb([f"{subnet}.{i}" for i in range(1, 255)],
                                              "_adb-tls-connect._tcp.local",
                                              local_ip=u_local, wait_s=0.55, bursts=1, use_multicast_broadcast=False)
            for svc in svcs:
                s_ip = svc["ip"]
                if s_ip not in mdns_ports:
                    label = svc.get("model") or svc.get("instance") or ""
                    mdns_ports[s_ip] = (str(svc["port"]), label)
    except Exception:
        pass

    try:
        res = subprocess.run(["adb", "devices", "-l"], capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=3)
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("List of"):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "offline":
                continue
            if len(parts) >= 2 and parts[1] == "device":
                ep = parts[0]
                model = ""
                for p in parts[2:]:
                    if p.startswith("model:"):
                        model = p.split(":", 1)[1]
                if ":" in ep and re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", ep):
                    ip, port = ep.split(":", 1)
                    connected_map[ip] = (port, model, ep)
                elif "._adb" in ep:
                    svc_prefix = ep.split(".")[0]
                    matched_ip = None
                    for m_ip, (m_port, m_svc) in mdns_ports.items():
                        if m_svc == svc_prefix:
                            connected_map[m_ip] = (m_port, model, ep)
                            matched_ip = m_ip
                            break
                    if not matched_ip:
                        connected_map[ep] = ("", model, ep)
    except Exception:
        pass

    return connected_map, mdns_ports

def generate_random_string(length: int = 6) -> str:
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join(random.choice(letters_and_digits) for _ in range(length))

def is_pax_5555_device(dev):
    """
    Retorna True SOLAMENTE si el dispositivo es PAX E700, PAX E800 o PAX A920Pro.
    Todos los demás terminales (PAX A80, Landi C20DS, tablets, teléfonos, etc.) retornan False.
    """
    if not dev:
        return False
    name = str(dev.get("name", "")).lower()
    model = str(dev.get("model", "")).lower()
    serial = str(dev.get("serial", "")).lower()
    key = str(dev.get("key", "")).lower()
    raw = f"{name} {model} {serial} {key}"

    # E700 (nombre de modelo o código Uranus)
    if "e700" in raw or "uranus" in raw:
        return True
    # E800 (nombre de modelo o código Gemini)
    if "e800" in raw or "gemini" in raw:
        return True
    # A920Pro / A920 Pro
    if "a920pro" in raw or "a920 pro" in raw or "a920" in raw:
        return True

    return False

def extract_ip_octets(ip_str):
    """Extrae los 4 octetos numéricos de una IP IPv4 (o USB con IP) para orden numérico ascendente."""
    if not ip_str:
        return (999, 999, 999, 999)
    m = re.search(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b", str(ip_str))
    if m:
        try:
            return tuple(int(x) for x in m.groups())
        except ValueError:
            pass
    return (999, 999, 999, 999)

def get_device_sort_key(dev):
    """
    Criterio de ordenamiento solicitado por el usuario:
    1. Al principio de la lista: Dispositivos en estado Conectado (ADB o USB) (rank 0).
       Después: Los demás dispositivos no conectados (rank 1).
    2. Dentro de cada grupo, orden ascendente conforme a su dirección IP numérica (4 octetos).
    """
    is_connected = bool(dev.get("is_adb_connected") or dev.get("is_usb"))
    conn_rank = 0 if is_connected else 1
    ip_octets = extract_ip_octets(dev.get("ip"))
    name_str = str(dev.get("name", "")).lower()
    dev_key = str(dev.get("key", "")).lower()
    return (conn_rank, ip_octets, 0 if dev.get("is_usb") else 1, name_str, dev_key)

def check_tcp_ports_fast(ip, ports, timeout=0.8):
    """Comprobación ultra-rápida no bloqueante de puertos TCP con timeout ajustado y reintento para radios Wi-Fi."""
    open_list = []
    for p in ports:
        if not p:
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, int(p))) == 0:
                    open_list.append(str(p))
                elif timeout < 1.0:
                    time.sleep(0.06)
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
                        s2.settimeout(timeout)
                        if s2.connect_ex((ip, int(p))) == 0:
                            open_list.append(str(p))
        except Exception:
            pass
    return open_list

def scan_live_wifi_devices(status_callback=None):
    """
    Escaneo real, completo y de alta fidelidad de la red local:
    - Identifica dispositivos USB directos y terminales ADB.
    - Ejecuta barrido Layer-2 nativo SendARP sobre los 254 IPs de la subred (1..254).
    - Agrupa los equipos según la red a la que pertenecen (Sitio de Trabajo vs Casa vs USB).
    - Deshabilita el estado conectable para equipos que no están físicamente presentes.
    """
    ensure_storage_mount()
    usb_results = get_usb_connected_devices()
    for u in usb_results:
        u["network"] = "USB Directo"
        u["is_on_current_net"] = True
    enable_tcpip_on_usb_devices()
    if not usb_results:
        usb_results = get_usb_connected_devices()
        for u in usb_results:
            u["network"] = "USB Directo"
            u["is_on_current_net"] = True

    local_ip, subnet, gw, current_net_name = get_network_info()
    cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    known_db = load_known_devices()

    if status_callback:
        status_callback(f"Escaneando 254 IPs en {current_net_name} ({subnet}.0/24)...")

    # 1. Escaneo nativo SendARP masivo en paralelo sobre todos los 254 IPs
    live_arp_macs = fast_subnet_arp_scan(subnet)

    # 2. Conexiones ADB vivas y servicios mDNS (multicast + unicast RFC 6762 en toda la subred)
    connected_map, mdns_ports = get_adb_connected_and_mdns(subnet=subnet, local_ip=local_ip)
    # Incorporar MACs recién resueltas por el barrido unicast mDNS
    try:
        live_arp_macs.update(get_local_arp_cache())
    except Exception:
        pass

    # 3. Conjunto completo de candidatos:
    # - Todos los que respondieron físicamente a SendARP
    # - Todos los conocidos en known_devices.json
    # - Todos los conectados por ADB o detectados por mDNS
    # - Local y Gateway
    usb_wlan_ips = set()
    for u in usb_results:
        u_wip = u.get("wlan_ip", "")
        if u_wip:
            usb_wlan_ips.add(u_wip)

    candidate_ips = set(live_arp_macs.keys())
    for k_ip in known_db.keys():
        candidate_ips.add(k_ip)
    for c_ip in connected_map.keys():
        candidate_ips.add(c_ip)
    for m_ip in mdns_ports.keys():
        candidate_ips.add(m_ip)
    for u_ip in usb_wlan_ips:
        candidate_ips.add(u_ip)
    candidate_ips.add(local_ip)
    candidate_ips.add(gw)

    all_candidate_ips = sorted(list(candidate_ips), key=lambda x: int(x.split(".")[-1]) if x.replace(".", "").isdigit() else 999)

    # 4. Comprobación paralela de puertos:
    # - Equipos que respondieron a ARP, conexiones ADB, mDNS o reportados por USB
    # - Y dispositivos conocidos de la red actual o estáticos que pertenezcan a la subred actual
    current_net_lower = current_net_name.lower()
    probe_candidate_ips = set(ip for ip in all_candidate_ips if ip in live_arp_macs or ip in connected_map or ip in mdns_ports or ip in usb_wlan_ips or ip == local_ip)
    for ip, k_info in known_db.items():
        if ip.startswith(subnet + "."):
            k_net = str(k_info.get("network", "")).lower()
            if ("trabajo" in current_net_lower and "trabajo" in k_net) or ("casa" in current_net_lower and "casa" in k_net) or k_info.get("is_static"):
                probe_candidate_ips.add(ip)
    alive_on_net_ips = list(probe_candidate_ips)

    def probe_device_ports(ip):
        if ip in connected_map:
            return ip, [connected_map[ip][0]]
        ports_to_check = [5555, 7888]
        last_p = known_db.get(ip, {}).get("last_port")
        if last_p and str(last_p).isdigit() and str(last_p) not in ("5555", "7888"):
            ports_to_check.append(int(last_p))
        if ip in mdns_ports:
            m_p = mdns_ports[ip][0]
            if str(m_p).isdigit() and int(m_p) not in ports_to_check:
                ports_to_check.append(int(m_p))
        return ip, check_tcp_ports_fast(ip, ports_to_check)

    port_results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        for ip, open_p in ex.map(probe_device_ports, alive_on_net_ips):
            if open_p:
                port_results[ip] = open_p

    results = list(usb_results)
    for ip in all_candidate_ips:
        # Permitir siempre equipos conectados por ADB, detectados por mDNS o reportados por un USB conectado (aunque estén en otra subred o VPN)
        if not ip.startswith(subnet + ".") and ip not in connected_map and ip not in mdns_ports and ip not in usb_wlan_ips:
            continue
        is_on_current_net = (ip in live_arp_macs) or (ip in connected_map) or (ip in mdns_ports) or (ip in port_results) or (ip in usb_wlan_ips) or (ip == local_ip)
        if not is_on_current_net:
            continue
        mac = live_arp_macs.get(ip) or known_db.get(ip, {}).get("mac", "")
        if ip == local_ip:
            mac = "Local"
        conn_info = connected_map.get(ip)
        mdns_info = mdns_ports.get(ip)
        known_info = known_db.get(ip, {})
        open_p = port_results.get(ip, [])

        # Asignación de red del dispositivo: los equipos activos en Wi-Fi pertenecen a la red actual
        dev_network = current_net_name

        detected_port = ""
        is_adb_connected = False
        is_port_open = False

        if is_on_current_net:
            if conn_info:
                detected_port = conn_info[0]
                is_adb_connected = True
                is_port_open = True
            elif open_p:
                detected_port = str(open_p[0])
                is_port_open = True
            elif mdns_info:
                detected_port = str(mdns_info[0])
                is_port_open = True
        else:
            # Si no está en esta red, no tiene puertos abiertos en esta ubicación
            detected_port = known_info.get("last_port", "")
            is_adb_connected = False
            is_port_open = False

        name = ""
        if conn_info and len(conn_info) >= 2 and conn_info[1]:
            name = conn_info[1]
        elif known_info.get("name"):
            name = known_info["name"]
        elif mdns_info and mdns_info[1]:
            name = f"Android ({mdns_info[1]})"

        if not name:
            if ip == local_ip:
                name = f"{socket.gethostname()} (Este PC)"
            elif ip == gw:
                vendor = lookup_mac_vendor_fast(mac)
                name = f"Router Wi-Fi ({vendor})" if vendor else "Router Wi-Fi (Puerta de enlace)"
            else:
                vendor = lookup_mac_vendor_fast(mac)
                name = vendor if vendor else "Dispositivo en Red Wi-Fi"
        else:
            if ip == local_ip and "(Este PC)" not in name:
                name = f"{name} (Este PC)"

        if name in ("E800", "E700", "A80") or (name.startswith("E") and len(name) == 4 and name[1:].isdigit()):
            if not name.startswith("PAX "):
                name = f"PAX {name}"

        is_static = known_info.get("is_static", False)

        # Si no tiene MAC viva, no tiene puertos, no está en ADB y no es estático ni local, omitir
        if not is_adb_connected and not is_port_open and not mac and not is_static and ip != local_ip:
            continue

        save_known_device(ip, name=name, mac=mac, is_static=is_static, last_port=detected_port, network=dev_network)

        displays = [0, 1] if "e800" in (name or "").lower() else [0]
        if is_adb_connected and "e800" not in (name or "").lower():
            target_str = conn_info[2] if (conn_info and len(conn_info) >= 3 and conn_info[2]) else f"{ip}:{detected_port}"
            displays = get_device_displays(target_str, device_name=name)

        active_serial = ""
        if conn_info and len(conn_info) >= 3 and conn_info[2]:
            active_serial = conn_info[2]
        elif detected_port:
            active_serial = f"{ip}:{detected_port}"
        else:
            active_serial = ip

        results.append({
            "key": ip,
            "ip": ip,
            "mac": mac,
            "name": name,
            "port": detected_port,
            "serial": active_serial,
            "is_adb_connected": is_adb_connected,
            "is_port_open": is_port_open,
            "is_local_or_router": (ip == local_ip or ip == gw),
            "is_static": is_static,
            "is_usb": False,
            "displays": displays,
            "network": dev_network,
            "is_on_current_net": is_on_current_net
        })

    return local_ip, subnet, results, current_net_name

def connect_ip_automatically(ip, known_port="", status_callback=None):
    """Conecta una IP por ADB probando puertos abiertos con tiempo de espera adecuado para el handshake."""
    cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    ports_to_try = []
    if known_port and str(known_port) not in ("USB", "", "None"):
        ports_to_try.append(str(known_port))
    for p in ("5555", "7888", "5556"):
        if p not in ports_to_try:
            ports_to_try.append(p)

    open_ports = check_tcp_ports_fast(ip, ports_to_try, timeout=1.2)
    if not open_ports:
        # Fallback a descubrimiento mDNS (multicast + unicast directo RFC 6762) para Android 11+
        try:
            _, mdns_ports = get_adb_connected_and_mdns(target_ips=[ip])
            if ip in mdns_ports:
                open_ports = [mdns_ports[ip][0]]
        except Exception:
            pass

    # Fallback inteligente USB: si TCP no respondió y el equipo USB coincide con esta IP o nombre en tabla
    if not open_ports:
        try:
            known_entry = load_known_devices().get(ip, {})
            known_name_low = str(known_entry.get("name", "")).lower()
            usb_devs = get_usb_connected_devices()
            matching_usb = None
            for u in usb_devs:
                if not u.get("is_adb_connected"):
                    continue
                u_wlan = u.get("wlan_ip", "")
                u_name = str(u.get("name", "")).lower()
                if ip == u_wlan or ip in str(u.get("ip", "")):
                    matching_usb = u
                    break
                if known_name_low and (("e700" in known_name_low and "e700" in u_name) or ("e800" in known_name_low and "e800" in u_name) or ("a80" in known_name_low and "a80" in u_name)):
                    matching_usb = u
                    break
            if matching_usb:
                u_serial = matching_usb["serial"]
                if status_callback:
                    status_callback(f"Dispositivo USB detectado ({u_serial}). Activando Wi-Fi (5555)...")
                pc_ip_now = get_wifi_adapter_ip(force=True)
                wake_device_to_pc_route(u_serial, pc_ip_now, cflags=cflags)
                net_det = get_usb_device_net_details(u_serial, cflags=cflags)
                if net_det.get("wlan_ip"):
                    ip = net_det["wlan_ip"]
                prepare_usb_device_for_wifi_adb(u_serial, cflags=cflags, port=5555)
                wake_device_to_pc_route(u_serial, pc_ip_now, cflags=cflags)
                open_ports = ["5555"]
        except Exception:
            pass

    # Si TCP no respondió aún pero se tiene un puerto configurado o es IP privada LAN, intentar puerto 5555 directo
    if not open_ports and known_port and str(known_port) not in ("USB", "", "None"):
        open_ports = [str(known_port)]
    elif not open_ports and is_valid_lan_ipv4(ip):
        open_ports = ["5555"]

    if not open_ports:
        return (
            False,
            "El dispositivo tiene los puertos ADB cerrados (activa 'Depuración por Wi-Fi' o puerto 5555).",
            ""
        )

    last_err = ""
    for port in open_ports:
        ep = f"{ip}:{port}"
        if status_callback:
            status_callback(f"Conectando ADB a {ep}...")
        try:
            is_online, out, is_unauthorized = connect_adb_endpoint_verified(ep, cflags=cflags, attempts=2)
            if is_unauthorized:
                last_err = out

            if is_online:
                save_known_device(ip, last_port=port)
                model = ""
                try:
                    m_res = subprocess.run(["adb", "-s", ep, "shell", "getprop", "ro.product.model"], capture_output=True, text=True, creationflags=cflags, timeout=2)
                    model = m_res.stdout.strip()
                    apply_safe_wifi_adb_props_async(ep, port=port, cflags=cflags)
                    ensure_device_internet_stability(ep)
                except Exception:
                    pass
                return True, ep, model
            elif is_unauthorized:
                return False, last_err, ""
            else:
                last_err = out or f"El dispositivo en {ep} no completó el inicio de sesión ADB (estado offline)."
                if "failed to connect" in last_err.lower() and str(port) != "5555":
                    last_err = (
                        f"Fallo al conectar a {ep}.\n\n"
                        f"En dispositivos con Android 11+ (como este terminal) debes VINCULARLO primero:\n"
                        f"1. Toca 'Puerto' en el bot y entra en la pestaña 'Vincular Dispositivo (Pairing)'.\n"
                        f"2. En el dispositivo toca 'Vincular dispositivo con un código de vinculación'.\n"
                        f"3. Escribe el código de 6 dígitos y el puerto de vinculación para autorizar la PC."
                    )
                # Purgar socket inmediatamente para evitar dejar dispositivos zombis en estado 'offline'
                subprocess.run(["adb", "disconnect", ep], capture_output=True, text=True, creationflags=cflags, timeout=2)
                return False, last_err, ""
        except Exception as e:
            last_err = str(e)

    return False, last_err or "No se pudo establecer sesión ADB.", ""

# ==============================================================================
# INTERFAZ GRÁFICA (GUI) CON MONITOR DE TIEMPO REAL Y CONTROL REMOTO
# ==============================================================================

class RealTimeMultiADBApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Administrador de Dispositivos Wi-Fi y USB (Organizado por Red)")
        self.root.geometry("1350x680")
        self.root.minsize(1140, 520)

        self.scanning = False
        self.connecting = False
        self.device_rows = {}
        self.all_devices_data = []
        self.missing_counters = {}
        self.port_fail_count = {}
        self.connecting_ips = set()
        self._installing_mic_keys = set()
        self.watcher_slice_idx = 0
        self._auto_opened_usb_serials = set()

        self.local_ip = "127.0.0.1"
        self.subnet = "192.168.1"
        self.gw = "192.168.1.1"
        self.current_net_name = "Detectando red..."

        self.group_frames = {}
        self.group_headers = {}
        self.group_row_containers = {}

        self._stop_watcher = threading.Event()
        self._watcher_thread = None
        self.user_disconnected = set()
        self._last_keepalive_time = 0.0
        self._last_port_probe_time = 0.0

        self.msg_queue = queue.Queue()
        self.root.after(50, self._process_queue)

        # Barra superior con título y botón de escaneo manual
        header = ttk.Frame(root, padding=12)
        header.pack(fill=tk.X)

        ttk.Label(
            header,
            text="Panel de Control de Dispositivos Android (Wi-Fi y USB)",
            font=("Segoe UI", 13, "bold")
        ).pack(side=tk.LEFT)

        ttk.Button(
            header,
            text="🕶 Ocultar a 2º Plano (Ctrl+Alt+L)",
            command=self.hide_to_background
        ).pack(side=tk.RIGHT, padx=5)

        # El escaneo manual sigue disponible internamente (trigger_scan) pero el botón visible ahora es "Instalar APK".
        self.btn_scan = ttk.Button(
            header,
            text="🔄 Forzar Escaneo Completo",
            command=self.trigger_scan
        )  # (no se empaqueta: no visible)

        self.btn_apk = ttk.Button(
            header,
            text="📦 Instalar APK",
            command=self.open_apk_installer
        )
        self.btn_apk.pack(side=tk.RIGHT, padx=5)

        # Subtítulo de red
        sub_frame = ttk.Frame(root, padding=(12, 0, 12, 4))
        sub_frame.pack(fill=tk.X)
        self.lbl_net_info = ttk.Label(
            sub_frame,
            text="Detectando red Wi-Fi y dispositivos...",
            foreground="#0055aa",
            font=("Segoe UI", 9, "bold")
        )
        self.lbl_net_info.pack(anchor=tk.W)

        # Barra de herramientas: Búsqueda rápida + Filtro de Red + Agregar IP Estática
        toolbar = ttk.Frame(root, padding=(12, 2, 12, 6))
        toolbar.pack(fill=tk.X)

        ttk.Label(toolbar, text="🔍 Buscar:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 4))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", self.apply_filter)
        self.entry_filter = ttk.Entry(toolbar, textvariable=self.filter_var, width=14)
        self.entry_filter.pack(side=tk.LEFT, padx=(0, 14))

        ttk.Label(toolbar, text="🌐 Ver Red:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 4))
        self.net_filter_var = tk.StringVar(value="Solo Red Actual Conectada")
        self.combo_net_filter = ttk.Combobox(
            toolbar,
            textvariable=self.net_filter_var,
            values=["Todas las Redes", "Solo Red Actual Conectada", "Solo Sitio de Trabajo", "Solo Casa"],
            state="readonly",
            width=26
        )
        self.combo_net_filter.pack(side=tk.LEFT, padx=(0, 14))
        self.combo_net_filter.bind("<<ComboboxSelected>>", self.apply_filter)

        ttk.Label(toolbar, text="➕ Agregar IP:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 4))
        self.manual_ip_var = tk.StringVar()
        self.entry_manual_ip = ttk.Entry(toolbar, textvariable=self.manual_ip_var, width=15)
        self.entry_manual_ip.pack(side=tk.LEFT, padx=(0, 6))
        self.entry_manual_ip.bind("<Return>", lambda e: self.add_manual_ip())

        btn_add = ttk.Button(toolbar, text="Agregar", command=self.add_manual_ip)
        btn_add.pack(side=tk.LEFT)

        btn_qr = ttk.Button(toolbar, text="📷 Vincular con QR", command=self.open_qr_pairing_dialog)
        btn_qr.pack(side=tk.LEFT, padx=(8, 0))

        self.screen_off_var = tk.BooleanVar(value=False)
        self.chk_screen_off = ttk.Checkbutton(
            toolbar,
            text="🕶 Apagar pantalla física al abrir",
            variable=self.screen_off_var
        )
        self.chk_screen_off.pack(side=tk.LEFT, padx=(12, 0))

        # Encabezados de columna
        col_header = ttk.Frame(root, padding=(16, 6, 30, 4))
        col_header.pack(fill=tk.X)
        ttk.Label(col_header, text="Sel.", width=4, font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT)
        ttk.Label(col_header, text="Nombre del Dispositivo", width=26, font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=3)
        ttk.Label(col_header, text="Dirección IP", width=20, font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=3)
        ttk.Label(col_header, text="Dirección MAC", width=17, font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=3)
        ttk.Label(col_header, text="Estado / Conexión", width=24, font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=3)
        ttk.Label(col_header, text="Control Remoto / ADB", width=66, font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=3)

        ttk.Separator(root, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=12)

        # Lista desplazable con soporte de rueda de ratón (MouseWheel)
        list_container = ttk.Frame(root, padding=(12, 4, 12, 4))
        list_container.pack(fill=tk.BOTH, expand=True)

        self.canvas = tk.Canvas(list_container, borderwidth=0, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(list_container, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

        self.canvas_window = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfig(self.canvas_window, width=e.width))

        # Botones de acción principal
        action_frame = ttk.Frame(root, padding=12)
        action_frame.pack(fill=tk.X)

        ttk.Button(action_frame, text="Seleccionar Disponibles", command=self.select_mobiles).pack(side=tk.LEFT, padx=4)
        ttk.Button(action_frame, text="Deseleccionar Todos", command=self.deselect_all).pack(side=tk.LEFT, padx=4)

        ttk.Button(action_frame, text="❌ Desconectar Todo ADB", command=self.disconnect_all).pack(side=tk.RIGHT, padx=4)
        self.btn_connect = ttk.Button(
            action_frame,
            text="⚡ Conectar Seleccionados",
            command=self.connect_selected
        )
        self.btn_connect.pack(side=tk.RIGHT, padx=6)

        # Barra de estado
        self.status_var = tk.StringVar(value="Iniciando escaneo...")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=5)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        # Cierre limpio y atajos
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
        self.root.bind("<Control-Alt-l>", lambda e: self.toggle_window_visibility())
        self.root.bind("<Control-Alt-L>", lambda e: self.toggle_window_visibility())
        self.root.bind("<Unmap>", self._on_unmap)

        self._hotkey_thread = threading.Thread(target=self._global_hotkey_loop, daemon=True)
        self._hotkey_thread.start()

        if _SHOW_WINDOW_EVENT_HANDLE:
            self._wake_thread = threading.Thread(target=self._single_instance_wake_loop, daemon=True)
            self._wake_thread.start()

        # Iniciar escaneo inicial
        self.root.after(100, self.trigger_scan)

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _on_unmap(self, event):
        if event.widget == self.root and self.root.state() == "iconic":
            self.root.after(40, self.root.withdraw)

    def hide_to_background(self):
        try:
            self.root.withdraw()
            self.set_status("Aplicación en segundo plano. Presiona CTRL + ALT + L para volver a abrirla.")
        except Exception:
            pass

    def show_from_background(self):
        try:
            self.root.deiconify()
            self.root.state("normal")
            self.root.attributes("-topmost", True)
            self.root.update()
            self.root.attributes("-topmost", False)
            self.root.lift()
            self.root.focus_force()
        except Exception:
            pass

    def toggle_window_visibility(self):
        try:
            if self.root.state() in ("withdrawn", "iconic"):
                self.show_from_background()
            else:
                self.hide_to_background()
        except Exception:
            pass

    def _global_hotkey_loop(self):
        user32 = ctypes.windll.user32
        VK_CONTROL = 0x11
        VK_MENU = 0x12
        VK_L = 0x4C
        was_pressed = False

        while not self._stop_watcher.is_set():
            time.sleep(0.04)
            try:
                is_ctrl = bool(user32.GetAsyncKeyState(VK_CONTROL) & 0x8000)
                is_alt = bool(user32.GetAsyncKeyState(VK_MENU) & 0x8000)
                is_l = bool(user32.GetAsyncKeyState(VK_L) & 0x8000)
                is_combo = is_ctrl and is_alt and is_l
                if is_combo and not was_pressed:
                    was_pressed = True
                    self.post_gui(self.toggle_window_visibility)
                elif not is_combo:
                    was_pressed = False
            except Exception:
                pass

    def _single_instance_wake_loop(self):
        k32 = _SINGLE_INSTANCE_K32
        evt = _SHOW_WINDOW_EVENT_HANDLE
        if not k32 or not evt:
            return
        while not self._stop_watcher.is_set():
            try:
                res = k32.WaitForSingleObject(evt, 250)
                if res == 0 and not self._stop_watcher.is_set():
                    self.post_gui(self.show_from_background)
            except Exception:
                time.sleep(0.25)

    def _on_closing(self):
        self._stop_watcher.set()
        _APP_SHUTTING_DOWN.set()
        try:
            self.root.withdraw()
        except Exception:
            pass
        try:
            close_all_legacy_mic_players()
        except Exception:
            pass
        terminate_all_child_processes()
        try:
            self.root.destroy()
        except Exception:
            pass

    def post_gui(self, fn, *args, **kwargs):
        self.msg_queue.put((fn, args, kwargs))

    def _process_queue(self):
        try:
            while True:
                fn, args, kwargs = self.msg_queue.get_nowait()
                try:
                    fn(*args, **kwargs)
                except Exception:
                    pass
        except queue.Empty:
            pass
        if not self._stop_watcher.is_set():
            self.root.after(40, self._process_queue)

    def set_status(self, text):
        self.post_gui(self.status_var.set, text)

    def _update_network_subtitle(self):
        count = len(self.device_rows)
        self.lbl_net_info.config(
            text=f"Red Actual: {self.current_net_name} ({self.subnet}.0/24)  |  IP PC: {self.local_ip}  |  Equipos: {count}  |  ⌨ Atajo: CTRL + ALT + L"
        )

    # ==========================================================================
    # GESTIÓN DE GRUPOS VISUALES POR RED
    # ==========================================================================

    def _get_or_create_group_container(self, group_name=None):
        if not hasattr(self, "rows_container") or not self.rows_container.winfo_exists():
            self.rows_container = ttk.Frame(self.scrollable_frame)
            self.rows_container.pack(fill=tk.X, expand=True, pady=1)
        return self.rows_container, self.rows_container

    # ==========================================================================
    # ESCANEO INICIAL Y POBLACIÓN DE LA LISTA
    # ==========================================================================

    def trigger_scan(self):
        if self.scanning or self.connecting:
            return
        self.scanning = True
        self.btn_scan.config(state=tk.DISABLED)
        self.set_status("Escaneando 254 IPs de la subred en tiempo real...")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        try:
            local_ip, subnet, devices, net_name = scan_live_wifi_devices(status_callback=self.set_status)
            self.post_gui(self._populate_devices, local_ip, subnet, devices, net_name)
        except Exception as e:
            self.set_status(f"Error durante el escaneo: {e}")
        finally:
            self.scanning = False
            self.post_gui(self.btn_scan.config, state=tk.NORMAL)

    def _populate_devices(self, local_ip, subnet, devices, net_name=None):
        self.local_ip = local_ip
        self.subnet = subnet
        if net_name:
            self.current_net_name = net_name
        self.all_devices_data = devices

        for w in self.scrollable_frame.winfo_children():
            w.destroy()
        self.device_rows.clear()
        self.missing_counters.clear()
        self.port_fail_count.clear()
        self.group_frames.clear()
        self.group_headers.clear()
        self.group_row_containers.clear()

        self.rows_container = ttk.Frame(self.scrollable_frame)
        self.rows_container.pack(fill=tk.X, expand=True, pady=1)

        sorted_devs = sorted(devices, key=get_device_sort_key)

        for dev in sorted_devs:
            self._create_row(dev)

        self._update_network_subtitle()

        any_connected = any(d.get("is_adb_connected") or d.get("is_usb") for d in devices)
        if any_connected:
            ensure_storage_mount()

        self.apply_filter()
        self.status_var.set(f"Detección activa: {len(devices)} dispositivos organizados por red.")

        if self._watcher_thread is None or not self._watcher_thread.is_alive():
            self._watcher_thread = threading.Thread(target=self._auto_watcher_loop, daemon=True)
            self._watcher_thread.start()

    # ==========================================================================
    # MONITOR EN TIEMPO REAL (SIN RECONEXIONES AUTOMÁTICAS INVASIVAS)
    # ==========================================================================

    def _auto_watcher_loop(self):
        """
        Hilo en segundo plano continuo (cada 2.5s):
        - Detecta automáticamente dispositivos que se conecten por USB o Wi-Fi.
        - Escanea rotativamente porciones de la subred para capturar nuevos dispositivos en Wi-Fi.
        - Detecta dispositivos que se desconecten físicamente y actualiza su estado.
        - NUNCA reconecta dispositivos de forma automática si el usuario los desconectó.
        """
        cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

        while not self._stop_watcher.is_set():
            time.sleep(6.0)
            if self.scanning or self.connecting:
                continue

            try:
                now_curr = time.time()
                # 0. Keep-alive Heartbeat cada 15s para evitar que Android suspenda el Wi-Fi o cierre ADB
                if now_curr - getattr(self, "_last_keepalive_time", 0) > 60.0:
                    self._last_keepalive_time = now_curr
                    for row_k, r_info in list(self.device_rows.items()):
                        d_obj = r_info.get("dev", {})
                        ip_item = d_obj.get("ip", "")
                        if d_obj.get("is_adb_connected") and not d_obj.get("is_usb") and ip_item not in self.user_disconnected:
                            s_tgt = d_obj.get("serial") or (f"{ip_item}:{d_obj.get('port', '5555')}" if d_obj.get("port") else ip_item)
                            try:
                                subprocess.Popen(["adb", "-s", s_tgt, "shell", ":"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=cflags)
                            except Exception:
                                pass

                # 0b. Detectar cambio automático de red Wi-Fi / subred cada 12s
                if now_curr - getattr(self, "_last_net_check_time", 0) > 12.0:
                    self._last_net_check_time = now_curr
                    new_ip, new_sub, new_gw, new_net = get_network_info()
                    if new_sub != self.subnet or new_ip != self.local_ip or new_net != self.current_net_name:
                        self.local_ip = new_ip
                        self.subnet = new_sub
                        self.gw = new_gw
                        self.current_net_name = new_net
                        self.post_gui(self._update_network_subtitle)
                        self.post_gui(self.trigger_scan)
                        continue

                # 1. Obtener USB actuales
                usb_results = get_usb_connected_devices()

                live_map = {}
                usb_wlan_ips = set()
                for u in usb_results:
                    u["network"] = "USB Directo"
                    u["is_on_current_net"] = True
                    sync_dev_mic_caches(u)
                    k = u["key"]
                    live_map[k] = u
                    if u.get("wlan_ip"):
                        usb_wlan_ips.add(u["wlan_ip"])

                # 2. Conexiones ADB y puertos MDNS (incluye consulta unicast periódica para detectar puertos dinámicos nuevos)
                should_probe_tcp = (now_curr - getattr(self, "_last_port_probe_time", 0) > 30.0)
                if should_probe_tcp and self.subnet and self.subnet != "127.0.0":
                    _known_quick = [k_ip for k_ip in load_known_devices().keys() if k_ip.startswith(self.subnet + ".")]
                    _arp_quick = [a_ip for a_ip in get_local_arp_cache().keys() if a_ip.startswith(self.subnet + ".")]
                    _u_targets = list(set(_known_quick + _arp_quick))
                    connected_map, mdns_ports = get_adb_connected_and_mdns(local_ip=self.local_ip, target_ips=_u_targets)
                else:
                    connected_map, mdns_ports = get_adb_connected_and_mdns()

                # 3. Lectura 100% pasiva de la tabla ARP local (Cero paquetes por el aire, cero saturación Wi-Fi)
                arp_macs = get_local_arp_cache()

                # 4. Candidatos a monitorear
                known_db = load_known_devices()
                candidate_ips = set(self.device_rows.keys())
                for k_ip in known_db.keys():
                    candidate_ips.add(k_ip)
                for c_ip in connected_map.keys():
                    candidate_ips.add(c_ip)
                for m_ip in mdns_ports.keys():
                    candidate_ips.add(m_ip)
                for u_ip in usb_wlan_ips:
                    candidate_ips.add(u_ip)
                for a_ip in arp_macs.keys():
                    candidate_ips.add(a_ip)
                candidate_ips.add(self.local_ip)
                candidate_ips.add(self.gw)

                valid_candidate_ips = [
                    ip for ip in candidate_ips
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip)
                    and (ip.startswith(self.subnet + ".") or ip in connected_map or ip in mdns_ports or ip in usb_wlan_ips)
                ]

                # Sondear puertos TCP solo en equipos no conectados y con cadencia espaciada para no agotar sockets
                candidate_port_results = {}
                if should_probe_tcp:
                    self._last_port_probe_time = now_curr
                    def _probe_ports_safe(ip):
                        if ip in connected_map:
                            return ip, [connected_map[ip][0]]
                        ports = [5555]
                        last_p = known_db.get(ip, {}).get("last_port")
                        if last_p and str(last_p).isdigit() and str(last_p) != "5555":
                            ports.append(int(last_p))
                        return ip, check_tcp_ports_fast(ip, ports, timeout=0.6)

                    current_net_lower = self.current_net_name.lower()
                    probe_candidate_ips = set(ip for ip in valid_candidate_ips if (ip in arp_macs or ip in mdns_ports or ip in usb_wlan_ips) and ip not in connected_map)
                    # Incluir siempre dispositivos estáticos y conocidos en la comprobación
                    for ip_c in valid_candidate_ips:
                        if ip_c.startswith(self.subnet + "."):
                            k_inf = known_db.get(ip_c, {})
                            if k_inf.get("is_static") or ip_c in self.device_rows:
                                probe_candidate_ips.add(ip_c)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
                        for ip, p_list in ex.map(_probe_ports_safe, list(probe_candidate_ips)):
                            if p_list:
                                candidate_port_results[ip] = p_list
                else:
                    for ip_c in connected_map:
                        candidate_port_results[ip_c] = [connected_map[ip_c][0]]

                for ip in valid_candidate_ips:
                    is_on_current_net = (ip in arp_macs) or (ip in connected_map) or (ip in mdns_ports) or (ip in candidate_port_results) or (ip in usb_wlan_ips) or (ip == self.local_ip)
                    if not is_on_current_net:
                        continue
                    mac = arp_macs.get(ip) or known_db.get(ip, {}).get("mac", "")
                    if ip == self.local_ip:
                        mac = "Local"
                    conn_info = connected_map.get(ip)
                    mdns_info = mdns_ports.get(ip)
                    known_info = known_db.get(ip, {})
                    open_p = candidate_port_results.get(ip, [])

                    # Asignación de red del dispositivo: los equipos activos en Wi-Fi pertenecen a la red actual
                    dev_network = self.current_net_name

                    detected_port = ""
                    is_adb_connected = False
                    is_port_open = False

                    if is_on_current_net:
                        if conn_info:
                            detected_port = conn_info[0]
                            is_adb_connected = True
                            is_port_open = True
                            self.port_fail_count[ip] = 0
                        elif open_p:
                            detected_port = str(open_p[0])
                            is_port_open = True
                            self.port_fail_count[ip] = 0
                        elif mdns_info:
                            detected_port = str(mdns_info[0])
                            is_port_open = True
                            self.port_fail_count[ip] = 0
                        else:
                            old_row = self.device_rows.get(ip)
                            if old_row and old_row["dev"].get("is_port_open"):
                                fails = self.port_fail_count.get(ip, 0) + 1
                                self.port_fail_count[ip] = fails
                                if fails < 4:
                                    is_port_open = True
                                    detected_port = old_row["dev"].get("port", "5555")
                                else:
                                    is_port_open = False
                            else:
                                is_port_open = False
                    else:
                        detected_port = known_info.get("last_port", "")
                        is_adb_connected = False
                        is_port_open = False

                    name = ""
                    if conn_info and len(conn_info) >= 2 and conn_info[1]:
                        name = conn_info[1]
                    elif known_info.get("name"):
                        name = known_info["name"]
                    elif mdns_info and mdns_info[1]:
                        name = f"Android ({mdns_info[1]})"

                    if not name:
                        if ip == self.local_ip:
                            name = f"{socket.gethostname()} (Este PC)"
                        elif ip == self.gw:
                            vendor = lookup_mac_vendor_fast(mac)
                            name = f"Router Wi-Fi ({vendor})" if vendor else "Router Wi-Fi (Puerta de enlace)"
                        else:
                            vendor = lookup_mac_vendor_fast(mac)
                            name = vendor if vendor else "Dispositivo en Red Wi-Fi"
                    else:
                        if ip == self.local_ip and "(Este PC)" not in name:
                            name = f"{name} (Este PC)"

                    if name in ("E800", "E700", "A80") or (name.startswith("E") and len(name) == 4 and name[1:].isdigit()):
                        if not name.startswith("PAX "):
                            name = f"PAX {name}"

                    is_static = known_info.get("is_static", False)

                    displays = [0, 1] if "e800" in (name or "").lower() else [0]
                    if is_adb_connected and "e800" not in (name or "").lower():
                        target_str = conn_info[2] if (conn_info and len(conn_info) >= 3 and conn_info[2]) else f"{ip}:{detected_port}"
                        displays = get_device_displays(target_str, device_name=name)

                    is_known = (ip in known_db)
                    if not is_adb_connected and not is_port_open and not mac and not is_static and not is_known and ip != self.local_ip:
                        continue

                    active_serial = ""
                    if conn_info and len(conn_info) >= 3 and conn_info[2]:
                        active_serial = conn_info[2]
                    elif detected_port:
                        active_serial = f"{ip}:{detected_port}"
                    else:
                        active_serial = ip

                    dev_item = {
                        "key": ip,
                        "ip": ip,
                        "mac": mac,
                        "name": name,
                        "port": detected_port,
                        "serial": active_serial,
                        "is_adb_connected": is_adb_connected,
                        "is_port_open": is_port_open,
                        "is_local_or_router": (ip == self.local_ip or ip == self.gw),
                        "is_static": is_static,
                        "is_known": is_known,
                        "is_usb": False,
                        "displays": displays,
                        "network": dev_network,
                        "is_on_current_net": is_on_current_net
                    }
                    sync_dev_mic_caches(dev_item)
                    live_map[ip] = dev_item

                # 5. Aplicación diferencial
                current_keys = set(self.device_rows.keys())
                live_keys = set(live_map.keys())

                to_add = [live_map[k] for k in (live_keys - current_keys)]
                for dev in to_add:
                    self.missing_counters[dev["key"]] = 0
                    self.post_gui(self._add_device_row, dev)

                to_remove_candidates = current_keys - live_keys
                for k in to_remove_candidates:
                    row_data = self.device_rows.get(k)
                    if row_data and row_data["dev"].get("is_local_or_router"):
                        continue
                    threshold = 1 if k.startswith("USB:") else 3
                    self.missing_counters[k] = self.missing_counters.get(k, 0) + 1
                    if self.missing_counters[k] >= threshold:
                        self.missing_counters.pop(k, None)
                        self.post_gui(self._remove_device_row, k)

                common_keys = current_keys & live_keys
                for k in common_keys:
                    self.missing_counters[k] = 0
                    dev = live_map[k]
                    row_info = self.device_rows.get(k)
                    if row_info:
                        old_dev = row_info["dev"]
                        if (old_dev.get("is_adb_connected") != dev.get("is_adb_connected") or
                            old_dev.get("is_port_open") != dev.get("is_port_open") or
                            old_dev.get("name") != dev.get("name") or
                            old_dev.get("port") != dev.get("port") or
                            old_dev.get("serial") != dev.get("serial") or
                            old_dev.get("is_on_current_net") != dev.get("is_on_current_net") or
                            old_dev.get("android_sdk") != dev.get("android_sdk") or
                            old_dev.get("mic_apk_installed") != dev.get("mic_apk_installed")):
                            self.post_gui(self._update_row_state_by_key, k, dev)
                        if (dev.get("is_adb_connected") or (dev.get("is_usb") and not dev.get("is_offline") and not dev.get("is_unauthorized"))) and not dev.get("is_local_or_router"):
                            if dev.get("android_sdk") is None:
                                self._schedule_mic_probe(dev)

            except Exception:
                pass

    # ==========================================================================
    # MANIPULACIÓN IN-SITU DE FILAS
    # ==========================================================================

    def _create_row(self, dev):
        dev_key = dev.get("key") or (f"USB:{dev['serial']}" if dev.get("is_usb") else dev["ip"])
        dev["key"] = dev_key
        sync_dev_mic_caches(dev)

        if dev_key in self.device_rows:
            return

        group_name = dev.get("network") or "Otros"
        if dev.get("is_usb"):
            group_name = "USB Directo"

        _, rows_container = self._get_or_create_group_container(group_name)

        row = ttk.Frame(rows_container, padding=4)
        row.pack(fill=tk.X, expand=True, pady=2)

        is_usb = dev.get("is_usb", False)
        is_adb = dev.get("is_adb_connected", False)
        is_sys = dev.get("is_local_or_router", False)
        is_port_open = dev.get("is_port_open", False)
        is_on_net = dev.get("is_on_current_net", True)

        can_connect = (not is_adb and not is_usb and not is_sys and is_on_net)

        chk_var = tk.BooleanVar(value=False)
        chk = ttk.Checkbutton(row, variable=chk_var, width=3)
        chk.pack(side=tk.LEFT, padx=4)
        if not can_connect:
            chk.config(state=tk.DISABLED)

        display_name = dev["name"]
        if dev.get("is_static"):
            display_name = f"⭐ {display_name} [Estática]"
        elif is_usb:
            display_name = f"🔌 {display_name}"

        lbl_name = ttk.Label(row, text=display_name, width=26, anchor=tk.W, font=("Segoe UI", 9, "bold"))
        lbl_name.pack(side=tk.LEFT, padx=3)

        lbl_ip = ttk.Label(row, text=dev["ip"], width=20, anchor=tk.W, font=("Consolas", 10))
        lbl_ip.pack(side=tk.LEFT, padx=3)

        lbl_mac = ttk.Label(row, text=dev["mac"] or "-", width=17, anchor=tk.W, font=("Consolas", 9), foreground="#555555")
        lbl_mac.pack(side=tk.LEFT, padx=3)

        if dev.get("is_offline"):
            status_text = "▲ USB (Offline)"
            status_color = "#b36b00"
        elif dev.get("is_unauthorized"):
            status_text = "▲ USB (Aceptar en pantalla)"
            status_color = "#b36b00"
        elif is_usb:
            status_text = "● Conectado (USB)"
            status_color = "green"
        elif is_adb:
            status_text = f"● Conectado ADB ({dev.get('port', '5555')})"
            status_color = "green"
        elif is_port_open and is_on_net:
            status_text = "● ADB disponible"
            status_color = "#0066cc"
        elif is_sys:
            status_text = "○ Red / Sistema"
            status_color = "#777777"
        elif not is_on_net:
            status_text = f"○ Fuera de red ({group_name})"
            status_color = "#888888"
        else:
            status_text = "○ Activo en Red"
            status_color = "#444444"

        lbl_status = ttk.Label(row, text=status_text, foreground=status_color, width=24, anchor=tk.W)
        lbl_status.pack(side=tk.LEFT, padx=3)

        # Columna de botones
        ctrl_frame = ttk.Frame(row)
        ctrl_frame.pack(side=tk.LEFT, padx=2)

        displays = dev.get("displays", [0])

        # 1. Botón unificado "Conectar" / "Desconectar" / "Modo Wi-Fi"
        can_desc = (is_adb and not is_usb and not is_sys)
        if is_usb:
            btn_text = "🔄 Reconectar" if dev.get("is_offline") else "⚡ Modo Wi-Fi"
            btn_conectar = ttk.Button(
                ctrl_frame,
                text=btn_text,
                width=12,
                command=lambda d=dev: self.enable_wifi_mode_for_usb_device(d)
            )
            btn_conectar.pack(side=tk.LEFT, padx=2)
            btn_conectar.config(state=tk.NORMAL)
        elif is_adb:
            btn_conectar = ttk.Button(
                ctrl_frame,
                text="Desconectar",
                width=11,
                command=lambda d=dev: self.disconnect_single_device(d)
            )
            btn_conectar.pack(side=tk.LEFT, padx=2)
            btn_conectar.config(state=tk.NORMAL if can_desc else tk.DISABLED)
        else:
            btn_conectar = ttk.Button(
                ctrl_frame,
                text="Conectar",
                width=11,
                command=lambda d=dev: self.connect_single_device(d)
            )
            btn_conectar.pack(side=tk.LEFT, padx=2)
            btn_conectar.config(state=tk.NORMAL if can_connect else tk.DISABLED)

        # 2. Botón "Pantalla" con opciones de pantalla normal o pantalla física apagada
        can_screen = (is_adb or is_usb or (is_port_open and not is_sys and is_on_net))
        pantalla_widget = None
        if len(displays) >= 2 or "e800" in (dev.get("name") or "").lower():
            mb_pantalla = ttk.Menubutton(ctrl_frame, text="Pantalla ▾", width=11)
            menu_pantalla = tk.Menu(mb_pantalla, tearoff=0)
            menu_pantalla.add_command(
                label="🖥 Pantalla 1 (Principal)",
                command=lambda d=dev: self.start_control_session(d, display_id=0, turn_screen_off=False)
            )
            menu_pantalla.add_command(
                label="🕶 Pantalla 1 (Física Apagada)",
                command=lambda d=dev: self.start_control_session(d, display_id=0, turn_screen_off=True)
            )
            menu_pantalla.add_command(
                label="🎙 Pantalla 1 (Audio por Micrófono)",
                command=lambda k=dev_key, d=dev: self.start_control_session(self._get_row_dev(k, d), display_id=0, turn_screen_off=None, audio_source="mic")
            )
            menu_pantalla.add_command(
                label="🕶🎙 Pantalla 1 (Apagada + Micrófono)",
                command=lambda k=dev_key, d=dev: self.start_control_session(self._get_row_dev(k, d), display_id=0, turn_screen_off=True, audio_source="mic")
            )
            menu_pantalla.add_separator()
            menu_pantalla.add_command(
                label="🖥 Pantalla 2 (Cliente)",
                command=lambda d=dev: self.start_control_session(d, display_id=1, turn_screen_off=False)
            )
            mb_pantalla["menu"] = menu_pantalla
            mb_pantalla.pack(side=tk.LEFT, padx=2)
            mb_pantalla.config(state=tk.NORMAL if can_screen else tk.DISABLED)
            pantalla_widget = mb_pantalla
        else:
            mb_pantalla = ttk.Menubutton(ctrl_frame, text="Pantalla ▾", width=11)
            menu_pantalla = tk.Menu(mb_pantalla, tearoff=0)
            menu_pantalla.add_command(
                label="🖥 Pantalla Normal",
                command=lambda d=dev: self.start_control_session(d, display_id=0, turn_screen_off=False)
            )
            menu_pantalla.add_command(
                label="🕶 Pantalla (Física Apagada)",
                command=lambda d=dev: self.start_control_session(d, display_id=0, turn_screen_off=True)
            )
            menu_pantalla.add_command(
                label="🎙 Pantalla (Audio por Micrófono)",
                command=lambda k=dev_key, d=dev: self.start_control_session(self._get_row_dev(k, d), display_id=0, turn_screen_off=None, audio_source="mic")
            )
            menu_pantalla.add_command(
                label="🕶🎙 Pantalla (Física Apagada + Micrófono)",
                command=lambda k=dev_key, d=dev: self.start_control_session(self._get_row_dev(k, d), display_id=0, turn_screen_off=True, audio_source="mic")
            )
            mb_pantalla["menu"] = menu_pantalla
            mb_pantalla.pack(side=tk.LEFT, padx=2)
            mb_pantalla.config(state=tk.NORMAL if can_screen else tk.DISABLED)
            pantalla_widget = mb_pantalla

        # 3. Botón "📁 Archivos" (Explorador integrado ADB para transferir archivos sin bloqueos)
        can_files = not is_sys and (is_on_net or is_adb or is_usb or dev.get("is_static"))
        btn_files = ttk.Button(
            ctrl_frame,
            text="📁 Archivos",
            width=10,
            command=lambda k=dev_key, d=dev: self.open_device_file_manager(self._get_row_dev(k, d))
        )
        btn_files.pack(side=tk.LEFT, padx=2)
        btn_files.config(state=tk.NORMAL if can_files else tk.DISABLED)

        # 3. Botón de puerto:
        # - Solo PAX E700, PAX E800 y PAX A920Pro muestran "Abrir puerto 5555" / "Cerrar puerto 5555"
        # - Todos los demás dispositivos muestran el botón "Puerto" para depuración inalámbrica
        if is_sys:
            btn_port_toggle = ttk.Button(
                ctrl_frame,
                text="-",
                width=17,
                state=tk.DISABLED
            )
        elif is_pax_5555_device(dev):
            if is_port_open or is_adb:
                btn_port_toggle = ttk.Button(
                    ctrl_frame,
                    text="Cerrar puerto 5555",
                    width=17,
                    command=lambda d=dev: self.toggle_port_5555(d, open_it=False)
                )
            else:
                btn_port_toggle = ttk.Button(
                    ctrl_frame,
                    text="Abrir puerto 5555",
                    width=17,
                    command=lambda d=dev: self.toggle_port_5555(d, open_it=True)
                )
            btn_port_toggle.config(state=tk.NORMAL)
        else:
            btn_port_toggle = ttk.Button(
                ctrl_frame,
                text="Puerto",
                width=17,
                command=lambda d=dev: self.prompt_custom_port(d)
            )
            btn_port_toggle.config(state=tk.NORMAL)

        btn_port_toggle.pack(side=tk.LEFT, padx=2)

        # 4. Botón condicional para Android < 11: instala MicrofonoADB.apk y permite escuchar su micrófono
        btn_mic_apk = ttk.Button(ctrl_frame, text="🎙 Instalar Mic", width=15)
        def _mic_popup(event, k=dev_key, d=dev):
            latest = self._get_row_dev(k, d)
            m = tk.Menu(self.root, tearoff=0)
            m.add_command(label="🔄 Reinstalar app MicrofonoADB", command=lambda: self.install_mic_apk_for_device(latest))
            m.add_command(label="🎙 Abrir Pantalla con Micrófono", command=lambda: self.start_control_session(latest, display_id=0, turn_screen_off=None, audio_source="mic"))
            m.add_command(label="🕶🎙 Abrir Apagada + Micrófono", command=lambda: self.start_control_session(latest, display_id=0, turn_screen_off=True, audio_source="mic"))
            m.tk_popup(event.x_root, event.y_root)
        btn_mic_apk.bind("<Button-3>", _mic_popup)
        self._refresh_mic_apk_button(btn_mic_apk, dev, dev_key)

        # Menú contextual para cambiar de red
        def _popup_menu(event, d=dev):
            m = tk.Menu(self.root, tearoff=0)
            m.add_command(label="🏢 Asignar a: Sitio de Trabajo", command=lambda: self.change_device_network(d, "Sitio de Trabajo"))
            m.add_command(label="🏠 Asignar a: Casa (Familia Rosales Martinez)", command=lambda: self.change_device_network(d, "Casa (Familia Rosales Martinez)"))
            m.tk_popup(event.x_root, event.y_root)

        row.bind("<Button-3>", _popup_menu)
        lbl_name.bind("<Button-3>", _popup_menu)
        lbl_ip.bind("<Button-3>", _popup_menu)

        self.device_rows[dev_key] = {
            "row_frame": row,
            "chk": chk,
            "chk_var": chk_var,
            "name_lbl": lbl_name,
            "ip_lbl": lbl_ip,
            "mac_lbl": lbl_mac,
            "status_lbl": lbl_status,
            "ctrl_frame": ctrl_frame,
            "btn_conectar": btn_conectar,
            "pantalla_widget": pantalla_widget,
            "btn_files": btn_files,
            "btn_port_toggle": btn_port_toggle,
            "btn_mic_apk": btn_mic_apk,
            "dev": dev,
            "group_name": group_name
        }
        self._schedule_mic_probe(dev)

    def change_device_network(self, dev, new_network):
        ip = dev.get("ip")
        dev["network"] = new_network
        if ip and not dev.get("is_usb"):
            save_known_device(ip, name=dev["name"], mac=dev.get("mac", ""), is_static=dev.get("is_static", False), last_port=dev.get("port", ""), network=new_network)
        self.set_status(f"Dispositivo {dev['name']} asignado a: {new_network}")
        self.trigger_scan()

    def _add_device_row(self, dev):
        self._create_row(dev)
        self.apply_filter()
        self._update_network_subtitle()

    def _remove_device_row(self, dev_key):
        row_info = self.device_rows.pop(dev_key, None)
        if row_info:
            row_info["row_frame"].destroy()
            self.apply_filter()
            self._update_network_subtitle()

    def _update_row_state_by_key(self, dev_key, dev):
        row_info = self.device_rows.get(dev_key)
        if not row_info:
            return

        row_info["dev"] = dev
        sync_dev_mic_caches(dev)
        is_usb = dev.get("is_usb", False)
        is_adb = dev.get("is_adb_connected", False)
        is_sys = dev.get("is_local_or_router", False)
        is_port_open = dev.get("is_port_open", False)
        is_on_net = dev.get("is_on_current_net", True)
        group_name = dev.get("network", "Otros")

        display_name = dev["name"]
        if dev.get("is_static"):
            display_name = f"⭐ {display_name} [Estática]"
        elif is_usb:
            display_name = f"🔌 {display_name}"
        row_info["name_lbl"].config(text=display_name)

        if is_usb:
            status_text = "● Conectado (USB)"
            status_color = "green"
        elif is_adb:
            status_text = f"● Conectado ADB ({dev.get('port', '5555')})"
            status_color = "green"
        elif is_port_open and is_on_net:
            status_text = "● ADB disponible"
            status_color = "#0066cc"
        elif is_sys:
            status_text = "○ Red / Sistema"
            status_color = "#777777"
        elif not is_on_net:
            status_text = f"○ Fuera de red ({group_name})"
            status_color = "#888888"
        else:
            status_text = "○ Activo en Red"
            status_color = "#444444"

        row_info["status_lbl"].config(text=status_text, foreground=status_color)

        can_connect = (not is_adb and not is_usb and not is_sys and is_on_net)
        can_desc = (is_adb and not is_usb and not is_sys)
        btn_con = row_info.get("btn_conectar")
        if btn_con:
            if is_usb:
                btn_con.config(
                    text="⚡ Modo Wi-Fi",
                    state=tk.NORMAL,
                    command=lambda d=dev: self.enable_wifi_mode_for_usb_device(d)
                )
            elif is_adb:
                btn_con.config(
                    text="Desconectar",
                    state=tk.NORMAL if can_desc else tk.DISABLED,
                    command=lambda d=dev: self.disconnect_single_device(d)
                )
            else:
                btn_con.config(
                    text="Conectar",
                    state=tk.NORMAL if can_connect else tk.DISABLED,
                    command=lambda d=dev: self.connect_single_device(d)
                )

        can_files = not is_sys and (is_on_net or is_adb or is_usb or dev.get("is_static"))
        btn_f = row_info.get("btn_files")
        if btn_f:
            btn_f.config(state=tk.NORMAL if can_files else tk.DISABLED)

        can_screen = (is_adb or is_usb or (is_port_open and not is_sys and is_on_net))
        pantalla_w = row_info.get("pantalla_widget")
        if pantalla_w:
            pantalla_w.config(state=tk.NORMAL if can_screen else tk.DISABLED)

        btn_port = row_info.get("btn_port_toggle")
        if btn_port:
            if is_sys:
                btn_port.config(text="-", state=tk.DISABLED)
            elif is_pax_5555_device(dev):
                if is_port_open or is_adb:
                    btn_port.config(
                        text="Cerrar puerto 5555",
                        state=tk.NORMAL,
                        command=lambda d=dev: self.toggle_port_5555(d, open_it=False)
                    )
                else:
                    btn_port.config(
                        text="Abrir puerto 5555",
                        state=tk.NORMAL,
                        command=lambda d=dev: self.toggle_port_5555(d, open_it=True)
                    )
            else:
                btn_port.config(
                    text="Puerto",
                    state=tk.NORMAL,
                    command=lambda d=dev: self.prompt_custom_port(d)
                )

        chk = row_info.get("chk")
        if chk:
            chk.config(state=tk.NORMAL if can_connect else tk.DISABLED)
            if not can_connect:
                row_info["chk_var"].set(False)

        self._refresh_mic_apk_button(row_info.get("btn_mic_apk"), dev, dev_key)
        self._schedule_mic_probe(dev)

        # Reordenar dinámicamente según el estado de conexión y la IP
        self.apply_filter()

    # ==========================================================================
    # ACCIONES INDIVIDUALES (CONECTAR, DESCONECTAR, PANTALLA)
    # ==========================================================================

    def connect_single_device(self, dev):
        """Conecta un dispositivo individual seleccionado a ADB."""
        dev_key = dev["key"]
        self.set_status(f"Conectando ADB a {dev['name']} ({dev['ip']})...")
        threading.Thread(target=self._connect_single_worker, args=(dev,), daemon=True).start()

    def _connect_single_worker(self, dev):
        dev_key = dev["key"]
        ip = dev["ip"]
        known_p = dev.get("port", "")
        row_info = self.device_rows.get(dev_key)
        if row_info:
            self.post_gui(lambda inf=row_info: inf["status_lbl"].config(text="⏳ Conectando...", foreground="#b36b00"))

        self.user_disconnected.discard(ip)
        self.user_disconnected.discard(f"{ip}:{known_p}")
        ok, detail, model = connect_ip_automatically(ip, known_port=known_p, status_callback=self.set_status)
        if ok:
            ensure_storage_mount()
            ensure_device_internet_stability(detail)
            dev["is_adb_connected"] = True
            dev["serial"] = detail
            if model:
                dev["name"] = model
            self.set_status(f"¡Conectado exitosamente a {dev['name']} ({detail})!")
            self.post_gui(self._update_row_state_by_key, dev_key, dev)
            self._schedule_mic_probe(dev)
        else:
            open_now = check_tcp_ports_fast(ip, [5555, 7888])
            dev["is_port_open"] = bool(open_now)
            self.set_status(f"No se pudo conectar a {dev['name']}: {detail}")
            self.post_gui(self._update_row_state_by_key, dev_key, dev)
            self.post_gui(messagebox.showwarning, "Error de Conexión ADB", f"No se pudo conectar a {dev['name']}:\n{detail}")

    def disconnect_single_device(self, dev):
        """Desconecta el dispositivo seleccionado de ADB. PERMANECE DESCONECTADO sin reconexión automática."""
        dev_key = dev["key"]
        ip = dev["ip"]
        if dev.get("is_usb") and not dev.get("serial", "").startswith(ip):
            messagebox.showinfo("Dispositivo USB Directo", f"{dev['name']} está conectado físicamente por cable USB directo.")
            return

        serial_target = dev.get("serial") or (f"{ip}:{dev['port']}" if dev.get("port") else ip)
        self.user_disconnected.add(ip)
        self.user_disconnected.add(serial_target)
        if ":" in serial_target:
            self.user_disconnected.add(serial_target.split(":")[0])
        self.set_status(f"Desconectando {dev['name']} ({serial_target})...")
        cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        try:
            subprocess.run(["adb", "disconnect", serial_target], capture_output=True, creationflags=cflags, timeout=3)
            if ":" in serial_target:
                subprocess.run(["adb", "disconnect", serial_target.split(":")[0]], capture_output=True, creationflags=cflags, timeout=2)
            dev["is_adb_connected"] = False
            open_p = check_tcp_ports_fast(ip, [5555, 7888])
            dev["is_port_open"] = bool(open_p)
            if open_p:
                dev["port"] = open_p[0]
            self.set_status(f"Dispositivo {dev['name']} desconectado de ADB.")
            self.post_gui(self._update_row_state_by_key, dev_key, dev)
        except Exception as e:
            self.set_status(f"Error al desconectar: {e}")


    def enable_wifi_mode_for_usb_device(self, dev):
        """Activa el modo Wi-Fi (puerto 5555) en un dispositivo conectado por cable USB."""
        serial = dev.get("serial")
        if not serial or ":" in serial:
            usb_devs = get_usb_connected_devices()
            for u in usb_devs:
                if u.get("serial"):
                    serial = u["serial"]
                    break

        if not serial:
            messagebox.showwarning("Sin Conexión USB", "No se detectó ningún dispositivo Android conectado por cable USB.")
            return

        dev_title = dev.get("name", "dispositivo")
        self.set_status(f"Activando modo Wi-Fi en {dev_title} ({serial})...")
        cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

        def _worker():
            try:
                # 1. Consultar TODAS las IPs reales en vivo, modelo, SSID y MAC por USB antes de tocar tcpip 5555
                net_det = get_usb_device_net_details(serial, cflags=cflags)
                dev_ssid, dev_mac = get_usb_device_ssid_and_mac(serial, cflags=cflags)
                cand_ips = list(net_det.get("all_ips", []))

                if not cand_ips and dev.get("wlan_ip"):
                    cand_ips.append(dev["wlan_ip"])
                elif not cand_ips and dev.get("ip"):
                    m_dev_ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", str(dev.get("ip", "")))
                    if m_dev_ip:
                        cand_ips.append(m_dev_ip.group(1))

                dev_name = dev.get("name", "Android")
                m_prop = net_det.get("model", "")
                if m_prop and ("USB" in dev_name or "dispositivo" in dev_name.lower()):
                    if m_prop.startswith("E") or m_prop.startswith("A920") or "e700" in m_prop.lower() or "e800" in m_prop.lower():
                        dev_name = f"PAX {m_prop}"
                    elif "A23" in m_prop or m_prop.startswith("SM_A"):
                        dev_name = f"Samsung {m_prop}"
                    else:
                        dev_name = m_prop

                # 2. Actualizar red actual del PC sin depender de cache viejo
                pc_ip, pc_subnet, _, pc_net_name = get_network_info()
                pc_ssid = get_current_wifi_ssid()
                self.local_ip = pc_ip
                self.subnet = pc_subnet
                self.current_net_name = pc_net_name

                if not cand_ips:
                    prepare_usb_device_for_wifi_adb(serial, cflags=cflags, port=5555)
                    self.post_gui(messagebox.showwarning, "Sin Red Wi-Fi en el Equipo",
                                  f"El puerto 5555 fue habilitado en {dev_name} ({serial}), pero el equipo no está conectado a ninguna red Wi-Fi.\n\n"
                                  f"Conecta el {dev_name} al Wi-Fi (puedes abrir Pantalla directamente por USB mientras tanto) e inténtalo de nuevo.")
                    return

                # 3. Despertar tabla ARP y puente entre bandas (ej. 5GHz <-> 2.4GHz) desde el equipo hacia el PC
                ping_ok, _ = wake_device_to_pc_route(serial, pc_ip, cflags=cflags)

                # 4. Probar primero si ya conecta directo por Wi-Fi sin reiniciar adbd innecesariamente
                connected_ip = ""
                conn_out = ""
                is_wifi_online = False
                for try_ip in cand_ips:
                    ok_pre, out_pre, _ = connect_adb_endpoint_verified(f"{try_ip}:5555", cflags=cflags, attempts=1)
                    if ok_pre:
                        connected_ip = try_ip
                        conn_out = out_pre
                        is_wifi_online = True
                        break

                # 5. Si no conectó directo, habilitar tcpip 5555 de forma segura y volver a despertar ARP + conectar
                if not is_wifi_online:
                    self.set_status(f"Abriendo puerto 5555 en {dev_name} ({serial})...")
                    prepare_usb_device_for_wifi_adb(serial, cflags=cflags, port=5555, force_tcpip=True)
                    ping_ok2, _ = wake_device_to_pc_route(serial, pc_ip, cflags=cflags)
                    ping_ok = ping_ok or ping_ok2
                    for try_ip in cand_ips:
                        ok_post, out_post, is_unauth = connect_adb_endpoint_verified(f"{try_ip}:5555", cflags=cflags, attempts=2)
                        conn_out = out_post
                        if ok_post:
                            connected_ip = try_ip
                            is_wifi_online = True
                            break
                        if is_unauth:
                            break

                primary_ip = connected_ip or cand_ips[0]
                if is_wifi_online:
                    save_known_device(primary_ip, name=dev_name, mac=dev_mac, is_static=True, last_port="5555", network=pc_net_name)
                    ensure_device_internet_stability(f"{primary_ip}:5555")
                    net_label = dev_ssid or pc_net_name
                    self.post_gui(messagebox.showinfo, "¡Conexión Wi-Fi Exitosa!",
                                  f"¡{dev_name} conectado exitosamente por Wi-Fi en {primary_ip}:5555!\n"
                                  f"Red: {net_label}\n\n"
                                  f"Ya puedes desconectar el cable USB si lo deseas.")
                    self.set_status(f"¡{dev_name} conectado por Wi-Fi en {primary_ip}:5555!")
                else:
                    if not ping_ok:
                        self.post_gui(messagebox.showwarning, "Redes Wi-Fi Aisladas o Distintas",
                                      f"El puerto 5555 quedó activo por USB, pero no hay ruta de red Wi-Fi entre ambos equipos:\n\n"
                                      f"• {dev_name}: Red '{dev_ssid or 'Desconocida'}' (IP {primary_ip})\n"
                                      f"• Este PC: Red '{pc_ssid or pc_net_name}' (IP {pc_ip})\n\n"
                                      f"Conéctalos a la misma red Wi-Fi/hotspot para usar conexión inalámbrica. Mientras tanto, 'Pantalla' y 'Archivos' siguen funcionando por cable USB.")
                    else:
                        self.post_gui(messagebox.showwarning, "Puerto 5555 Activo — Sin Respuesta Wi-Fi",
                                      f"El puerto 5555 se abrió en {dev_name} ({primary_ip}), pero ADB no completó el enlace:\n{conn_out}\n\n"
                                      f"En {dev_name}, verifica que el Wi-Fi no tenga aislamiento de clientes o reinicia Depuración USB.")

                self.trigger_scan()
            except Exception as ex:
                self.post_gui(messagebox.showerror, "Error", f"Error al activar modo Wi-Fi: {ex}")

        threading.Thread(target=_worker, daemon=True).start()

    def open_device_file_manager(self, dev):
        """Abre el Explorador de Archivos ADB integrado con barra de progreso estilo Windows,
        arrastrar y soltar (Drag and Drop), copiar/cortar/pegar y atajos de teclado.
        Conecta por ADB automáticamente si el dispositivo no estaba conectado."""
        dev = self._get_row_dev(dev.get("key"), dev) if dev else {}
        dev_name = dev.get("name", "Dispositivo")
        ip = dev.get("ip", "")
        serial = dev.get("serial", "")
        dev_key = dev.get("key", ip)

        serial_target = dev.get("serial")
        if not serial_target:
            if dev.get("port"):
                serial_target = f"{dev['ip']}:{dev['port']}"
            else:
                serial_target = dev.get("ip", "")

        resolved = resolve_active_adb_target(serial_target, dev=dev)
        cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

        is_already_active = False
        if dev.get("is_usb"):
            chk_t = resolved or serial_target
            try:
                chk = subprocess.run(["adb", "-s", str(chk_t), "get-state"], capture_output=True, text=True, creationflags=cflags, timeout=1.5)
                if "device" in chk.stdout:
                    is_already_active = True
            except Exception:
                pass
        else:
            if resolved:
                try:
                    chk = subprocess.run(["adb", "-s", str(resolved), "get-state"], capture_output=True, text=True, creationflags=cflags, timeout=1.5)
                    if "device" in chk.stdout:
                        is_already_active = True
                except Exception:
                    pass

        if not is_already_active and not dev.get("is_usb"):
            self.set_status(f"Conectando ADB a {dev_name} ({ip}) para acceder a sus archivos...")
            threading.Thread(target=self._auto_connect_and_open_files, args=(dev,), daemon=True).start()
            return

        self._show_device_file_manager_window(dev, resolved or serial_target)

    def _auto_connect_and_open_files(self, dev):
        dev_key = dev.get("key", dev.get("ip", ""))
        ip = dev.get("ip", "")
        dev_name = dev.get("name", "Dispositivo")
        row_info = self.device_rows.get(dev_key)
        if row_info:
            self.post_gui(lambda inf=row_info: inf["status_lbl"].config(text="⏳ Conectando...", foreground="#b36b00"))

        ok, detail, model = connect_ip_automatically(ip, known_port=dev.get("port", ""), status_callback=self.set_status)
        if ok:
            ensure_storage_mount()
            ensure_device_internet_stability(detail)
            dev["is_adb_connected"] = True
            dev["serial"] = detail
            if model:
                dev["name"] = model
            resolved = resolve_active_adb_target(detail, dev=dev) or detail
            self.post_gui(self._update_row_state_by_key, dev_key, dev)
            self.set_status(f"¡Conectado exitosamente a {dev['name']}! Abriendo archivos...")
            self.post_gui(self._show_device_file_manager_window, dev, resolved)
        else:
            open_now = check_tcp_ports_fast(ip, [5555, 7888])
            dev["is_port_open"] = bool(open_now)
            self.post_gui(self._update_row_state_by_key, dev_key, dev)
            self.post_gui(messagebox.showwarning, "No se pudo acceder a archivos",
                          f"No se pudo conectar a {dev_name} ({ip}) por ADB.\n\nDetalle: {detail}\n\nVerifique que el dispositivo esté encendido, conectado a la red y con depuración ADB activa.")

    def _show_device_file_manager_window(self, dev, target):
        dev_name = dev.get("name", "Dispositivo")
        ip = dev.get("ip", "")
        serial = dev.get("serial", "")
        mounted_drive = get_device_mounted_drive(dev_name, ip or serial)

        dialog = tk.Toplevel(self.root)
        dialog.title(f"📁 Explorador de Archivos ADB - {dev_name} ({target})")
        dialog.geometry("920x640")
        dialog.minsize(760, 520)
        dialog.transient(self.root)

        cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        current_target = [target]

        def ensure_connected_target(force_reconnect=False):
            t = current_target[0]
            if dev.get("is_usb"):
                return t
            if not force_reconnect:
                try:
                    chk = subprocess.run(["adb", "-s", str(t), "get-state"], capture_output=True, text=True, creationflags=cflags, timeout=1.5)
                    if "device" in chk.stdout:
                        return t
                except Exception:
                    pass
            if ip:
                ok, detail, model = connect_ip_automatically(ip, known_port=dev.get("port", ""))
                if ok:
                    dev["is_adb_connected"] = True
                    dev["serial"] = detail
                    new_t = resolve_active_adb_target(detail, dev=dev) or detail
                    current_target[0] = new_t
                    try:
                        dialog.after(0, lambda: dialog.title(f"📁 Explorador de Archivos ADB - {dev_name} ({new_t})"))
                    except Exception:
                        pass
                    return new_t
            return t

        def run_adb(cmd_args, timeout=8, max_retries=1):
            """Ejecuta un comando ADB con reintento y reconexión automática si el dispositivo se desconecta."""
            t = ensure_connected_target(force_reconnect=False)
            full_cmd = ["adb", "-s", str(t)] + list(cmd_args)
            try:
                res = subprocess.run(full_cmd, capture_output=True, text=True, errors="replace",
                                     creationflags=cflags, timeout=timeout)
            except Exception as ex:
                res = subprocess.CompletedProcess(full_cmd, 1, stdout="", stderr=str(ex))

            raw_err = (res.stderr or "").lower()
            raw_out = (res.stdout or "").lower()
            is_offline = any(k in raw_err or k in raw_out for k in ("not found", "offline", "error: closed", "device '", "cannot connect"))
            if is_offline and max_retries > 0 and not dev.get("is_usb") and ip:
                new_t = ensure_connected_target(force_reconnect=True)
                full_cmd = ["adb", "-s", str(new_t)] + list(cmd_args)
                try:
                    res = subprocess.run(full_cmd, capture_output=True, text=True, errors="replace",
                                         creationflags=cflags, timeout=timeout)
                except Exception as ex:
                    res = subprocess.CompletedProcess(full_cmd, 1, stdout="", stderr=str(ex))
            return res

        # Clipboard interno para transferencias dentro del dispositivo Android
        # {"action": "copy"|"cut", "source_dir": str, "items": list}
        device_clipboard = {"action": "", "source_dir": "", "items": []}

        # Funciones auxiliares de formateo (Estilo Windows)
        def _format_size(sz):
            if sz < 1024:
                return f"{sz} B"
            elif sz < 1024 * 1024:
                return f"{sz / 1024.0:.1f} KB"
            elif sz < 1024 * 1024 * 1024:
                return f"{sz / (1024.0 * 1024.0):.1f} MB"
            else:
                return f"{sz / (1024.0 * 1024.0 * 1024.0):.2f} GB"

        def _format_speed(bps):
            if bps < 1024:
                return f"{bps:.0f} B/s"
            elif bps < 1024 * 1024:
                return f"{bps / 1024.0:.1f} KB/s"
            else:
                return f"{bps / (1024.0 * 1024.0):.1f} MB/s"

        def _format_eta(seconds):
            if seconds is None or seconds <= 0:
                return "Calculando..."
            s = int(seconds)
            if s < 60:
                return f"Aprox. {s} segundo{'s' if s != 1 else ''}"
            m = s // 60
            rem_s = s % 60
            if m < 60:
                return f"Aprox. {m} min {rem_s} s"
            h = m // 60
            rem_m = m % 60
            return f"Aprox. {h} h {rem_m} min"

        def _get_windows_clipboard_files():
            """Lee archivos del portapapeles de Windows (CF_HDROP = 15)."""
            files = []
            try:
                user32 = ctypes.windll.user32
                shell32 = ctypes.windll.shell32
                if not user32.OpenClipboard(None):
                    return files
                try:
                    h_drop = user32.GetClipboardData(15)
                    if h_drop:
                        count = shell32.DragQueryFileW(h_drop, 0xFFFFFFFF, None, 0)
                        buf = ctypes.create_unicode_buffer(1024)
                        for i in range(count):
                            shell32.DragQueryFileW(h_drop, i, buf, 1024)
                            val = buf.value
                            if val and os.path.exists(val):
                                files.append(val)
                finally:
                    user32.CloseClipboard()
            except Exception:
                pass
            return files

        # ----------------------------------------------------------------------
        # DIÁLOGO DE TRANSFERENCIA CON BARRA DE PROGRESO ESTILO WINDOWS Y ETA
        # ----------------------------------------------------------------------
        def run_transfer_with_progress(is_upload, file_pairs, on_complete=None):
            """
            Ejecuta la subida o descarga de archivos mostrando una ventana de progreso
            idéntica a Windows con: porcentaje, velocidad en tiempo real, tiempo restante y botón Cancelar.
            file_pairs: lista de dicts con:
              {
                "src": str,
                "dest_dir": str,
                "dest_name": str,
                "size": int (bytes esperados)
              }
            """
            if not file_pairs:
                return

            total_items = len(file_pairs)
            total_bytes = sum(max(1, p.get("size", 1)) for p in file_pairs)

            # Ventana modal de progreso
            pwin = tk.Toplevel(dialog)
            title_verb = "Subiendo a" if is_upload else "Descargando de"
            pwin.title(f"{title_verb} {dev_name}...")
            pwin.geometry("540x230")
            pwin.resizable(False, False)
            pwin.transient(dialog)

            # Centrar sobre la ventana del explorador
            try:
                dialog.update_idletasks()
                gx = dialog.winfo_rootx() + (dialog.winfo_width() - 540) // 2
                gy = dialog.winfo_rooty() + (dialog.winfo_height() - 230) // 2
                pwin.geometry(f"540x230+{max(0, gx)}+{max(0, gy)}")
            except Exception:
                pass

            pframe = ttk.Frame(pwin, padding=16)
            pframe.pack(fill=tk.BOTH, expand=True)

            action_icon = "📤" if is_upload else "📥"
            main_header = f"{action_icon} {title_verb} {dev_name}"
            lbl_title = ttk.Label(pframe, text=main_header, font=("Segoe UI", 11, "bold"))
            lbl_title.pack(anchor=tk.W, pady=(0, 4))

            lbl_file = ttk.Label(pframe, text="Iniciando transferencia...", font=("Segoe UI", 9))
            lbl_file.pack(anchor=tk.W, pady=(0, 2))

            lbl_stats = ttk.Label(pframe, text="Velocidad: Calculando...  •  Tiempo restante: Calculando...",
                                  font=("Segoe UI", 9), foreground="#0055aa")
            lbl_stats.pack(anchor=tk.W, pady=(0, 8))

            progress_var = tk.DoubleVar(value=0.0)
            progressbar = ttk.Progressbar(pframe, variable=progress_var, maximum=100.0, mode="determinate")
            progressbar.pack(fill=tk.X, pady=(0, 4))

            lbl_size = ttk.Label(pframe, text=f"0 B de {_format_size(total_bytes)} (0%)",
                                 font=("Segoe UI", 8), foreground="#555555")
            lbl_size.pack(anchor=tk.W, pady=(0, 8))

            cancel_flag = {"cancelled": False, "proc": None}

            def _on_cancel():
                cancel_flag["cancelled"] = True
                proc = cancel_flag.get("proc")
                if proc:
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                lbl_stats.config(text="Cancelando transferencia...", foreground="#cc0000")
                pwin.destroy()

            btn_frame = ttk.Frame(pframe)
            btn_frame.pack(fill=tk.X)
            btn_cancel = ttk.Button(btn_frame, text="Cancelar", width=12, command=_on_cancel)
            btn_cancel.pack(side=tk.RIGHT)

            pwin.protocol("WM_DELETE_WINDOW", _on_cancel)

            def _worker():
                bytes_completed_before = 0
                transfer_start_time = time.time()
                last_time = transfer_start_time
                last_bytes = 0

                for idx, item in enumerate(file_pairs, 1):
                    if cancel_flag["cancelled"]:
                        break

                    src_path = item["src"]
                    dest_dir = item["dest_dir"]
                    dest_name = item["dest_name"]
                    item_size = item.get("size", 1)

                    # Actualizar GUI: archivo actual
                    def _update_file_label(i=idx, n=dest_name):
                        if not pwin.winfo_exists():
                            return
                        lbl_file.config(text=f"Elemento {i} de {total_items}: {n}")
                    pwin.after(0, _update_file_label)

                    active_t = ensure_connected_target(force_reconnect=False)
                    if is_upload:
                        cmd = ["adb", "-s", str(active_t), "push", src_path, dest_dir]
                        remote_dest_file = dest_dir.rstrip("/") + "/" + dest_name
                    else:
                        cmd = ["adb", "-s", str(active_t), "pull", src_path, dest_dir]
                        local_dest_file = os.path.join(dest_dir, dest_name)

                    try:
                        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                creationflags=cflags)
                        cancel_flag["proc"] = proc

                        while proc.poll() is None:
                            if cancel_flag["cancelled"]:
                                proc.terminate()
                                break

                            # Medir bytes del archivo actual
                            current_item_done = 0
                            if is_upload:
                                try:
                                    s_res = subprocess.run(["adb", "-s", str(current_target[0]), "shell", f'stat -c %s "{remote_dest_file}"'],
                                                           capture_output=True, text=True, creationflags=cflags, timeout=1.2)
                                    s_out = s_res.stdout.strip()
                                    if s_out.isdigit():
                                        current_item_done = min(item_size, int(s_out))
                                except Exception:
                                    pass
                            else:
                                if os.path.exists(local_dest_file):
                                    try:
                                        current_item_done = min(item_size, os.path.getsize(local_dest_file))
                                    except Exception:
                                        pass

                            total_done = bytes_completed_before + current_item_done
                            now = time.time()
                            elapsed_total = max(0.1, now - transfer_start_time)
                            speed_bps = total_done / elapsed_total

                            remaining_bytes = max(0, total_bytes - total_done)
                            eta_secs = remaining_bytes / max(1024.0, speed_bps) if speed_bps > 0 else 0

                            pct = min(100.0, (total_done / total_bytes) * 100.0)
                            speed_txt = _format_speed(speed_bps)
                            eta_txt = _format_eta(eta_secs)
                            size_txt = f"{_format_size(total_done)} de {_format_size(total_bytes)} ({pct:.0f}%)"

                            def _update_progress(p=pct, sp=speed_txt, et=eta_txt, sz=size_txt):
                                if not pwin.winfo_exists():
                                    return
                                progress_var.set(p)
                                lbl_stats.config(text=f"Velocidad: {sp}  •  Tiempo restante: {et}")
                                lbl_size.config(text=sz)

                            pwin.after(0, _update_progress)
                            time.sleep(0.3)

                        proc.wait()
                        bytes_completed_before += item_size
                    except Exception as ex:
                        pass

                # Al terminar
                def _finish():
                    if pwin.winfo_exists():
                        progress_var.set(100.0)
                        pwin.destroy()
                    if cancel_flag["cancelled"]:
                        status_lbl.config(text="Transferencia cancelada por el usuario.")
                    else:
                        status_lbl.config(text=f"✔ ¡Transferencia completada: {total_items} elemento(s) ({_format_size(total_bytes)})!")
                    if on_complete:
                        on_complete()

                dialog.after(0, _finish)

            threading.Thread(target=_worker, daemon=True).start()

        # ----------------------------------------------------------------------
        # BARRA SUPERIOR E INFORMACIÓN DE DISPOSITIVO / UNIDAD WINDOWS
        # ----------------------------------------------------------------------
        banner_frame = ttk.Frame(dialog, padding=(10, 8, 10, 4))
        banner_frame.pack(fill=tk.X)

        drive_info_text = f"Unidad Windows: {mounted_drive}\\" if mounted_drive else "Unidad Windows: No detectada (transferencia directa ADB activa)"
        lbl_drive_info = ttk.Label(banner_frame, text=f"📱 {dev_name}  |  {drive_info_text}", font=("Segoe UI", 9, "bold"), foreground="#0055aa")
        lbl_drive_info.pack(side=tk.LEFT)

        if mounted_drive:
            def _open_in_windows():
                try:
                    subprocess.Popen(f'explorer.exe "{mounted_drive}\\"', shell=True)
                except Exception as ex:
                    messagebox.showerror("Error", f"No se pudo abrir la unidad: {ex}", parent=dialog)
            btn_win_drive = ttk.Button(banner_frame, text=f"📂 Abrir {mounted_drive}\\ en Windows Explorer", command=_open_in_windows)
            btn_win_drive.pack(side=tk.RIGHT, padx=4)

        # Barra de navegación por carpetas
        nav_frame = ttk.Frame(dialog, padding=(10, 4, 10, 6))
        nav_frame.pack(fill=tk.X)

        ttk.Label(nav_frame, text="Ruta:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 4))

        path_var = tk.StringVar(value="/sdcard/")
        entry_path = ttk.Entry(nav_frame, textvariable=path_var, font=("Consolas", 10))
        entry_path.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))

        # Contenedor de la lista de archivos (Treeview con soporte multi-selección)
        tree_frame = ttk.Frame(dialog, padding=(10, 2, 10, 4))
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("tipo", "nombre", "tamano", "fecha")
        tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="extended")
        tree.heading("tipo", text="Tipo")
        tree.heading("nombre", text="Nombre")
        tree.heading("tamano", text="Tamaño")
        tree.heading("fecha", text="Fecha de Modificación")

        tree.column("tipo", width=80, anchor=tk.CENTER)
        tree.column("nombre", width=420, anchor=tk.W)
        tree.column("tamano", width=110, anchor=tk.E)
        tree.column("fecha", width=170, anchor=tk.CENTER)

        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        status_lbl = ttk.Label(dialog, text="Listo.", relief=tk.SUNKEN, anchor=tk.W, padding=4, font=("Segoe UI", 9))
        status_lbl.pack(fill=tk.X, side=tk.BOTTOM)

        current_items = []

        def load_directory(target_path):
            norm_path = target_path.strip()
            if not norm_path.endswith("/"):
                norm_path += "/"
            path_var.set(norm_path)
            status_lbl.config(text=f"Cargando archivos de {norm_path}...")
            dialog.config(cursor="watch")

            def _fetch():
                items = []
                err_msg = ""
                try:
                    res = run_adb(["shell", f'ls -la "{norm_path}"'], timeout=10)
                    for line in res.stdout.splitlines():
                        parsed = parse_android_ls_line(line)
                        if not parsed:
                            continue
                        is_dir = parsed["is_dir"]
                        sz = parsed["size"]
                        items.append({
                            "name": parsed["name"],
                            "is_dir": is_dir,
                            "is_link": parsed["is_link"],
                            "size": sz,
                            "size_str": "-" if is_dir else _format_size(sz),
                            "date": parsed["date"]
                        })
                    # Resolver symlinks (ej. /sdcard -> /storage/self/primary) para permitir navegarlos como carpetas
                    link_items = [it for it in items if it.get("is_link")]
                    if link_items:
                        norm_prefix = "/" if norm_path == "/" else (norm_path.rstrip("/") + "/")
                        checks = " ; ".join(
                            f'[ -d "{norm_prefix}{it["name"].replace(chr(34), "")}" ] && echo "{it["name"].replace(chr(34), "")}"'
                            for it in link_items
                        )
                        try:
                            chk_res = run_adb(["shell", checks], timeout=5)
                            dir_links = {ln.strip() for ln in chk_res.stdout.splitlines() if ln.strip()}
                            for it in link_items:
                                if it["name"] in dir_links:
                                    it["is_dir"] = True
                                    it["size_str"] = "-"
                        except Exception:
                            pass
                    if not items and res.returncode != 0:
                        raw_err = (res.stderr or res.stdout or "").strip()
                        if raw_err:
                            err_msg = raw_err.splitlines()[-1]
                        # Fallbacks inteligentes si la ruta inicial no existe en este dispositivo
                        if norm_path == "/sdcard/":
                            dialog.after(0, lambda: load_directory("/storage/emulated/0/"))
                            return
                        elif norm_path == "/storage/emulated/0/":
                            dialog.after(0, lambda: load_directory("/"))
                            return
                    items.sort(key=lambda x: (0 if x["is_dir"] else 1, x["name"].lower()))
                except Exception as ex:
                    err_msg = str(ex)

                def _populate():
                    if not dialog.winfo_exists():
                        return
                    for row_id in tree.get_children():
                        tree.delete(row_id)
                    current_items.clear()
                    for it in items:
                        current_items.append(it)
                        icon_type = "📁 Carpeta" if it["is_dir"] else "📄 Archivo"
                        tree.insert("", tk.END, values=(icon_type, it["name"], it["size_str"], it["date"]))
                    dirs_cnt = sum(1 for it in items if it["is_dir"])
                    files_cnt = len(items) - dirs_cnt
                    if err_msg and not items:
                        status_lbl.config(text=f"Error al acceder a {norm_path}: {err_msg}")
                    else:
                        status_lbl.config(text=f"{dirs_cnt} carpetas, {files_cnt} archivos en {norm_path} | Listo.")
                    dialog.config(cursor="")

                dialog.after(0, _populate)

            threading.Thread(target=_fetch, daemon=True).start()

        def go_to_entered():
            load_directory(path_var.get())

        entry_path.bind("<Return>", lambda e: go_to_entered())
        ttk.Button(nav_frame, text="Ir", width=4, command=go_to_entered).pack(side=tk.LEFT, padx=(0, 8))

        def go_up():
            curr = path_var.get().strip().rstrip("/")
            if not curr or curr == "/":
                return
            if "/" in curr:
                parent = curr.rsplit("/", 1)[0]
                if not parent:
                    parent = "/"
                load_directory(parent)
            else:
                load_directory("/")

        ttk.Button(nav_frame, text="⬆ Arriba", command=go_up).pack(side=tk.LEFT, padx=2)
        ttk.Button(nav_frame, text="📂 Raíz (/)", command=lambda: load_directory("/")).pack(side=tk.LEFT, padx=2)
        ttk.Button(nav_frame, text="🏠 Almacenamiento", command=lambda: load_directory("/sdcard/")).pack(side=tk.LEFT, padx=2)
        ttk.Button(nav_frame, text="📥 Descargas", command=lambda: load_directory("/sdcard/Download/")).pack(side=tk.LEFT, padx=2)
        ttk.Button(nav_frame, text="📷 Fotos", command=lambda: load_directory("/sdcard/DCIM/")).pack(side=tk.LEFT, padx=2)
        ttk.Button(nav_frame, text="🔄 Refrescar", command=lambda: load_directory(path_var.get())).pack(side=tk.LEFT, padx=2)

        # ----------------------------------------------------------------------
        # SUBIDA Y DESCARGA CON BARRA DE PROGRESO
        # ----------------------------------------------------------------------
        def upload_specific_files(file_list):
            """Sube una lista de rutas locales de PC al directorio actual con barra de progreso."""
            if not file_list:
                return
            curr_dir = path_var.get()
            file_pairs = []
            for src_path in file_list:
                src_path = os.path.normpath(src_path)
                if not os.path.exists(src_path):
                    continue
                name = os.path.basename(src_path)
                sz = 1
                if os.path.isfile(src_path):
                    sz = os.path.getsize(src_path)
                elif os.path.isdir(src_path):
                    for r, d, fnames in os.walk(src_path):
                        for fn in fnames:
                            try:
                                sz += os.path.getsize(os.path.join(r, fn))
                            except Exception:
                                pass
                file_pairs.append({
                    "src": src_path,
                    "dest_dir": curr_dir,
                    "dest_name": name,
                    "size": sz
                })

            if not file_pairs:
                return

            run_transfer_with_progress(is_upload=True, file_pairs=file_pairs,
                                       on_complete=lambda: load_directory(curr_dir))

        def upload_files():
            files = filedialog.askopenfilenames(parent=dialog, title="Seleccionar archivo(s) para subir al dispositivo")
            if files:
                upload_specific_files(files)

        def upload_folder():
            folder = filedialog.askdirectory(parent=dialog, title="Seleccionar carpeta para subir al dispositivo")
            if folder:
                upload_specific_files([folder])

        def download_selected():
            sel = tree.selection()
            if not sel:
                messagebox.showinfo("Selecciona elemento(s)", "Selecciona uno o más archivos o carpetas para descargar.", parent=dialog)
                return

            dest_dir = filedialog.askdirectory(parent=dialog, title="Seleccionar carpeta en la PC para guardar")
            if not dest_dir:
                return

            curr_dir = path_var.get().rstrip("/")
            file_pairs = []
            for item_id in sel:
                vals = tree.item(item_id, "values")
                name = vals[1]
                remote_full = f"{curr_dir}/{name}"

                # Obtener tamaño aproximado
                sz = 1024
                for ci in current_items:
                    if ci["name"] == name:
                        sz = ci.get("size", 1024)
                        break

                file_pairs.append({
                    "src": remote_full,
                    "dest_dir": dest_dir,
                    "dest_name": name,
                    "size": max(1024, sz)
                })

            run_transfer_with_progress(is_upload=False, file_pairs=file_pairs,
                                       on_complete=lambda: status_lbl.config(text=f"✔ Archivos descargados en {dest_dir}"))

        def on_item_double_click(event):
            sel = tree.selection()
            if not sel:
                return
            item_vals = tree.item(sel[0], "values")
            if not item_vals:
                return
            tipo, name = item_vals[0], item_vals[1]
            curr_dir = path_var.get().rstrip("/")
            if "Carpeta" in tipo:
                new_path = f"{curr_dir}/{name}/"
                load_directory(new_path)
            else:
                download_selected()

        tree.bind("<Double-1>", on_item_double_click)
        tree.bind("<Return>", on_item_double_click)
        tree.bind("<BackSpace>", lambda e: go_up())

        # ----------------------------------------------------------------------
        # ARRASTRAR Y SOLTAR (DRAG AND DROP) DESDE WINDOWS
        # ----------------------------------------------------------------------
        def on_files_dropped(dropped_files):
            if not dropped_files:
                return
            cleaned = []
            for item in dropped_files:
                if isinstance(item, bytes):
                    try:
                        p = item.decode("utf-8")
                    except Exception:
                        p = item.decode("mbcs", errors="replace")
                else:
                    p = str(item)
                p = os.path.normpath(p.strip())
                if os.path.exists(p):
                    cleaned.append(p)
            if cleaned:
                upload_specific_files(cleaned)

        try:
            import windnd
            windnd.hook_dropfiles(dialog, func=on_files_dropped, force_unicode=True)
            windnd.hook_dropfiles(tree, func=on_files_dropped, force_unicode=True)
        except Exception:
            pass

        # ----------------------------------------------------------------------
        # OPERACIONES: COPIAR, CORTAR, PEGAR, RENOMBRAR, ELIMINAR
        # ----------------------------------------------------------------------
        def copy_selection():
            sel = tree.selection()
            if not sel:
                return
            names = [tree.item(s, "values")[1] for s in sel]
            device_clipboard["action"] = "copy"
            device_clipboard["source_dir"] = path_var.get().rstrip("/")
            device_clipboard["items"] = names
            status_lbl.config(text=f"📋 Copiado: {len(names)} elemento(s). Ve a la carpeta de destino y pulsa Pegar (Ctrl+V).")

        def cut_selection():
            sel = tree.selection()
            if not sel:
                return
            names = [tree.item(s, "values")[1] for s in sel]
            device_clipboard["action"] = "cut"
            device_clipboard["source_dir"] = path_var.get().rstrip("/")
            device_clipboard["items"] = names
            status_lbl.config(text=f"✂ Cortado: {len(names)} elemento(s). Ve a la carpeta de destino y pulsa Pegar (Ctrl+V).")

        def paste_action():
            # 1. Comprobar si hay archivos en el portapapeles de Windows (Ctrl+C en el explorador de Windows)
            win_files = _get_windows_clipboard_files()
            if win_files:
                status_lbl.config(text=f"📋 Pegando {len(win_files)} archivo(s) desde el Portapapeles de Windows...")
                upload_specific_files(win_files)
                return

            # 2. Comprobar si hay elementos copiados/cortados dentro del dispositivo Android
            items = device_clipboard.get("items", [])
            action = device_clipboard.get("action", "")
            src_dir = device_clipboard.get("source_dir", "")
            dest_dir = path_var.get().rstrip("/")

            if not items or not action or not src_dir:
                messagebox.showinfo("Portapapeles Vacío",
                                    "No hay archivos en el portapapeles.\nPuedes copiar archivos en Windows (Ctrl+C) y pegarlos aquí,\no seleccionar archivos del dispositivo y usar Copiar/Cortar.",
                                    parent=dialog)
                return

            verb = "Copiando" if action == "copy" else "Moviendo"
            status_lbl.config(text=f"{verb} {len(items)} elemento(s) a {dest_dir}...")

            def _paste_worker():
                for it_name in items:
                    src_full = f"{src_dir}/{it_name}"
                    dest_full = f"{dest_dir}/{it_name}"
                    if action == "copy":
                        run_adb(["shell", f'cp -r "{src_full}" "{dest_full}"'], timeout=30)
                    elif action == "cut":
                        run_adb(["shell", f'mv "{src_full}" "{dest_full}"'], timeout=10)

                if action == "cut":
                    device_clipboard["items"] = []
                    device_clipboard["action"] = ""

                dialog.after(0, lambda: [status_lbl.config(text=f"✔ ¡Pegado completado en {dest_dir}!"), load_directory(dest_dir)])

            threading.Thread(target=_paste_worker, daemon=True).start()

        def rename_selected():
            sel = tree.selection()
            if not sel:
                return
            old_name = tree.item(sel[0], "values")[1]
            new_name = simpledialog.askstring("Renombrar", f"Nuevo nombre para '{old_name}':",
                                              initialvalue=old_name, parent=dialog)
            if not new_name or not new_name.strip() or new_name.strip() == old_name:
                return

            clean_name = new_name.strip().replace('"', "")
            curr_dir = path_var.get().rstrip("/")
            src_full = f"{curr_dir}/{old_name}"
            dest_full = f"{curr_dir}/{clean_name}"

            try:
                run_adb(["shell", f'mv "{src_full}" "{dest_full}"'], timeout=5)
                load_directory(path_var.get())
            except Exception as ex:
                messagebox.showerror("Error", f"No se pudo renombrar: {ex}", parent=dialog)

        def create_folder():
            name = simpledialog.askstring("Nueva Carpeta", "Ingresa el nombre de la nueva carpeta:", parent=dialog)
            if not name or not name.strip():
                return
            clean_name = name.strip().replace('"', "")
            curr_dir = path_var.get().rstrip("/")
            new_full = f"{curr_dir}/{clean_name}"
            status_lbl.config(text=f"Creando carpeta {clean_name}...")
            try:
                run_adb(["shell", f'mkdir -p "{new_full}"'], timeout=5)
                load_directory(path_var.get())
            except Exception as ex:
                messagebox.showerror("Error", f"No se pudo crear la carpeta: {ex}", parent=dialog)

        def delete_selected():
            sel = tree.selection()
            if not sel:
                messagebox.showinfo("Selecciona elemento(s)", "Selecciona uno o más archivos o carpetas para eliminar.", parent=dialog)
                return
            names = [tree.item(s, "values")[1] for s in sel]
            msg = f"¿Estás seguro de que deseas eliminar permanentemente '{names[0]}'?" if len(names) == 1 else f"¿Estás seguro de que deseas eliminar permanentemente {len(names)} elementos seleccionados?"
            if not messagebox.askyesno("Confirmar Eliminación", msg, parent=dialog):
                return
            curr_dir = path_var.get().rstrip("/")
            status_lbl.config(text=f"Eliminando {len(names)} elemento(s)...")

            def _del_worker():
                for it_name in names:
                    full_p = f"{curr_dir}/{it_name}"
                    try:
                        run_adb(["shell", f'rm -rf "{full_p}"'], timeout=8)
                    except Exception:
                        pass
                dialog.after(0, lambda: load_directory(curr_dir))

            threading.Thread(target=_del_worker, daemon=True).start()

        # ----------------------------------------------------------------------
        # MENÚ CONTEXTUAL DE CLIC DERECHO
        # ----------------------------------------------------------------------
        def show_context_menu(event):
            row_id = tree.identify_row(event.y)
            if row_id:
                if row_id not in tree.selection():
                    tree.selection_set(row_id)

            sel = tree.selection()
            menu = tk.Menu(dialog, tearoff=0)

            can_paste = bool(_get_windows_clipboard_files() or device_clipboard.get("items"))

            if sel:
                menu.add_command(label="📋 Copiar (Ctrl+C)", command=copy_selection)
                menu.add_command(label="✂ Cortar (Ctrl+X)", command=cut_selection)
                menu.add_command(label="📋 Pegar (Ctrl+V)", command=paste_action,
                                 state=tk.NORMAL if can_paste else tk.DISABLED)
                menu.add_separator()
                menu.add_command(label="📥 Descargar a la PC...", command=download_selected)
                if len(sel) == 1:
                    menu.add_command(label="✏ Renombrar... (F2)", command=rename_selected)
                menu.add_command(label="🗑 Eliminar (Supr)", command=delete_selected)
            else:
                menu.add_command(label="📋 Pegar (Ctrl+V)", command=paste_action,
                                 state=tk.NORMAL if can_paste else tk.DISABLED)
                menu.add_separator()
                menu.add_command(label="➕ Nueva Carpeta...", command=create_folder)
                menu.add_command(label="🔄 Refrescar (F5)", command=lambda: load_directory(path_var.get()))

            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()

        tree.bind("<Button-3>", show_context_menu)

        # Atajos de teclado en el explorador
        dialog.bind("<Control-c>", lambda e: copy_selection())
        dialog.bind("<Control-C>", lambda e: copy_selection())
        dialog.bind("<Control-x>", lambda e: cut_selection())
        dialog.bind("<Control-X>", lambda e: cut_selection())
        dialog.bind("<Control-v>", lambda e: paste_action())
        dialog.bind("<Control-V>", lambda e: paste_action())
        dialog.bind("<Delete>", lambda e: delete_selected())
        dialog.bind("<F2>", lambda e: rename_selected())
        dialog.bind("<F5>", lambda e: load_directory(path_var.get()))

        # ----------------------------------------------------------------------
        # BARRA DE ACCIONES INFERIOR
        # ----------------------------------------------------------------------
        act_frame = ttk.Frame(dialog, padding=(10, 6, 10, 8))
        act_frame.pack(fill=tk.X, side=tk.BOTTOM)

        ttk.Button(act_frame, text="📤 Subir Archivo(s)", command=upload_files).pack(side=tk.LEFT, padx=3)
        ttk.Button(act_frame, text="📁 Subir Carpeta", command=upload_folder).pack(side=tk.LEFT, padx=3)
        ttk.Button(act_frame, text="📥 Descargar a la PC", command=download_selected).pack(side=tk.LEFT, padx=3)
        ttk.Button(act_frame, text="➕ Nueva Carpeta", command=create_folder).pack(side=tk.LEFT, padx=3)
        ttk.Button(act_frame, text="✏ Renombrar", command=rename_selected).pack(side=tk.LEFT, padx=3)
        ttk.Button(act_frame, text="🗑 Eliminar", command=delete_selected).pack(side=tk.LEFT, padx=3)

        ttk.Button(act_frame, text="Cerrar", command=dialog.destroy).pack(side=tk.RIGHT, padx=4)

        # Cargar directorio inicial
        load_directory("/sdcard/")


    def open_qr_pairing_dialog(self):
        """Abre directamente el diálogo de vinculación por código QR desde la barra de herramientas."""
        self.prompt_custom_port(dev=None)

    def prompt_custom_port(self, dev=None):
        """Abre un diálogo modal para vincular con Código QR o 6 dígitos en una sola pestaña, y conectar por puerto."""
        if dev is None:
            dev = {"name": "Nuevo Dispositivo", "ip": "", "key": "", "port": ""}

        name = dev.get("name", "Dispositivo")
        ip = dev.get("ip", "")
        pc_ip = getattr(self, "local_ip", None) or get_wifi_adapter_ip()
        current_port = str(dev.get("port") or dev.get("last_port") or "")
        if current_port in ("5555", "None"):
            current_port = ""

        dialog = tk.Toplevel(self.root)
        dialog.title(f"Depuración Inalámbrica - {name}")
        dialog.geometry("690x560")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        try:
            x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 345
            y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 280
            dialog.geometry(f"+{x}+{y}")
        except Exception:
            pass

        main_f = ttk.Frame(dialog, padding=12)
        main_f.pack(fill=tk.BOTH, expand=True)

        header_title = f"Configurar Conexión: {name}" if ip else "Vincular Dispositivo Android por Wi-Fi"
        ttk.Label(main_f, text=header_title, font=("Segoe UI", 11, "bold")).pack(anchor=tk.W, pady=(0, 2))
        if ip:
            ttk.Label(main_f, text=f"IP del equipo: {ip} | Red Actual: {self.current_net_name}", font=("Consolas", 9), foreground="#0066cc").pack(anchor=tk.W, pady=(0, 6))
        else:
            ttk.Label(main_f, text=f"Red Actual: {self.current_net_name} (IP de esta PC: {pc_ip})", font=("Segoe UI", 9), foreground="#0066cc").pack(anchor=tk.W, pady=(0, 6))

        notebook = ttk.Notebook(main_f)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 6))

        # Variables de control para la sesión QR
        stop_qr_event = threading.Event()
        current_zeroconf = [None]

        def stop_qr_session():
            stop_qr_event.set()
            if current_zeroconf[0]:
                try:
                    current_zeroconf[0].close()
                except Exception:
                    pass
                current_zeroconf[0] = None

        def on_dialog_close():
            stop_qr_session()
            dialog.destroy()

        dialog.protocol("WM_DELETE_WINDOW", on_dialog_close)
        dialog.bind("<Escape>", lambda e: on_dialog_close())

        # ======================================================================
        # PESTAÑA 1: VINCULAR DISPOSITIVO (CÓDIGO QR Y MANUAL 6 DÍGITOS JUNTOS)
        # ======================================================================
        tab_pair_all = ttk.Frame(notebook, padding=10)
        notebook.add(tab_pair_all, text="  🔗 Vincular Dispositivo (QR o Código)  ")

        content_cols = ttk.Frame(tab_pair_all)
        content_cols.pack(fill=tk.BOTH, expand=True)

        # --- Columna Izquierda: Código QR Automático ---
        col_left = ttk.LabelFrame(content_cols, text=" Opción A: Código QR (Automático) ", padding=8)
        col_left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        ttk.Label(
            col_left,
            text="1. En el teléfono: Opciones de desarrollador\n   -> Depuración inalámbrica.\n2. Toca 'Vincular disp. mediante código QR'.\n3. Apunta la cámara hacia este código:",
            font=("Segoe UI", 8),
            justify=tk.LEFT
        ).pack(anchor=tk.W, pady=(0, 4))

        qr_box = ttk.Frame(col_left, relief=tk.SOLID, borderwidth=1, padding=2)
        qr_box.pack(pady=2)
        qr_lbl = ttk.Label(qr_box)
        qr_lbl.pack()

        qr_status_lbl = ttk.Label(
            col_left,
            text="⏳ Esperando escaneo con la cámara...",
            font=("Segoe UI", 8, "bold"),
            foreground="#0066cc",
            wraplength=230,
            justify=tk.CENTER
        )
        qr_status_lbl.pack(pady=(4, 4))

        btn_regen = ttk.Button(col_left, text="🔄 Generar nuevo QR", command=lambda: start_qr_session())
        btn_regen.pack(pady=(2, 0))

        # --- Columna Derecha: Vinculación Manual (6 Dígitos) ---
        col_right = ttk.LabelFrame(content_cols, text=" Opción B: Código de 6 Dígitos (Manual) ", padding=8)
        col_right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))

        ttk.Label(
            col_right,
            text="1. En 'Depuración inalámbrica', toca:\n   'Vincular con un código de vinculación'.\n2. Ingresa los datos que muestra el teléfono:",
            font=("Segoe UI", 8),
            justify=tk.LEFT
        ).pack(anchor=tk.W, pady=(0, 6))

        grid_f = ttk.Frame(col_right)
        grid_f.pack(fill=tk.X, pady=(2, 8))

        row_idx = 0
        ip_manual_entry = None
        if not ip:
            ttk.Label(grid_f, text="IP del teléfono:", font=("Segoe UI", 8)).grid(row=row_idx, column=0, sticky=tk.W, pady=3)
            ip_manual_entry = ttk.Entry(grid_f, width=14, font=("Consolas", 9))
            ip_manual_entry.grid(row=row_idx, column=1, sticky=tk.W, padx=6, pady=3)
            # Prellenar con la IP móvil detectada si existe
            for r_k, r_info in self.device_rows.items():
                r_dev = r_info.get("dev", {})
                r_ip = r_dev.get("ip", "")
                if r_ip and r_ip != pc_ip and not r_dev.get("is_router") and not r_dev.get("is_local_or_router"):
                    ip_manual_entry.insert(0, r_ip)
                    break
            row_idx += 1

        ttk.Label(grid_f, text="Puerto de vinculación:", font=("Segoe UI", 8)).grid(row=row_idx, column=0, sticky=tk.W, pady=3)
        pair_port_entry = ttk.Entry(grid_f, width=14, font=("Consolas", 9))
        pair_port_entry.grid(row=row_idx, column=1, sticky=tk.W, padx=6, pady=3)
        row_idx += 1

        ttk.Label(grid_f, text="Código (6 dígitos):", font=("Segoe UI", 8)).grid(row=row_idx, column=0, sticky=tk.W, pady=3)
        pair_code_entry = ttk.Entry(grid_f, width=14, font=("Consolas", 9))
        pair_code_entry.grid(row=row_idx, column=1, sticky=tk.W, padx=6, pady=3)
        row_idx += 1

        ttk.Label(grid_f, text="Puerto de conexión:", font=("Segoe UI", 8)).grid(row=row_idx, column=0, sticky=tk.W, pady=3)
        final_port_entry = ttk.Entry(grid_f, width=14, font=("Consolas", 9))
        final_port_entry.grid(row=row_idx, column=1, sticky=tk.W, padx=6, pady=3)
        if current_port:
            final_port_entry.insert(0, current_port)

        def on_confirm_pair(event=None):
            target_ip = ip or (ip_manual_entry.get().strip() if ip_manual_entry else "")
            p_port = pair_port_entry.get().strip()
            p_code = pair_code_entry.get().strip()
            c_port = final_port_entry.get().strip()

            if not target_ip:
                messagebox.showerror("Error", "Ingresa la dirección IP del teléfono.", parent=dialog)
                return
            if not p_port.isdigit() or not (1 <= int(p_port) <= 65535):
                messagebox.showerror("Error", "Ingresa el puerto de vinculación (el que sale en la ventana emergente con el código).", parent=dialog)
                return
            if not p_code or len(p_code) < 6:
                messagebox.showerror("Error", "Ingresa el código de 6 dígitos que muestra el dispositivo.", parent=dialog)
                return
            if c_port and (not c_port.isdigit() or not (1 <= int(c_port) <= 65535)):
                messagebox.showerror("Error", "El puerto de conexión debe ser un número válido (1 - 65535) o dejarse vacío para detectarlo automáticamente.", parent=dialog)
                return

            on_dialog_close()
            target_dev = dict(dev)
            target_dev["ip"] = target_ip
            self._apply_pair_and_connect(target_dev, p_port, p_code, c_port)

        btn_manual = ttk.Button(col_right, text="✔ Vincular y Conectar", command=on_confirm_pair)
        btn_manual.pack(anchor=tk.E, pady=(10, 0))

        # --- Lógica de la Sesión QR ---
        def start_qr_session():
            stop_qr_session()
            stop_qr_event.clear()

            srv_num = random.randint(100000, 999999)
            srv_name = f"studio-{srv_num}"
            pwd = f"{random.randint(100000, 999999)}"
            payload = f"WIFI:T:ADB;S:{srv_name};P:{pwd};;"

            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=4,
                border=2,
            )
            qr.add_data(payload)
            qr.make(fit=True)
            pil_img = qr.make_image(fill_color="black", back_color="white")
            tk_img = ImageTk.PhotoImage(pil_img)
            qr_lbl.config(image=tk_img)
            qr_lbl.image = tk_img
            qr_status_lbl.config(
                text="⏳ Esperando escaneo con la cámara del teléfono...",
                foreground="#0066cc"
            )

            threading.Thread(target=_qr_worker, args=(srv_name, pwd), daemon=True).start()

        def _qr_worker(srv_name, pwd):
            cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            target_ip = dev.get("ip", "") if dev else ""

            def _set_status(text, color):
                self.post_gui(lambda t=text, c=color: qr_status_lbl.config(text=t, foreground=c))

            def _close_zc(zc_inst):
                if zc_inst:
                    try:
                        zc_inst.close()
                    except Exception:
                        pass
                if current_zeroconf[0] is zc_inst:
                    current_zeroconf[0] = None

            # --- Descubrimiento mDNS con el propio ADB (mismo método que Android Studio) ---
            mdns_re = re.compile(r"^(\S+)\s+(_adb-tls-(?:pairing|connect)\._tcp)\.?\s+(\d{1,3}(?:\.\d{1,3}){3}):(\d+)")

            def _adb_mdns_services():
                """Devuelve lista de (instancia, tipo, ip, puerto) desde 'adb mdns services'."""
                found = []
                try:
                    res = subprocess.run(["adb", "mdns", "services"], capture_output=True, text=True,
                                         errors="replace", creationflags=cflags, timeout=4)
                    for line in (res.stdout or "").splitlines():
                        m = mdns_re.match(line.strip())
                        if m:
                            found.append((m.group(1), m.group(2), m.group(3), int(m.group(4))))
                except Exception:
                    pass
                return found

            def _run_pair(ip_addr, port):
                """Ejecuta adb pair. Solo se considera éxito si adb responde 'Successfully paired'."""
                try:
                    res = subprocess.run(["adb", "pair", f"{ip_addr}:{port}", pwd], capture_output=True,
                                         text=True, errors="replace", creationflags=cflags, timeout=12)
                    out = (res.stdout + res.stderr).strip()
                except subprocess.TimeoutExpired:
                    return False, "Tiempo de espera agotado en adb pair"
                except Exception as e:
                    return False, str(e)
                return ("successfully paired" in out.lower()), out

            # --- Escucha mDNS con zeroconf (respaldo del anterior) ---
            class PairingListener:
                def __init__(self):
                    self.ip = None
                    self.port = None

                def _resolve(self, zc, type_, name):
                    try:
                        # El teléfono publica el servicio de vinculación con el nombre exacto del QR
                        if srv_name.lower() not in name.lower():
                            return
                        info = zc.get_service_info(type_, name, timeout=2500)
                        if info:
                            addresses = [a for a in info.parsed_addresses() if "." in a]
                            if addresses and not self.ip:
                                self.ip = addresses[0]
                                self.port = info.port
                    except Exception:
                        pass

                def add_service(self, zc, type_, name):
                    threading.Thread(target=self._resolve, args=(zc, type_, name), daemon=True).start()

                def update_service(self, zc, type_, name):
                    threading.Thread(target=self._resolve, args=(zc, type_, name), daemon=True).start()

                def remove_service(self, zc, type_, name):
                    pass

            try:
                zc = Zeroconf(interfaces=[pc_ip]) if (pc_ip and is_valid_lan_ipv4(pc_ip)) else Zeroconf()
            except Exception:
                try:
                    zc = Zeroconf()
                except Exception:
                    zc = None

            current_zeroconf[0] = zc
            listener = PairingListener()
            if zc:
                try:
                    ServiceBrowser(zc, "_adb-tls-pairing._tcp.local.", listener)
                except Exception:
                    pass

            # Estado compartido de la vinculación (un solo 'adb pair' a la vez)
            pair_state = {"ip": None, "port": None, "paired": False, "last_error": ""}
            pair_lock = threading.Lock()

            def _try_pair(ip_addr, port):
                with pair_lock:
                    if pair_state["paired"] or stop_qr_event.is_set():
                        return pair_state["paired"]
                    _set_status(f"🔄 ¡Detectado ({ip_addr}:{port})! Vinculando...", "#b36b00")
                    ok, out = _run_pair(ip_addr, port)
                    if ok:
                        pair_state.update(ip=ip_addr, port=port, paired=True)
                    else:
                        pair_state["last_error"] = out
                        _set_status("⏳ Esperando escaneo con la cámara del teléfono...", "#0066cc")
                    return ok

            # Construir lista de IPs prioritarias y subred /24 completa para consulta unicast mDNS (RFC 6762 §6.7)
            subnet_prefix = ""
            if pc_ip and is_valid_lan_ipv4(pc_ip):
                subnet_prefix = ".".join(str(pc_ip).split(".")[:3])
            full_subnet_ips = [f"{subnet_prefix}.{i}" for i in range(1, 255) if f"{subnet_prefix}.{i}" != pc_ip] if subnet_prefix else []

            def _collect_priority_ips():
                ips_list = []
                def _add(x):
                    if x and x != pc_ip and is_valid_lan_ipv4(x) and x not in ips_list:
                        ips_list.append(x)
                _add(target_ip)
                for _rk, r_info in list(self.device_rows.items()):
                    r_dev = r_info.get("dev", {})
                    if not r_dev.get("is_router") and not r_dev.get("is_local_or_router"):
                        _add(r_dev.get("ip", ""))
                for a_ip in get_local_arp_cache().keys():
                    if not subnet_prefix or a_ip.startswith(subnet_prefix + "."):
                        _add(a_ip)
                for k_ip in load_known_devices().keys():
                    if not subnet_prefix or k_ip.startswith(subnet_prefix + "."):
                        _add(k_ip)
                return ips_list

            # Bucle principal: combina mDNS multicast (ADB + Zeroconf) + mDNS Unicast RFC 6762 §6.7
            # (El modo unicast funciona incluso cuando el router Wi-Fi bloquea multicast 224.0.0.251)
            start_t = time.time()
            pair_attempts = {}  # (ip, port) -> [count, last_ts]
            cycle = 0
            while not stop_qr_event.is_set() and not pair_state["paired"] and (time.time() - start_t) < 90:
                endpoints = []
                # 1. mDNS nativo de ADB (multicast)
                for inst, svc, s_ip, s_port in _adb_mdns_services():
                    if svc.startswith("_adb-tls-pairing") and srv_name.lower() in inst.lower():
                        endpoints.append((s_ip, s_port))
                # 2. Zeroconf multicast en la interfaz Wi-Fi
                if listener.ip and listener.port:
                    endpoints.append((listener.ip, listener.port))
                # 3. Consulta mDNS con QU=1 (RFC 6762 §5.4 + §6.7): consulta multicast/broadcast + IPs prioritarias
                #    y cada 4 ciclos toda la subred /24; incluye consulta SRV directa por srv_name (delayMs=0 en Android 14-16)
                if not endpoints:
                    u_ips = full_subnet_ips if (full_subnet_ips and cycle % 4 == 3) else (_collect_priority_ips() or full_subnet_ips)
                    u_svcs = query_unicast_mdns_adb(
                        u_ips,
                        service_type="_adb-tls-pairing._tcp.local",
                        local_ip=pc_ip,
                        wait_s=0.60 if len(u_ips) <= 30 else 0.70,
                        bursts=1,
                        stop_event=stop_qr_event,
                        use_multicast_broadcast=True,
                        instance_name=srv_name,
                    )
                    matched_eps = []
                    other_pairing_eps = []
                    for s_info in u_svcs:
                        cand_ep = (s_info["ip"], int(s_info["port"]))
                        if srv_name.lower() in s_info.get("instance", "").lower():
                            if cand_ep not in matched_eps:
                                matched_eps.append(cand_ep)
                        else:
                            if cand_ep not in other_pairing_eps:
                                other_pairing_eps.append(cand_ep)
                    endpoints.extend(matched_eps or other_pairing_eps)
                cycle += 1

                now_ts = time.time()
                for ep in endpoints:
                    if pair_state["paired"] or stop_qr_event.is_set():
                        break
                    cnt, last_att = pair_attempts.get(ep, (0, 0.0))
                    if cnt >= 3 or (now_ts - last_att) < 1.5:
                        continue
                    pair_attempts[ep] = (cnt + 1, now_ts)
                    _try_pair(ep[0], ep[1])

                if not pair_state["paired"]:
                    stop_qr_event.wait(0.35)

            if stop_qr_event.is_set():
                _close_zc(zc)
                return

            if not pair_state["paired"]:
                _close_zc(zc)
                if pair_state["last_error"]:
                    _set_status(f"❌ Error al vincular: {pair_state['last_error']}\nPulsa 'Generar nuevo QR' o usa la Opción B.", "#cc0000")
                else:
                    _set_status("⚠ Tiempo agotado. Pulsa 'Generar nuevo QR' o usa la Opción B de la derecha.", "#cc3300")
                return

            pair_ip = pair_state["ip"]
            pair_port = pair_state["port"]

            _set_status("✔ ¡Vinculado con éxito! Buscando puerto de conexión...", "#196f3d")

            class ConnectListener:
                def __init__(self, t_ip):
                    self.target_ip = t_ip
                    self.port = None

                def _resolve(self, zc_inst, type_, name):
                    try:
                        info = zc_inst.get_service_info(type_, name, timeout=2000)
                        if info:
                            addresses = info.parsed_addresses()
                            if self.target_ip in addresses:
                                self.port = info.port
                    except Exception:
                        pass

                def add_service(self, zc_inst, type_, name):
                    threading.Thread(target=self._resolve, args=(zc_inst, type_, name), daemon=True).start()

                def update_service(self, zc_inst, type_, name):
                    threading.Thread(target=self._resolve, args=(zc_inst, type_, name), daemon=True).start()

                def remove_service(self, zc_inst, type_, name):
                    pass

            c_listener = ConnectListener(pair_ip)
            if zc:
                try:
                    ServiceBrowser(zc, "_adb-tls-connect._tcp.local.", c_listener)
                except Exception:
                    pass

            def _adb_connect_verified_qr(port):
                ep = f"{pair_ip}:{port}"
                is_on, out, is_unauth = connect_adb_endpoint_verified(ep, cflags=cflags, attempts=2)
                if is_on:
                    return True, out
                if is_unauth:
                    return False, out
                return False, out

            # Buscar el puerto de conexión: Unicast mDNS directo al teléfono (instantáneo) + ADB mDNS + Zeroconf
            c_start = time.time()
            connect_port = None
            detected_model = ""
            conn_out = ""
            tried_conn_counts = {}
            while not stop_qr_event.is_set() and not connect_port and (time.time() - c_start) < 25:
                cands = []
                # 1. Consulta Unicast mDNS directa al teléfono vinculado (~200ms incluso si router bloquea multicast)
                for s_info in query_unicast_mdns_adb([pair_ip], "_adb-tls-connect._tcp.local",
                                                     local_ip=pc_ip, wait_s=0.75, bursts=2, stop_event=stop_qr_event):
                    if s_info["ip"] == pair_ip:
                        p_int = int(s_info["port"])
                        if p_int != pair_port and p_int not in cands:
                            cands.append(p_int)
                        if s_info.get("model") and not detected_model:
                            detected_model = s_info["model"]
                # 2. ADB mDNS y Zeroconf multicast
                for inst, svc, s_ip, s_port in _adb_mdns_services():
                    if svc.startswith("_adb-tls-connect") and s_ip == pair_ip and s_port not in cands:
                        cands.append(s_port)
                if c_listener.port and c_listener.port not in cands:
                    cands.append(c_listener.port)

                for cp in cands:
                    if stop_qr_event.is_set():
                        break
                    if tried_conn_counts.get(cp, 0) >= 3:
                        continue
                    tried_conn_counts[cp] = tried_conn_counts.get(cp, 0) + 1
                    _set_status(f"🚀 Conectando ADB a {pair_ip}:{cp}...", "#196f3d")
                    ok, conn_out = _adb_connect_verified_qr(cp)
                    if ok:
                        connect_port = cp
                        break
                if not connect_port:
                    stop_qr_event.wait(0.8)

            _close_zc(zc)

            if stop_qr_event.is_set():
                return

            # Últimos recursos: puerto guardado del equipo o puertos clásicos
            if not connect_port:
                fallback_ports = []
                if dev and dev.get("port"):
                    fallback_ports.append(str(dev["port"]))
                fallback_ports.extend(check_tcp_ports_fast(pair_ip, [5555, 7888], timeout=1.0))
                for fp in fallback_ports:
                    try:
                        fp_int = int(fp)
                    except Exception:
                        continue
                    if tried_conn_counts.get(fp_int, 0) >= 2:
                        continue
                    tried_conn_counts[fp_int] = tried_conn_counts.get(fp_int, 0) + 1
                    ok, conn_out = _adb_connect_verified_qr(fp_int)
                    if ok:
                        connect_port = fp_int
                        break

            if not connect_port:
                if conn_out:
                    _set_status(f"Vinculado con éxito. Error conectando: {conn_out}\nIngresa el puerto en 'Conectar por Puerto' para finalizar.", "#cc3300")
                else:
                    _set_status("✔ ¡Dispositivo vinculado con éxito!\nIngresa el puerto en 'Conectar por Puerto' para finalizar.", "#196f3d")
                return

            _set_status(f"🎉 ¡Dispositivo vinculado y conectado exitosamente en {pair_ip}:{connect_port}!", "#196f3d")

            # Obtener el modelo real del dispositivo recién conectado si aún no lo tenemos
            if not detected_model:
                try:
                    m_res = subprocess.run(["adb", "-s", f"{pair_ip}:{connect_port}", "shell", "getprop", "ro.product.model"],
                                           capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=3)
                    detected_model = (m_res.stdout or "").strip()
                except Exception:
                    pass

            existing_name = dev.get("name", "") if dev else ""
            if detected_model:
                dev_name = detected_model
            elif existing_name and "dispositivo" not in existing_name.lower():
                dev_name = existing_name
            else:
                dev_name = f"Android ({pair_ip})"

            pair_mac = get_local_arp_cache().get(pair_ip, "") or (dev.get("mac", "") if dev else "")
            save_known_device(
                pair_ip,
                name=dev_name,
                mac=pair_mac,
                is_static=True,
                last_port=str(connect_port),
                network=self.current_net_name
            )
            if dev and dev.get("key"):
                dev["name"] = dev_name
                dev["port"] = str(connect_port)
                dev["last_port"] = str(connect_port)
                dev["serial"] = f"{pair_ip}:{connect_port}"
                dev["is_port_open"] = True
                dev["is_adb_connected"] = True
                self.post_gui(self._update_row_state_by_key, dev.get("key", pair_ip), dev)

            def _auto_close():
                try:
                    dialog.destroy()
                except Exception:
                    pass
                self.trigger_scan()

            self.post_gui(lambda: self.root.after(1200, _auto_close))

        # Iniciar sesión QR automáticamente al abrir el diálogo
        start_qr_session()

        # ======================================================================
        # PESTAÑA 2: CONECTAR POR PUERTO (EQUIPOS PREVIAMENTE VINCULADOS)
        # ======================================================================
        tab_conn = ttk.Frame(notebook, padding=12)
        notebook.add(tab_conn, text="  ⚡ Conectar por Puerto (Ya Vinculado)  ")

        ttk.Label(
            tab_conn,
            text="Usa este modo si el equipo ya está vinculado a esta PC.\nIngresa el puerto que aparece en 'Dirección IP y puerto' del teléfono:",
            font=("Segoe UI", 9),
            foreground="#333333"
        ).pack(anchor=tk.W, pady=(0, 10))

        f_port = ttk.Frame(tab_conn)
        f_port.pack(fill=tk.X, pady=(0, 15))
        ttk.Label(f_port, text="Puerto ADB:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT)
        port_entry = ttk.Entry(f_port, width=12, font=("Consolas", 10))
        port_entry.pack(side=tk.LEFT, padx=8)
        if current_port:
            port_entry.insert(0, current_port)
            port_entry.select_range(0, tk.END)

        def on_confirm_connect(event=None):
            val = port_entry.get().strip()
            if not val or not val.isdigit() or not (1 <= int(val) <= 65535):
                messagebox.showerror("Puerto Inválido", "Ingresa un número de puerto válido (1 - 65535).", parent=dialog)
                return
            on_dialog_close()
            self._apply_custom_port(dev, val)

        btn_tab2 = ttk.Frame(tab_conn)
        btn_tab2.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Button(btn_tab2, text="Conectar", command=on_confirm_connect).pack(side=tk.LEFT)
        port_entry.bind("<Return>", on_confirm_connect)

        # Botón general para cerrar
        btn_bottom_bar = ttk.Frame(main_f)
        btn_bottom_bar.pack(fill=tk.X, side=tk.BOTTOM, pady=(6, 0))
        ttk.Button(btn_bottom_bar, text="Cerrar", command=on_dialog_close).pack(side=tk.RIGHT)

    def _apply_pair_and_connect(self, dev, pair_port, pair_code, connect_port):
        """Ejecuta adb pair y luego adb connect en un hilo en segundo plano."""
        ip = dev.get("ip", "")
        name = dev.get("name", "Dispositivo")
        self.set_status(f"Vinculando {name} ({ip}:{pair_port}) con código {pair_code}...")

        def _worker():
            cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            pair_target = f"{ip}:{pair_port}"
            res = subprocess.run(["adb", "pair", pair_target, pair_code], capture_output=True, text=True, creationflags=cflags, timeout=12)
            pair_out = (res.stdout + res.stderr).strip()

            if "successfully paired" in pair_out.lower() or res.returncode == 0:
                self.set_status(f"¡Vinculado con éxito a {name}! Buscando puerto de conexión...")
                final_c_port = str(connect_port or "").strip()
                if not final_c_port:
                    for _ in range(4):
                        u_svcs = query_unicast_mdns_adb([ip], "_adb-tls-connect._tcp.local",
                                                        local_ip=getattr(self, "local_ip", ""), wait_s=0.75, bursts=2)
                        for s_info in u_svcs:
                            if s_info["ip"] == ip and str(s_info["port"]) != str(pair_port):
                                final_c_port = str(s_info["port"])
                                if s_info.get("model") and (not dev.get("name") or "dispositivo" in dev.get("name", "").lower()):
                                    dev["name"] = s_info["model"]
                                break
                        if final_c_port:
                            break
                        time.sleep(0.5)
                if final_c_port:
                    self._apply_custom_port(dev, final_c_port)
                else:
                    self.set_status(f"¡Vinculado a {name}! Usa 'Conectar por Puerto' si no se detectó automáticamente.")
                    self.post_gui(self.trigger_scan)
            else:
                self.set_status(f"Fallo de vinculación: {pair_out}")
                self.post_gui(
                    messagebox.showerror,
                    "Fallo al Vincular",
                    f"No se pudo vincular con {name} ({pair_target}):\n\n{pair_out}\n\nVerifica que el código y el puerto de vinculación coincidan con la ventana emergente del teléfono."
                )

        threading.Thread(target=_worker, daemon=True).start()

    def _apply_custom_port(self, dev, port_str):
        """Aplica el puerto ingresado manualmente y lanza la conexión ADB."""
        ip = dev.get("ip", "")
        dev_key = dev.get("key", ip)
        old_port = dev.get("port")

        dev["port"] = port_str
        dev["last_port"] = port_str
        dev["is_port_open"] = True

        if ip and not dev.get("is_usb"):
            save_known_device(
                ip,
                name=dev.get("name"),
                mac=dev.get("mac", ""),
                is_static=dev.get("is_static", True),
                last_port=port_str,
                network=dev.get("network", self.current_net_name)
            )

        self._update_row_state_by_key(dev_key, dev)

        # Si ya estaba conectado a otro puerto anterior, desconectar el viejo
        if old_port and old_port != port_str and ip:
            cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            try:
                subprocess.run(["adb", "disconnect", f"{ip}:{old_port}"], capture_output=True, creationflags=cflags, timeout=2)
            except Exception:
                pass

        self.connect_single_device(dev)

    def toggle_port_5555(self, dev, open_it=True):
        """Abre o cierra el puerto 5555 en el dispositivo vía cable USB o comando ADB."""
        threading.Thread(target=self._toggle_port_worker, args=(dev, open_it), daemon=True).start()

    def _toggle_port_worker(self, dev, open_it=True):
        cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        name = dev.get("name", "Dispositivo")
        ip = dev.get("ip", "")
        dev_key = dev.get("key", ip)

        if open_it:
            self.set_status(f"Abriendo puerto 5555 en {name} vía USB...")
            target_serial = None
            target_status = "device"
            if dev.get("is_usb"):
                target_serial = dev.get("serial")
                target_status = "offline" if dev.get("is_offline") else ("unauthorized" if dev.get("is_unauthorized") else "device")
            else:
                try:
                    res = subprocess.run(["adb", "devices", "-l"], capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=3)
                    usb_targets = []
                    for line in res.stdout.splitlines():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            s = parts[0]
                            st = parts[1]
                            if ":" not in s and "_adb-tls" not in s and st in ("device", "offline", "unauthorized"):
                                model = ""
                                for p in parts[2:]:
                                    if p.startswith("model:"):
                                        model = p.split(":", 1)[1]
                                if not model and s == "1340003718":
                                    model = "E700"
                                elif not model and s.startswith("1070"):
                                    model = "E800"
                                usb_targets.append((s, model, st))

                    # 1. Coincidencia específica por serial o IP conocida
                    row_ip = dev.get("ip", "")
                    name_lower = name.lower()
                    for s, m, st in usb_targets:
                        m_lower = m.lower() if m else ""
                        if (
                            (s == "1340003718" and ("e700" in name_lower or "205" in row_ip)) or
                            (s.startswith("1070") and ("e800" in name_lower or "204" in row_ip)) or
                            ("e700" in m_lower and "e700" in name_lower) or
                            ("e800" in m_lower and "e800" in name_lower) or
                            (m_lower and (m_lower in name_lower or name_lower in m_lower))
                        ):
                            target_serial = s
                            target_status = st
                            break

                    # 2. Si no hubo coincidencia directa pero hay USBs
                    if not target_serial and usb_targets:
                        target_serial = usb_targets[0][0]
                        target_status = usb_targets[0][2]
                except Exception:
                    pass

            if not target_serial:
                self.set_status(f"No se detectó cable USB para {name}.")
                self.post_gui(
                    messagebox.showinfo,
                    "Conexión por Cable Requerida",
                    f"Para abrir el puerto 5555 en {name}:\n\n"
                    f"1. Conecta el cable USB del {name} al PC.\n"
                    f"2. Toca nuevamente el botón 'Abrir puerto 5555'.\n\n"
                    f"El bot abrirá el puerto inmediatamente vía cable USB y se conectará automáticamente por Wi-Fi."
                )
                return

            if target_status == "unauthorized":
                self.set_status(f"El dispositivo USB {target_serial} requiere autorización en pantalla.")
                self.post_gui(
                    messagebox.showwarning,
                    "Autorización Requerida en Pantalla",
                    f"El terminal {name} (USB {target_serial}) está conectado, pero esperando confirmación:\n\n"
                    f"1. Enciende y desbloquea la pantalla de {name}.\n"
                    f"2. En el mensaje '¿Permitir depuración por USB?', marca 'Permitir siempre desde esta computadora'.\n"
                    f"3. Presiona 'Aceptar' y vuelve a tocar 'Abrir puerto 5555'."
                )
                return

            self.set_status(f"Activando TCP/IP 5555 en {name} (USB {target_serial})...")
            net_det = {"wlan_ip": "", "all_ips": [], "model": ""}
            dev_mac = ""
            if target_status == "device":
                net_det = get_usb_device_net_details(target_serial, cflags=cflags)
                _, dev_mac = get_usb_device_ssid_and_mac(target_serial, cflags=cflags)

            wlan_ip = net_det.get("wlan_ip", "")
            m_chk = net_det.get("model", "")
            real_model = (f"PAX {m_chk}" if (m_chk.startswith("E") or m_chk.startswith("A")) else m_chk) if m_chk else ""

            tcpip_ok = prepare_usb_device_for_wifi_adb(target_serial, cflags=cflags, port=5555, force_tcpip=True)

            if not tcpip_ok:
                self.set_status(f"Dispositivo {name} detectado por USB pero no responde.")
                self.post_gui(
                    messagebox.showwarning,
                    "Terminal USB no Responde (Depuración Desactivada)",
                    f"Se detectó el cable USB conectado a {name} (Serial: {target_serial}), pero el terminal no responde a los comandos ADB.\n\n"
                    f"Para habilitarlo en el terminal:\n"
                    f"1. Enciende y desbloquea la pantalla del equipo.\n"
                    f"2. Ve a Ajustes -> Opciones de desarrollador.\n"
                    f"3. Apaga y vuelve a encender 'Depuración por USB'.\n"
                    f"4. Si aparece '¿Permitir depuración por USB?', marca 'Permitir siempre' y toca ACEPTAR.\n"
                    f"5. Si sigue sin responder, desconecta el cable USB y vuelve a conectarlo firmemente."
                )
                return

            try:
                target_name = real_model if real_model else dev.get("name", name)
                fallback_ip = ip if is_valid_lan_ipv4(ip) else ""
                target_ip = wlan_ip or fallback_ip
                pc_ip_now = get_wifi_adapter_ip(force=True)
                wake_device_to_pc_route(target_serial, pc_ip_now, cflags=cflags)

                if dev.get("is_usb"):
                    dev["wlan_ip"] = target_ip
                    dev["ip"] = f"USB (IP: {target_ip})" if target_ip else f"USB ({target_serial})"
                else:
                    dev["ip"] = target_ip or ip
                    dev["port"] = "5555"
                dev["name"] = target_name
                dev["is_port_open"] = True

                is_wifi_adb_up = False
                if target_ip:
                    save_known_device(target_ip, name=target_name, mac=dev_mac, is_static=True, last_port="5555", network=self.current_net_name)
                    ok_conn, _, _ = connect_adb_endpoint_verified(f"{target_ip}:5555", cflags=cflags, attempts=2)
                    if ok_conn:
                        is_wifi_adb_up = True
                        ensure_device_internet_stability(f"{target_ip}:5555")

                self.set_status(f"¡Puerto 5555 abierto exitosamente en {target_name} ({target_ip or target_serial})!")
                self.post_gui(self._update_row_state_by_key, dev_key, dev)

                if target_ip and target_ip in self.device_rows:
                    wifi_row_dev = self.device_rows[target_ip]["dev"]
                    wifi_row_dev["is_port_open"] = True
                    wifi_row_dev["port"] = "5555"
                    wifi_row_dev["name"] = target_name
                    if is_wifi_adb_up:
                        wifi_row_dev["is_adb_connected"] = True
                    self.post_gui(self._update_row_state_by_key, target_ip, wifi_row_dev)

                self.trigger_scan()

                msg_status = (
                    f"El bot abrió el puerto y lo conectó por Wi-Fi ({target_ip}:5555).\nYa puedes desconectar el cable USB."
                    if is_wifi_adb_up else
                    f"El puerto 5555 quedó abierto en {target_name} ({target_ip or 'sin Wi-Fi activo'})."
                )
                self.post_gui(messagebox.showinfo, "Puerto 5555 Abierto", f"¡Puerto 5555 abierto en {target_name}!\n\n{msg_status}")
            except Exception as e:
                self.set_status(f"Error abriendo puerto 5555: {e}")
        else:
            self.set_status(f"Cerrando puerto 5555 en {name}...")
            try:
                # 1. Pasar a modo usb y desconectar Wi-Fi
                if ip:
                    subprocess.run(["adb", "-s", f"{ip}:5555", "usb"], capture_output=True, creationflags=cflags, timeout=3)
                    subprocess.run(["adb", "disconnect", f"{ip}:5555"], capture_output=True, creationflags=cflags, timeout=2)
                    subprocess.run(["adb", "disconnect", ip], capture_output=True, creationflags=cflags, timeout=2)

                # Si hay cable USB conectado para este equipo, también pasar el USB a modo usb
                target_serial = None
                if dev.get("is_usb"):
                    target_serial = dev.get("serial")
                else:
                    try:
                        res = subprocess.run(["adb", "devices", "-l"], capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=3)
                        for line in res.stdout.splitlines():
                            parts = line.strip().split()
                            if len(parts) >= 2 and parts[1] == "device":
                                s = parts[0]
                                if ":" not in s and "_adb-tls" not in s:
                                    model = ""
                                    for p in parts[2:]:
                                        if p.startswith("model:"):
                                            model = p.split(":", 1)[1]
                                    if model and model.lower() in name.lower():
                                        target_serial = s
                                        break
                    except Exception:
                        pass
                if target_serial:
                    subprocess.run(["adb", "-s", target_serial, "usb"], capture_output=True, creationflags=cflags, timeout=3)

                time.sleep(0.5)
                open_check = check_tcp_ports_fast(ip, [5555]) if ip else []
                dev["is_adb_connected"] = False
                dev["is_port_open"] = bool(open_check)
                self.set_status(f"Puerto 5555 cerrado en {name}.")
                self.post_gui(self._update_row_state_by_key, dev_key, dev)
                self.trigger_scan()
            except Exception as e:
                self.set_status(f"Error cerrando puerto 5555: {e}")

    def _auto_open_usb_port(self, serial, model_name):
        """Control manual mediante botón 'Abrir puerto 5555'."""
        return
        cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        try:
            subprocess.run(["adb", "-s", serial, "tcpip", "5555"], capture_output=True, creationflags=cflags, timeout=5)
            for prop, val in [
                ("persist.adb.tcp.port", "5555"),
                ("persist.service.adb.enable", "5555"),
                ("persist.sys.enable.tcpip", "true")
            ]:
                subprocess.run(["adb", "-s", serial, "shell", "setprop", prop, val], capture_output=True, creationflags=cflags, timeout=1.5)

            # Extraer IP de wlan0 y registrarla
            wlan_ip = ""
            try:
                ip_out = subprocess.run(["adb", "-s", serial, "shell", "ip", "-f", "inet", "addr", "show", "wlan0"], capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=2).stdout
                m_ip = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", ip_out)
                if m_ip:
                    wlan_ip = m_ip.group(1)
                    save_known_device(wlan_ip, name=model_name, is_static=True, last_port="5555", network="Sitio de Trabajo")
            except Exception:
                pass

            msg_extra = f" (IP Wi-Fi: {wlan_ip})" if wlan_ip else ""
            self.set_status(f"¡Cable USB detectado! Puerto 5555 abierto automáticamente en {model_name}{msg_extra}.")
            time.sleep(1.0)
            self.trigger_scan()
        except Exception:
            pass

    def _get_row_dev(self, dev_key, fallback_dev=None):
        row_info = self.device_rows.get(dev_key)
        if row_info and row_info.get("dev"):
            return row_info["dev"]
        return fallback_dev

    # ==========================================================================
    # INSTALADOR MÚLTIPLE DE APK (ventana "Instalar APK")
    # ==========================================================================

    @staticmethod
    def _apk_dev_state(dev):
        """Devuelve 'connected', 'available' o None según el estado mostrado en la lista principal."""
        if dev.get("is_local_or_router"):
            return None
        if dev.get("is_usb"):
            if dev.get("is_adb_connected") and not dev.get("is_offline") and not dev.get("is_unauthorized"):
                return "connected"
            return None
        if dev.get("is_adb_connected"):
            return "connected"
        if dev.get("is_port_open") and dev.get("is_on_current_net", True):
            return "available"
        return None

    @staticmethod
    def _read_apk_package_name(apk_path):
        """Extrae el nombre de paquete (package) leyendo AndroidManifest.xml binario dentro del APK (sin aapt)."""
        import zipfile
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                data = zf.read("AndroidManifest.xml")
            if len(data) < 16:
                return ""
            pos = 8
            strings = []
            while pos + 8 <= len(data):
                ctype, _hsz, csz = struct.unpack_from("<HHI", data, pos)
                if csz <= 0 or pos + csz > len(data):
                    break
                if ctype == 0x0001:  # RES_STRING_POOL_TYPE
                    scnt, _stcnt, flags, soff, _ = struct.unpack_from("<IIIII", data, pos + 8)
                    is_utf8 = bool(flags & (1 << 8))
                    offsets = struct.unpack_from(f"<{scnt}I", data, pos + 28)
                    base = pos + soff
                    for o in offsets:
                        p = base + o
                        if p >= len(data):
                            strings.append("")
                            continue
                        if is_utf8:
                            v = data[p]
                            p += 2 if (v & 0x80) else 1
                            b = data[p]
                            if b & 0x80:
                                blen = ((b & 0x7F) << 8) | data[p + 1]
                                p += 2
                            else:
                                blen = b
                                p += 1
                            strings.append(data[p:p + blen].decode("utf-8", errors="replace"))
                        else:
                            v = struct.unpack_from("<H", data, p)[0]
                            if v & 0x8000:
                                v = ((v & 0x7FFF) << 16) | struct.unpack_from("<H", data, p + 2)[0]
                                p += 4
                            else:
                                p += 2
                            strings.append(data[p:p + v * 2].decode("utf-16le", errors="replace"))
                elif ctype == 0x0102:  # RES_XML_START_ELEMENT_TYPE
                    name_idx = struct.unpack_from("<I", data, pos + 20)[0]
                    attr_start, attr_sz, attr_cnt = struct.unpack_from("<HHH", data, pos + 24)
                    if 0 <= name_idx < len(strings) and strings[name_idx] == "manifest":
                        apos = pos + 16 + attr_start
                        for _ in range(attr_cnt):
                            if apos + 20 > pos + csz:
                                break
                            _ns, aname_idx, rval_idx, _tsz, _r0, _dtype, _dval = struct.unpack_from("<IIIHBBI", data, apos)
                            aname = strings[aname_idx] if 0 <= aname_idx < len(strings) else ""
                            if aname == "package" and 0 <= rval_idx < len(strings):
                                return strings[rval_idx].strip()
                            apos += attr_sz
                        break
                pos += csz
        except Exception:
            pass
        return ""

    def open_apk_installer(self):
        win = getattr(self, "_apk_win", None)
        try:
            if win is not None and win.winfo_exists():
                win.deiconify()
                win.lift()
                win.focus_force()
                return
        except Exception:
            pass

        win = tk.Toplevel(self.root)
        self._apk_win = win
        win.title("📦 Instalar APK en múltiples dispositivos")
        win.geometry("1040x680")
        win.minsize(820, 560)
        # Ventana independiente con botones nativos de minimizar, maximizar y cerrar
        win.resizable(True, True)
        try:
            win.attributes("-toolwindow", False)
        except Exception:
            pass

        apk_paths = []          # rutas de APK montadas
        checked = set()         # claves de dispositivos marcados
        row_status = {}         # clave -> texto de resultado de instalación
        shown = {"keys": [], "sig": None}
        state = {"installing": False, "after": None}
        auto_replace_var = tk.BooleanVar(value=True)

        main = ttk.Frame(win, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        # ---- Sección APKs ----
        apk_box = ttk.LabelFrame(main, text=" 1. APK(s) a instalar ", padding=8)
        apk_box.pack(fill=tk.X)

        apk_list_f = ttk.Frame(apk_box)
        apk_list_f.pack(fill=tk.X)
        apk_tree = ttk.Treeview(apk_list_f, columns=("nombre", "tam", "ruta"), show="headings", height=4, selectmode="extended")
        apk_tree.heading("nombre", text="Archivo")
        apk_tree.heading("tam", text="Tamaño")
        apk_tree.heading("ruta", text="Ruta")
        apk_tree.column("nombre", width=240, anchor=tk.W)
        apk_tree.column("tam", width=80, anchor=tk.E)
        apk_tree.column("ruta", width=520, anchor=tk.W)
        apk_sb = ttk.Scrollbar(apk_list_f, orient=tk.VERTICAL, command=apk_tree.yview)
        apk_tree.configure(yscrollcommand=apk_sb.set)
        apk_tree.pack(side=tk.LEFT, fill=tk.X, expand=True)
        apk_sb.pack(side=tk.LEFT, fill=tk.Y)

        def _fmt_size(n):
            if n < 1024 * 1024:
                return f"{n / 1024.0:.0f} KB"
            return f"{n / (1024.0 * 1024.0):.1f} MB"

        def add_apks():
            files = filedialog.askopenfilenames(
                parent=win, title="Seleccionar APK(s)",
                filetypes=[("Paquetes Android", "*.apk"), ("Todos los archivos", "*.*")]
            )
            for f in files:
                p = os.path.normpath(f)
                if p in apk_paths or not os.path.isfile(p):
                    continue
                apk_paths.append(p)
                try:
                    sz = _fmt_size(os.path.getsize(p))
                except Exception:
                    sz = "-"
                apk_tree.insert("", tk.END, iid=p, values=(os.path.basename(p), sz, p))
            _refresh_install_btn()

        def remove_apks():
            for iid in apk_tree.selection():
                if iid in apk_paths:
                    apk_paths.remove(iid)
                apk_tree.delete(iid)
            _refresh_install_btn()

        def clear_apks():
            for iid in list(apk_paths):
                try:
                    apk_tree.delete(iid)
                except Exception:
                    pass
            apk_paths.clear()
            _refresh_install_btn()

        apk_btns = ttk.Frame(apk_box)
        apk_btns.pack(fill=tk.X, pady=(6, 0))
        ttk.Button(apk_btns, text="➕ Adjuntar APK(s)...", command=add_apks).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(apk_btns, text="➖ Quitar seleccionado(s)", command=remove_apks).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(apk_btns, text="🗑 Limpiar lista", command=clear_apks).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Checkbutton(
            apk_btns,
            text="Reemplazar automáticamente si hay conflicto de firma o versión anterior",
            variable=auto_replace_var
        ).pack(side=tk.RIGHT)

        # ---- Sección dispositivos ----
        dev_box = ttk.LabelFrame(main, text=" 2. Dispositivos (se actualiza en tiempo real) ", padding=8)
        dev_box.pack(fill=tk.BOTH, expand=True, pady=(8, 0))

        dev_f = ttk.Frame(dev_box)
        dev_f.pack(fill=tk.BOTH, expand=True)
        cols = ("sel", "nombre", "ip", "estado", "resultado")
        dev_tree = ttk.Treeview(dev_f, columns=cols, show="headings", selectmode="none")
        dev_tree.heading("sel", text="Sel.")
        dev_tree.heading("nombre", text="Dispositivo")
        dev_tree.heading("ip", text="Dirección IP")
        dev_tree.heading("estado", text="Estado / Conexión")
        dev_tree.heading("resultado", text="Resultado de instalación")
        dev_tree.column("sel", width=44, minwidth=44, anchor=tk.CENTER, stretch=False)
        dev_tree.column("nombre", width=190, minwidth=130, anchor=tk.W, stretch=False)
        dev_tree.column("ip", width=155, minwidth=120, anchor=tk.W, stretch=False)
        dev_tree.column("estado", width=165, minwidth=135, anchor=tk.W, stretch=False)
        dev_tree.column("resultado", width=430, minwidth=260, anchor=tk.W, stretch=True)
        dev_tree.tag_configure("connected", foreground="#1e7a34")
        dev_tree.tag_configure("available", foreground="#0066cc")
        dev_tree.tag_configure("ok", foreground="#1e7a34")
        dev_tree.tag_configure("err", foreground="#cc2222")
        dev_sb = ttk.Scrollbar(dev_f, orient=tk.VERTICAL, command=dev_tree.yview)
        dev_hsb = ttk.Scrollbar(dev_f, orient=tk.HORIZONTAL, command=dev_tree.xview)
        dev_tree.configure(yscrollcommand=dev_sb.set, xscrollcommand=dev_hsb.set)
        dev_tree.grid(row=0, column=0, sticky="nsew")
        dev_sb.grid(row=0, column=1, sticky="ns")
        dev_hsb.grid(row=1, column=0, sticky="ew")
        dev_f.grid_rowconfigure(0, weight=1)
        dev_f.grid_columnconfigure(0, weight=1)

        lbl_info = ttk.Label(dev_box, text="", font=("Segoe UI", 9), foreground="#555555")
        lbl_info.pack(anchor=tk.W, pady=(6, 0))

        def toggle_row(event):
            if state["installing"]:
                return
            if dev_tree.identify_region(event.x, event.y) != "cell":
                return
            iid = dev_tree.identify_row(event.y)
            if not iid or iid not in shown["keys"]:
                return
            if iid in checked:
                checked.discard(iid)
            else:
                checked.add(iid)
            _redraw_row(iid)
            _refresh_install_btn()

        dev_tree.bind("<Button-1>", toggle_row)

        def _current_devices():
            out = []
            for k, info in list(self.device_rows.items()):
                d = info.get("dev")
                if not d:
                    continue
                st = self._apk_dev_state(d)
                if st:
                    out.append((k, d, st))
            out.sort(key=lambda t: get_device_sort_key(t[1]))
            return out

        def _row_values(k, d, st):
            if st == "connected":
                if d.get("is_usb"):
                    est = "● Conectado (USB)"
                else:
                    est = f"● Conectado ADB ({d.get('port', '5555')})"
            else:
                est = "● ADB disponible"
            ip = d.get("ip", "")
            return ("☑" if k in checked else "☐", d.get("name", "Dispositivo"), ip, est, row_status.get(k, ""))

        def _row_tags(k, d, st):
            res = row_status.get(k, "")
            if res.startswith("✔"):
                return (st, "ok")
            if res.startswith("✖"):
                return (st, "err")
            return (st,)

        def _redraw_row(k):
            info = self.device_rows.get(k)
            if not info or not info.get("dev"):
                return
            d = info["dev"]
            st = self._apk_dev_state(d)
            if not st:
                return
            try:
                dev_tree.item(k, values=_row_values(k, d, st), tags=_row_tags(k, d, st))
            except Exception:
                pass

        def refresh_devices():
            """Sincroniza la lista con el estado actual de la ventana principal."""
            devs = _current_devices()
            keys = [k for k, _, _ in devs]
            sig = tuple((k, st, d.get("name"), d.get("port"), d.get("ip")) for k, d, st in devs)
            # descartar marcados que ya no estén listados
            for k in list(checked):
                if k not in keys:
                    checked.discard(k)
            if sig != shown["sig"] or keys != shown["keys"]:
                existing = set(dev_tree.get_children())
                for k in existing - set(keys):
                    dev_tree.delete(k)
                for idx, (k, d, st) in enumerate(devs):
                    vals = _row_values(k, d, st)
                    if k in existing:
                        dev_tree.item(k, values=vals, tags=_row_tags(k, d, st))
                    else:
                        dev_tree.insert("", tk.END, iid=k, values=vals, tags=_row_tags(k, d, st))
                    dev_tree.move(k, "", idx)
                shown["keys"] = keys
                shown["sig"] = sig
            n_conn = sum(1 for _, _, st in devs if st == "connected")
            n_av = sum(1 for _, _, st in devs if st == "available")
            lbl_info.config(text=f"{n_conn} conectado(s)  |  {n_av} con ADB disponible  |  {len(checked)} seleccionado(s)")
            _refresh_install_btn()

        def _poll():
            try:
                if not win.winfo_exists():
                    return
            except Exception:
                return
            try:
                refresh_devices()
            except Exception:
                pass
            state["after"] = win.after(1200, _poll)

        def select_all_connected():
            if state["installing"]:
                return
            for k, d, st in _current_devices():
                if st == "connected":
                    checked.add(k)
            refresh_devices()
            for k in shown["keys"]:
                _redraw_row(k)

        def select_none():
            if state["installing"]:
                return
            checked.clear()
            for k in shown["keys"]:
                _redraw_row(k)
            refresh_devices()

        sel_bar = ttk.Frame(dev_box)
        sel_bar.pack(fill=tk.X, pady=(6, 0))
        ttk.Button(sel_bar, text="Seleccionar conectados", command=select_all_connected).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(sel_bar, text="Deseleccionar todos", command=select_none).pack(side=tk.LEFT)

        # ---- Barra inferior ----
        bottom = ttk.Frame(main)
        bottom.pack(fill=tk.X, pady=(10, 0))
        lbl_prog = ttk.Label(bottom, text="", font=("Segoe UI", 9, "bold"))
        lbl_prog.pack(side=tk.LEFT)
        btn_close = ttk.Button(bottom, text="Cerrar", command=lambda: _on_close())
        btn_close.pack(side=tk.RIGHT, padx=(6, 0))
        btn_install = ttk.Button(bottom, text="⬇ Instalar", command=lambda: start_install())
        btn_install.pack(side=tk.RIGHT)

        def _refresh_install_btn():
            ok = bool(apk_paths) and bool(checked) and not state["installing"]
            try:
                btn_install.config(state=tk.NORMAL if ok else tk.DISABLED)
            except Exception:
                pass

        def _set_result(k, text):
            row_status[k] = text
            def _apply():
                try:
                    if win.winfo_exists():
                        _redraw_row(k)
                except Exception:
                    pass
            self.post_gui(_apply)

        cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

        def _run_install_cmd(target, args, on_wait=None, timeout=900):
            """Ejecuta 'adb install' y, si queda esperando, detecta avisos en pantalla del dispositivo
            (Play Protect / instalador) para informarlo en la lista en lugar de parecer congelado."""
            proc = subprocess.Popen(["adb", "-s", str(target)] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, errors="replace", creationflags=cflags)
            t0 = time.time()
            last_probe = 0.0
            prompted = False
            while True:
                try:
                    out, err = proc.communicate(timeout=1.0)
                    return (out or "") + "\n" + (err or "")
                except subprocess.TimeoutExpired:
                    pass
                now = time.time()
                if now - t0 > timeout:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    raise subprocess.TimeoutExpired(args, timeout)
                if on_wait and now - t0 > 8 and now - last_probe > 4:
                    last_probe = now
                    try:
                        f = subprocess.run(["adb", "-s", str(target), "shell", "dumpsys window | grep mCurrentFocus"],
                                           capture_output=True, text=True, errors="replace",
                                           creationflags=cflags, timeout=6).stdout.lower()
                    except Exception:
                        f = ""
                    waiting = any(w in f for w in ("protectdialogs", "packageinstaller", "installappprogress", "installstart"))
                    if waiting and not prompted:
                        prompted = True
                        on_wait("⏳ Esperando que aceptes el aviso en la pantalla del dispositivo (Play Protect/instalador)...")
                    elif not waiting and prompted:
                        prompted = False
                        on_wait(None)

        def _uninstall_pkg(target, pkg):
            """Desinstala un paquete existente antes de reinstalar cuando la firma o versión entra en conflicto."""
            if not pkg:
                return False
            try:
                r = subprocess.run(["adb", "-s", str(target), "uninstall", pkg], capture_output=True, text=True,
                                   errors="replace", creationflags=cflags, timeout=45)
                out = ((r.stdout or "") + " " + (r.stderr or "")).lower()
                if "success" in out:
                    return True
            except Exception:
                pass
            try:
                r2 = subprocess.run(["adb", "-s", str(target), "shell", "pm", "uninstall", "--user", "0", pkg],
                                    capture_output=True, text=True, errors="replace", creationflags=cflags, timeout=30)
                if "success" in ((r2.stdout or "") + " " + (r2.stderr or "")).lower():
                    return True
            except Exception:
                pass
            return False

        def _extract_pkg_from_error(err_text, apk):
            # Ej: "Package com.kubilabs.ontheflypos signatures do not match..." / "Existing package com.foo ..."
            m = re.search(r"(?:Package|package)\s+([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+)", err_text or "")
            if m:
                return m.group(1).strip()
            return self._read_apk_package_name(apk)

        def _install_one_apk(target, apk, on_wait=None, allow_replace=True):
            """Instala o actualiza un APK. Si Android rechaza por firma distinta o versión anterior
            y allow_replace está activo, desinstala la versión en conflicto y la instala limpia.
            Devuelve (ok, mensaje)."""
            def _try_attempts(extra_flags=()):
                flag_sets = [
                    ["install", "-r", "-t", "-g", *extra_flags, apk],
                    ["install", "-r", "-t", *extra_flags, apk],
                    ["install", "-r", *extra_flags, apk],
                ]
                last_out = ""
                for idx_a, args in enumerate(flag_sets):
                    try:
                        out = _run_install_cmd(target, args, on_wait=on_wait).strip()
                    except subprocess.TimeoutExpired:
                        return False, "__TIMEOUT__"
                    except Exception as ex:
                        return False, str(ex)
                    low = out.lower()
                    if "success" in low and "failure" not in low:
                        return True, "OK"
                    last_out = out
                    if idx_a < len(flag_sets) - 1 and (
                        "unknown option" in low or "invalid option" in low
                        or "usage: pm install" in low or "usage: adb install" in low
                        or ("-g" in low and "not" in low) or ("-t" in low and "not" in low)
                    ):
                        continue
                    break
                return False, last_out

            ok, last = _try_attempts()
            if ok:
                return True, "OK"
            if last == "__TIMEOUT__":
                return False, "Tiempo de espera agotado (¿aviso sin aceptar en el dispositivo?)"

            low_last = (last or "").lower()
            # 1. Si es downgrade de versión, intentar primero con -d (conserva datos si es debuggable)
            if "install_failed_version_downgrade" in low_last:
                ok_d, last_d = _try_attempts(extra_flags=("-d",))
                if ok_d:
                    return True, "OK (downgrade)"
                if last_d != "__TIMEOUT__":
                    last = last_d
                    low_last = (last or "").lower()

            # 2. Si persiste conflicto de firma (INSTALL_FAILED_UPDATE_INCOMPATIBLE) o downgrade bloqueado:
            #    desinstalar el paquete en conflicto y volver a instalar limpiamente.
            is_sig_conflict = "install_failed_update_incompatible" in low_last or "signatures do not match" in low_last
            is_downgrade_conflict = "install_failed_version_downgrade" in low_last
            if allow_replace and (is_sig_conflict or is_downgrade_conflict):
                pkg = _extract_pkg_from_error(last, apk)
                if pkg:
                    reason = "firma distinta" if is_sig_conflict else "versión anterior"
                    if on_wait:
                        on_wait(f"⏳ Conflicto ({reason}): reemplazando {pkg}...")
                    if _uninstall_pkg(target, pkg):
                        if on_wait:
                            on_wait(f"⏳ Reinstalando {os.path.basename(apk)}...")
                        ok_r, last_r = _try_attempts()
                        if ok_r:
                            return True, f"reemplazada por {reason}"
                        if last_r == "__TIMEOUT__":
                            return False, "Tiempo de espera agotado al reinstalar"
                        last = last_r

            m = re.search(r"(INSTALL_[A-Z0-9_]+)", last or "")
            if m:
                code = m.group(1)
                hints = {
                    "INSTALL_FAILED_VERSION_DOWNGRADE": "versión instalada es más nueva",
                    "INSTALL_FAILED_UPDATE_INCOMPATIBLE": "firma distinta a la instalada",
                    "INSTALL_FAILED_INSUFFICIENT_STORAGE": "sin espacio",
                    "INSTALL_FAILED_OLDER_SDK": "Android demasiado antiguo",
                    "INSTALL_FAILED_USER_RESTRICTED": "instalación bloqueada por el dispositivo",
                    "INSTALL_FAILED_TEST_ONLY": "APK solo para pruebas",
                    "INSTALL_PARSE_FAILED_NO_CERTIFICATES": "APK sin firmar",
                }
                for hk, hv in hints.items():
                    if hk in code:
                        return False, f"{code} ({hv})"
                return False, code
            return False, (last.splitlines()[-1] if last else "Error desconocido")[:160]

        def _install_on_device(k, d, st, apks, allow_replace=True):
            name = d.get("name", "Dispositivo")
            try:
                if st == "available" or not d.get("is_adb_connected"):
                    _set_result(k, "⏳ Conectando ADB...")
                    ok, detail, model = connect_ip_automatically(d.get("ip", ""), known_port=d.get("port", ""))
                    if not ok:
                        _set_result(k, f"✖ No se pudo conectar: {str(detail).splitlines()[0][:100]}")
                        return False
                    d["is_adb_connected"] = True
                    d["serial"] = detail
                    self.post_gui(self._update_row_state_by_key, k, d)
                    target = resolve_active_adb_target(detail, dev=d) or detail
                else:
                    base = d.get("serial") or d.get("ip", "")
                    target = resolve_active_adb_target(base, dev=d) or base
                done = 0
                replaced_any = False
                for apk in apks:
                    base_msg = f"⏳ Instalando {os.path.basename(apk)} ({done + 1}/{len(apks)})..."
                    _set_result(k, base_msg)

                    def _on_wait(msg, _k=k, _b=base_msg):
                        _set_result(_k, msg if msg else _b)

                    ok, msg = _install_one_apk(target, apk, on_wait=_on_wait, allow_replace=allow_replace)
                    if not ok and ("not found" in msg.lower() or "offline" in msg.lower()) and not d.get("is_usb") and d.get("ip"):
                        ok2, detail2, _m = connect_ip_automatically(d.get("ip", ""), known_port=d.get("port", ""))
                        if ok2:
                            target = resolve_active_adb_target(detail2, dev=d) or detail2
                            ok, msg = _install_one_apk(target, apk, on_wait=_on_wait, allow_replace=allow_replace)
                    if not ok:
                        _set_result(k, f"✖ {os.path.basename(apk)}: {msg}")
                        return False
                    if "reemplazada" in str(msg).lower():
                        replaced_any = True
                    done += 1
                suffix = " (reemplazada por firma/versión)" if replaced_any else ""
                _set_result(k, f"✔ {done} APK(s) instalada(s)/actualizada(s){suffix}")
                return True
            except Exception as ex:
                _set_result(k, f"✖ Error: {str(ex)[:120]}")
                return False

        def start_install():
            if state["installing"] or not apk_paths or not checked:
                return
            targets = []
            for k, d, st in _current_devices():
                if k in checked:
                    targets.append((k, d, st))
            if not targets:
                messagebox.showinfo("Instalar APK", "Selecciona al menos un dispositivo conectado.", parent=win)
                return
            # Un mismo equipo físico puede aparecer por USB y por Wi-Fi: se instala una sola vez (vía USB)
            usb_wlan = {d.get("wlan_ip"): k for k, d, st in targets if d.get("is_usb") and d.get("wlan_ip")}
            mirror = {}
            unique_targets = []
            for k, d, st in targets:
                if not d.get("is_usb") and d.get("ip") in usb_wlan:
                    mirror[k] = usb_wlan[d.get("ip")]
                else:
                    unique_targets.append((k, d, st))
            targets_all = targets
            targets = unique_targets
            apks = list(apk_paths)
            allow_replace = bool(auto_replace_var.get())
            state["installing"] = True
            btn_install.config(state=tk.DISABLED)
            for k, _, _ in targets_all:
                _set_result(k, "⏳ En cola...")
            total = len(targets)
            lbl_prog.config(text=f"Instalando en {total} dispositivo(s) simultáneamente...")

            def _run():
                results = {}
                with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, total)) as ex:
                    futs = {ex.submit(_install_on_device, k, d, st, apks, allow_replace): k for k, d, st in targets}
                    for fut in concurrent.futures.as_completed(futs):
                        k = futs[fut]
                        try:
                            results[k] = bool(fut.result())
                        except Exception:
                            results[k] = False
                        for mk, src in mirror.items():
                            if src == k:
                                _set_result(mk, "↺ Mismo equipo (USB): " + row_status.get(k, "").lstrip("✔✖⏳ ").strip())
                        ok_n = sum(1 for v in results.values() if v)
                        try:
                            self.post_gui(lambda o=ok_n, n=len(results): lbl_prog.config(
                                text=f"Progreso: {n}/{total} terminados ({o} correctos)"))
                        except Exception:
                            pass

                def _finish():
                    state["installing"] = False
                    ok_n = sum(1 for v in results.values() if v)
                    try:
                        if win.winfo_exists():
                            lbl_prog.config(text=f"✔ Finalizado: {ok_n} correcto(s), {total - ok_n} con error")
                            _refresh_install_btn()
                    except Exception:
                        pass
                    self.set_status(f"Instalación de APK finalizada: {ok_n}/{total} dispositivos correctos.")

                self.post_gui(_finish)

            threading.Thread(target=_run, daemon=True).start()

        def _on_close():
            if state["installing"]:
                if not messagebox.askyesno("Instalación en curso",
                                           "Hay una instalación en curso. Si cierras la ventana seguirá ejecutándose en segundo plano.\n\n¿Cerrar de todos modos?",
                                           parent=win):
                    return
            try:
                if state["after"]:
                    win.after_cancel(state["after"])
            except Exception:
                pass
            self._apk_win = None
            win.destroy()

        win.protocol("WM_DELETE_WINDOW", _on_close)
        _refresh_install_btn()
        _poll()

    def _refresh_mic_apk_button(self, btn_mic, dev, dev_key):
        if not btn_mic:
            return
        is_usb = dev.get("is_usb", False)
        is_adb = dev.get("is_adb_connected", False)
        is_sys = dev.get("is_local_or_router", False)
        is_ready = (is_adb or (is_usb and not dev.get("is_offline") and not dev.get("is_unauthorized"))) and not is_sys
        sdk = dev.get("android_sdk")

        if is_ready and sdk is not None and sdk < 30:
            if dev_key in self._installing_mic_keys:
                btn_mic.config(text="⏳ Instalando...", state=tk.DISABLED)
            elif dev.get("mic_apk_installed"):
                btn_mic.config(
                    text="🎙 Escuchar Mic",
                    state=tk.NORMAL,
                    command=lambda k=dev_key, d=dev: self._on_mic_apk_button(self._get_row_dev(k, d))
                )
            else:
                btn_mic.config(
                    text="🎙 Instalar Mic",
                    state=tk.NORMAL,
                    command=lambda k=dev_key, d=dev: self._on_mic_apk_button(self._get_row_dev(k, d))
                )
            if not btn_mic.winfo_ismapped():
                btn_mic.pack(side=tk.LEFT, padx=2)
        else:
            if not is_ready and dev_key:
                with _DEV_MIC_CACHE_LOCK:
                    for ck in _mic_cache_keys(dev.get("serial"), dev=dev):
                        _DEV_MIC_PKG_CACHE.pop(ck, None)
                dev.pop("mic_apk_installed", None)
            if btn_mic.winfo_ismapped():
                btn_mic.pack_forget()

    def _apply_probed_mic_info(self, dev_key, sdk, installed):
        row_info = self.device_rows.get(dev_key)
        if not row_info:
            return
        d = row_info["dev"]
        changed = False
        if sdk is not None and d.get("android_sdk") != sdk:
            d["android_sdk"] = sdk
            changed = True
        if installed is not None and d.get("mic_apk_installed") != installed:
            d["mic_apk_installed"] = installed
            changed = True
        if changed:
            self._refresh_mic_apk_button(row_info.get("btn_mic_apk"), d, dev_key)

    def _schedule_mic_probe(self, dev):
        if not dev:
            return
        is_usb = dev.get("is_usb", False)
        is_adb = dev.get("is_adb_connected", False)
        is_sys = dev.get("is_local_or_router", False)
        if not ((is_adb or (is_usb and not dev.get("is_offline") and not dev.get("is_unauthorized"))) and not is_sys):
            return

        dev_name_str = str(dev.get("name") or "")
        target_hint = dev.get("serial") or (f"{dev.get('ip')}:{dev.get('port')}" if dev.get("port") else dev.get("ip"))
        if target_hint and ("d2s" in dev_name_str.lower() or "kds" in dev_name_str.lower()):
            start_kds_alarm_sound_bridge(target_hint, scrcpy_proc=None, device_name=dev_name_str, dev=dev)

        sync_dev_mic_caches(dev)
        sdk_now = dev.get("android_sdk")
        pkg_now = dev.get("mic_apk_installed")
        if sdk_now is not None and (sdk_now >= 30 or pkg_now is not None):
            return

        dev_key = dev.get("key") or dev.get("ip") or dev.get("serial")
        if not dev_key:
            return

        with _DEV_MIC_CACHE_LOCK:
            if dev_key in _DEV_PROBE_INFLIGHT:
                return
            _DEV_PROBE_INFLIGHT.add(dev_key)

        target_hint = dev.get("serial") or (f"{dev.get('ip')}:{dev.get('port')}" if dev.get("port") else dev.get("ip"))
        dev_snapshot = dict(dev)

        def _probe():
            try:
                sdk = get_device_android_sdk(target_hint, dev=dev_snapshot)
                installed = None
                if sdk is not None and sdk < 30:
                    installed = is_mic_apk_installed(target_hint, dev=dev_snapshot)
                if sdk is not None:
                    self.post_gui(self._apply_probed_mic_info, dev_key, sdk, installed)
            finally:
                with _DEV_MIC_CACHE_LOCK:
                    _DEV_PROBE_INFLIGHT.discard(dev_key)

        threading.Thread(target=_probe, daemon=True).start()

    def _on_mic_apk_button(self, dev):
        if not dev:
            return
        sync_dev_mic_caches(dev)
        if dev.get("mic_apk_installed"):
            self.start_control_session(dev, display_id=0, turn_screen_off=None, audio_source="mic")
        else:
            self.install_mic_apk_for_device(dev)

    def _prompt_install_mic_and_launch(self, dev, display_id=0, turn_screen_off=False):
        sdk = dev.get("android_sdk", "?")
        resp = messagebox.askyesno(
            "Instalar MicrofonoADB",
            f"{dev['name']} usa Android < 11 (SDK {sdk}).\n\n"
            "Para escuchar el sonido físico por el micrófono se requiere la mini app 'MicrofonoADB'.\n\n"
            "¿Deseas instalarla automáticamente ahora y abrir la pantalla con micrófono?"
        )
        if resp:
            self.install_mic_apk_for_device(dev, relaunch_args=(display_id, turn_screen_off, "mic"))

    def install_mic_apk_for_device(self, dev, relaunch_args=None):
        """Instala MicrofonoADB.apk en segundo plano sobre un dispositivo Android < 11."""
        dev_key = dev.get("key") or dev.get("ip") or dev.get("serial")
        if not dev_key or dev_key in self._installing_mic_keys:
            return

        if not os.path.exists(MIC_APK_PATH):
            messagebox.showerror("APK No Encontrado", f"No se encontró el archivo:\n{MIC_APK_PATH}")
            return

        self._installing_mic_keys.add(dev_key)
        row_info = self.device_rows.get(dev_key)
        if row_info:
            self._refresh_mic_apk_button(row_info.get("btn_mic_apk"), dev, dev_key)

        target_hint = dev.get("serial") or (f"{dev.get('ip')}:{dev.get('port')}" if dev.get("port") else dev.get("ip"))
        self.set_status(f"Instalando MicrofonoADB.apk en {dev['name']}...")

        def _worker():
            ok, detail = install_mic_apk_on_device(target_hint, dev=dev)
            def _finish():
                self._installing_mic_keys.discard(dev_key)
                cur_row = self.device_rows.get(dev_key)
                cur_dev = cur_row["dev"] if cur_row else dev
                if ok:
                    cur_dev["mic_apk_installed"] = True
                if cur_row:
                    self._refresh_mic_apk_button(cur_row.get("btn_mic_apk"), cur_dev, dev_key)
                if ok:
                    self.set_status(f"¡MicrofonoADB instalado en {cur_dev['name']}! Listo para escuchar audio.")
                    if relaunch_args:
                        d_id, scr_off, a_src = relaunch_args
                        self.start_control_session(cur_dev, display_id=d_id, turn_screen_off=scr_off, audio_source=a_src)
                    else:
                        messagebox.showinfo(
                            "MicrofonoADB Instalado",
                            f"La mini app se instaló correctamente en {cur_dev['name']}.\n\n"
                            "Ahora haz clic en '🎙 Escuchar Mic' (o en 'Pantalla ▾ -> 🎙 Pantalla (Audio por Micrófono)') para escuchar sus sonidos."
                        )
                else:
                    self.set_status(f"Error al instalar MicrofonoADB en {cur_dev['name']}.")
                    messagebox.showerror("Error de Instalación", f"No se pudo instalar MicrofonoADB en {cur_dev['name']}:\n{detail}")
            self.post_gui(_finish)

        threading.Thread(target=_worker, daemon=True).start()

    def start_control_session(self, dev, display_id=0, turn_screen_off=None, audio_source=None):
        """Inicia el control remoto en ventana normal (minimizables y maximizables). Conecta por ADB si es necesario."""
        dev = self._get_row_dev(dev.get("key"), dev)
        if turn_screen_off is None:
            turn_screen_off = bool(getattr(self, "screen_off_var", None) and self.screen_off_var.get())

        serial_target = dev.get("serial")
        if not serial_target:
            if dev.get("port"):
                serial_target = f"{dev['ip']}:{dev['port']}"
            else:
                serial_target = dev["ip"]

        resolved = resolve_active_adb_target(serial_target, dev=dev)

        cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        is_already_active = False
        if dev.get("is_usb") or dev.get("is_adb_connected"):
            is_already_active = True
        elif resolved:
            try:
                chk = subprocess.run(["adb", "-s", str(resolved), "get-state"], capture_output=True, text=True, creationflags=cflags, timeout=2)
                if "device" in chk.stdout:
                    is_already_active = True
            except Exception:
                pass

        if is_already_active:
            if audio_source == "mic":
                sync_dev_mic_caches(dev)
                sdk = dev.get("android_sdk")
                if sdk is None:
                    sdk = get_device_android_sdk(resolved, dev=dev)
                if sdk is not None and sdk < 30:
                    installed = dev.get("mic_apk_installed")
                    if installed is None:
                        installed = is_mic_apk_installed(resolved, dev=dev)
                    if not installed:
                        self._prompt_install_mic_and_launch(dev, display_id=display_id, turn_screen_off=turn_screen_off)
                        return
            launch_remote_control(resolved, display_id=display_id, device_name=dev["name"], dev=dev, turn_screen_off=turn_screen_off, audio_source=audio_source)
            self.root.after(350, self.hide_to_background)
        else:
            if not dev.get("is_port_open"):
                messagebox.showwarning("No Disponible", f"{dev['name']} se encuentra fuera de esta red o no tiene el puerto ADB abierto.")
                return
            self.set_status(f"Conectando ADB a {dev['name']} ({dev['ip']})...")
            threading.Thread(target=self._auto_connect_and_launch, args=(dev, display_id, turn_screen_off, audio_source), daemon=True).start()

    def _auto_connect_and_launch(self, dev, display_id, turn_screen_off=False, audio_source=None):
        dev_key = dev["key"]
        ip = dev["ip"]
        row_info = self.device_rows.get(dev_key)
        if row_info:
            self.post_gui(lambda inf=row_info: inf["status_lbl"].config(text="⏳ Conectando...", foreground="#b36b00"))
        ok, detail, model = connect_ip_automatically(ip, known_port=dev.get("port", ""), status_callback=self.set_status)
        if ok:
            ensure_storage_mount()
            ensure_device_internet_stability(detail)
            dev["is_adb_connected"] = True
            dev["serial"] = detail
            if model:
                dev["name"] = model
            resolved = resolve_active_adb_target(detail, dev=dev)
            if audio_source == "mic":
                sdk = get_device_android_sdk(resolved, dev=dev)
                if sdk is not None and sdk < 30:
                    is_mic_apk_installed(resolved, dev=dev)
            self.post_gui(self._update_row_state_by_key, dev_key, dev)
            if audio_source == "mic" and dev.get("android_sdk") is not None and dev.get("android_sdk") < 30 and not dev.get("mic_apk_installed"):
                self.post_gui(self._prompt_install_mic_and_launch, dev, display_id, turn_screen_off)
                return
            self.post_gui(launch_remote_control, resolved, display_id, dev["name"], dev, turn_screen_off, audio_source)
            self.root.after(450, self.hide_to_background)
        else:
            open_now = check_tcp_ports_fast(ip, [5555, 7888])
            dev["is_port_open"] = bool(open_now)
            self.post_gui(self._update_row_state_by_key, dev_key, dev)
            self.post_gui(messagebox.showwarning, "Error de Conexión", f"No se pudo conectar a {dev['name']}:\n{detail}")

    def apply_filter(self, *args):
        query = self.filter_var.get().strip().lower()
        selected_net = self.net_filter_var.get().strip()

        # 1. Desempaquetar todas las filas para refrescar el orden visual
        for k, info in self.device_rows.items():
            info["row_frame"].pack_forget()

        # 2. Ordenar las filas:
        #    - Al principio: Dispositivos en estado Conectado (ADB o USB)
        #    - Después: Los demás dispositivos
        #    - Ambos grupos en orden numérico ascendente por dirección IP
        sorted_items = sorted(
            self.device_rows.items(),
            key=lambda it: get_device_sort_key(it[1]["dev"])
        )

        # 3. Empaquetar en el orden exacto las que cumplan los filtros activos
        for k, info in sorted_items:
            dev = info["dev"]
            name = str(dev.get("name", "")).lower()
            ip = str(dev.get("ip", "")).lower()
            dev_net = dev.get("network", "")
            grp = info.get("group_name", dev_net)

            # Filtro de red
            net_match = True
            if selected_net == "Solo Red Actual Conectada":
                net_match = dev.get("is_on_current_net") or dev.get("is_usb")
            elif selected_net == "Solo Sitio de Trabajo":
                net_match = ("trabajo" in str(grp).lower() or "trabajo" in dev_net.lower())
            elif selected_net == "Solo Casa":
                net_match = ("casa" in str(grp).lower() or "familia" in str(grp).lower() or "casa" in dev_net.lower() or "familia" in dev_net.lower())

            # Filtro de texto
            text_match = (not query or query in ip or query in name)

            if net_match and text_match:
                info["row_frame"].pack(fill=tk.X, expand=True, pady=2)

        self.root.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def add_manual_ip(self):
        raw_ip = self.manual_ip_var.get().strip()
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", raw_ip):
            messagebox.showwarning("IP Inválida", "Por favor ingresa una dirección IPv4 válida (ejemplo: 192.168.1.78).")
            return

        self.set_status(f"Comprobando IP estática {raw_ip}...")
        threading.Thread(target=self._add_manual_worker, args=(raw_ip,), daemon=True).start()

    def _add_manual_worker(self, ip):
        cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        mac = get_mac_sendarp(ip)
        res = subprocess.run(["ping", "-n", "1", "-w", "400", ip], capture_output=True, text=True, creationflags=cflags)
        is_alive = ("TTL=" in res.stdout or "ttl=" in res.stdout.lower()) or (mac is not None)

        if not is_alive:
            self.post_gui(messagebox.showwarning, "Sin Respuesta", f"El equipo {ip} no respondió. Verifica que esté encendido y en la misma red Wi-Fi.")
            self.set_status(f"Dispositivo {ip} no respondió.")
            return

        if not mac:
            arp_out = subprocess.run(["arp", "-a"], capture_output=True, text=True, creationflags=cflags).stdout
            for line in arp_out.splitlines():
                if ip in line:
                    m = re.search(r"([0-9a-fA-F\-]{17})", line)
                    if m:
                        mac = m.group(1).upper().replace("-", ":")

        open_p = check_tcp_ports_fast(ip, [5555, 7888])
        detected_port = open_p[0] if open_p else ""
        vendor = lookup_mac_vendor_fast(mac) if mac else ""
        name = f"Dispositivo Estático ({vendor})" if vendor else "Dispositivo IP Estática"

        save_known_device(ip, name=name, mac=mac, is_static=True, last_port=detected_port, network=self.current_net_name)
        self.post_gui(self.manual_ip_var.set, "")
        self.set_status(f"¡Dispositivo estático {ip} guardado y confirmado!")
        self.post_gui(self.trigger_scan)

    def select_mobiles(self):
        for info in self.device_rows.values():
            dev = info["dev"]
            can_con = dev.get("is_port_open") and not dev.get("is_adb_connected") and not dev.get("is_usb") and not dev.get("is_local_or_router") and dev.get("is_on_current_net", True)
            info["chk_var"].set(bool(can_con))

    def deselect_all(self):
        for info in self.device_rows.values():
            info["chk_var"].set(False)

    def connect_selected(self):
        if self.connecting:
            return
        targets = [(k, info) for k, info in self.device_rows.items() if info["chk_var"].get()]
        if not targets:
            messagebox.showwarning("Sin selección", "Marca al menos un dispositivo disponible para conectar por ADB.")
            return

        self.connecting = True
        self.btn_connect.config(state=tk.DISABLED)
        threading.Thread(target=self._connect_worker, args=(targets,), daemon=True).start()

    def _connect_worker(self, targets):
        successes = []
        failures = []

        for k, info in targets:
            dev = info["dev"]
            dev_name = dev["name"]
            ip = dev["ip"]
            known_p = dev.get("port", "")
            self.post_gui(lambda inf=info: inf["status_lbl"].config(text="⏳ Conectando...", foreground="#b36b00"))

            ok, detail, model = connect_ip_automatically(
                ip,
                known_port=known_p,
                status_callback=self.set_status
            )

            if ok:
                ensure_storage_mount()
                ensure_device_internet_stability(detail)
                dev["is_adb_connected"] = True
                dev["serial"] = detail
                if model:
                    dev["name"] = model
                self.post_gui(self._update_row_state_by_key, k, dev)
                successes.append(f"{dev_name} ({detail})")
            else:
                open_now = check_tcp_ports_fast(ip, [5555, 7888])
                dev["is_port_open"] = bool(open_now)
                self.post_gui(self._update_row_state_by_key, k, dev)
                failures.append((f"{dev_name} ({ip})", detail))

        self.connecting = False
        self.post_gui(self.btn_connect.config, state=tk.NORMAL)
        self.set_status(f"Proceso finalizado -> Conectados: {len(successes)} | No disponibles: {len(failures)}")

        msg = ""
        if successes:
            msg += f"Conectados exitosamente ({len(successes)}):\n" + "\n".join(f"  ✔ {s}" for s in successes) + "\n\n"
        if failures:
            msg += f"No se pudo conectar a ({len(failures)}):\n" + "\n".join(
                f"  ✖ {title}:\n    {reason}"
                for title, reason in failures
            )

        self.post_gui(messagebox.showinfo, "Resultado de Conexión ADB", msg)

    def disconnect_all(self):
        cflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        subprocess.run(["adb", "disconnect"], capture_output=True, creationflags=cflags, timeout=3)
        for k, info in self.device_rows.items():
            if not info["dev"]["is_local_or_router"]:
                info["dev"]["is_adb_connected"] = False
                ip = info["dev"]["ip"]
                if not info["dev"].get("is_usb"):
                    open_p = check_tcp_ports_fast(ip, [5555, 7888])
                    info["dev"]["is_port_open"] = bool(open_p)
                self._update_row_state_by_key(k, info["dev"])
        self.status_var.set("Todos los dispositivos ADB Wi-Fi han sido desconectados.")
        messagebox.showinfo("Desconectado", "Se han cerrado todas las conexiones ADB por Wi-Fi.")

_SINGLE_INSTANCE_MUTEX_NAME = "Local\\MultiADBWifiBot_SingleInstance_Mutex_v1"
_SHOW_WINDOW_EVENT_NAME = "Local\\MultiADBWifiBot_ShowWindow_Event_v1"
_APP_WINDOW_TITLE = "Administrador de Dispositivos Wi-Fi y USB (Organizado por Red)"
_SINGLE_INSTANCE_MUTEX_HANDLE = None
_SHOW_WINDOW_EVENT_HANDLE = None
_SINGLE_INSTANCE_K32 = None


def acquire_single_instance_lock():
    """Garantiza una única instancia en ejecución; si ya existe otra, restaura/trae al frente su ventana."""
    global _SINGLE_INSTANCE_MUTEX_HANDLE, _SHOW_WINDOW_EVENT_HANDLE, _SINGLE_INSTANCE_K32
    if os.name != "nt":
        return True

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    k32.CreateMutexW.restype = ctypes.c_void_p
    k32.CreateEventW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p]
    k32.CreateEventW.restype = ctypes.c_void_p
    k32.OpenEventW.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_wchar_p]
    k32.OpenEventW.restype = ctypes.c_void_p
    k32.SetEvent.argtypes = [ctypes.c_void_p]
    k32.SetEvent.restype = ctypes.c_int
    k32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    k32.WaitForSingleObject.restype = ctypes.c_uint32
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    k32.CloseHandle.restype = ctypes.c_int
    _SINGLE_INSTANCE_K32 = k32

    ctypes.set_last_error(0)
    h_mutex = k32.CreateMutexW(None, 0, _SINGLE_INSTANCE_MUTEX_NAME)
    err = ctypes.get_last_error()
    if not h_mutex:
        return True

    if err == 183:  # ERROR_ALREADY_EXISTS
        try:
            k32.CloseHandle(h_mutex)
        except Exception:
            pass
        h_evt = k32.OpenEventW(0x0002, 0, _SHOW_WINDOW_EVENT_NAME)  # EVENT_MODIFY_STATE
        if h_evt:
            try:
                k32.SetEvent(h_evt)
            finally:
                k32.CloseHandle(h_evt)
        else:
            try:
                u32 = ctypes.WinDLL("user32", use_last_error=False)
                u32.FindWindowW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p]
                u32.FindWindowW.restype = ctypes.c_void_p
                hwnd = u32.FindWindowW(None, _APP_WINDOW_TITLE)
                if hwnd:
                    u32.ShowWindow(hwnd, 9)  # SW_RESTORE
                    u32.SetForegroundWindow(hwnd)
            except Exception:
                pass
        return False

    _SINGLE_INSTANCE_MUTEX_HANDLE = h_mutex
    _SHOW_WINDOW_EVENT_HANDLE = k32.CreateEventW(None, 0, 0, _SHOW_WINDOW_EVENT_NAME)
    return True


def release_single_instance_lock():
    """Libera los objetos Mutex/Event al cerrar la única instancia."""
    global _SINGLE_INSTANCE_MUTEX_HANDLE, _SHOW_WINDOW_EVENT_HANDLE
    k32 = _SINGLE_INSTANCE_K32
    if k32:
        if _SHOW_WINDOW_EVENT_HANDLE:
            try:
                k32.CloseHandle(_SHOW_WINDOW_EVENT_HANDLE)
            except Exception:
                pass
            _SHOW_WINDOW_EVENT_HANDLE = None
        if _SINGLE_INSTANCE_MUTEX_HANDLE:
            try:
                k32.CloseHandle(_SINGLE_INSTANCE_MUTEX_HANDLE)
            except Exception:
                pass
            _SINGLE_INSTANCE_MUTEX_HANDLE = None


if __name__ == "__main__":
    if not acquire_single_instance_lock():
        sys.exit(0)
    try:
        root = tk.Tk()
        app = RealTimeMultiADBApp(root)
        root.mainloop()
    finally:
        terminate_all_child_processes()
        release_single_instance_lock()
        # Salida total: no deja hilos ni procesos internos vivos hasta volver a abrir el programa
        os._exit(0)
