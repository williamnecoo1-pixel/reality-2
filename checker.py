import concurrent.futures
import json
import os
import re
import socket
import subprocess
import tempfile
import time
import base64
import threading
from urllib.parse import parse_qs, unquote, urlparse

import requests

# ============================================================
# 1. SOURCES
# ============================================================

SOURCE_URLS = [
    "https://github.com/williamnecoo1-pixel/testrw/raw/refs/heads/main/reality_configs.txt",
    "https://github.com/williamnecoo1-pixel/ss/raw/refs/heads/main/sub.txt",
]

XRAY = "./xray/xray"

TEST_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://www.apple.com/library/test/success.html",
]

TIMEOUT = 15
MAX_WORKERS = 15
MAX_LATENCY_MS = 5000

_tls = threading.local()


def get_session():
    if not hasattr(_tls, "session"):
        session = requests.Session()
        session.trust_env = False
        _tls.session = session
    return _tls.session


# ============================================================
# 2. DOWNLOAD + SUBSCRIPTION DECODING
# ============================================================

def extract_links(text):
    pattern = r'(?:vless|trojan|vmess)://[^\s<>"\']+'
    return re.findall(pattern, text, re.IGNORECASE)


def decode_subscription(text):
    links = extract_links(text)

    if links:
        return links

    # Try Base64 subscription
    compact = "".join(text.split())

    try:
        padded = compact + "=" * (-len(compact) % 4)
        decoded = base64.urlsafe_b64decode(padded).decode(
            "utf-8", errors="ignore"
        )
        links = extract_links(decoded)

        if links:
            return links
    except Exception:
        pass

    return []


def download_configs():
    configs = []

    for url in SOURCE_URLS:
        try:
            print(f"[DOWNLOAD] {url}", flush=True)

            response = requests.get(
                url,
                timeout=20,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            response.raise_for_status()

            found = decode_subscription(response.text)

            print(
                f"[SOURCE] Found {len(found)} configurations",
                flush=True
            )

            configs.extend(found)

        except Exception as e:
            print(f"[DOWNLOAD FAILED] {type(e).__name__}", flush=True)

    return list(dict.fromkeys(configs))


# ============================================================
# 3. CONFIG PARSER
# ============================================================

def parse_config(line):
    try:

        # ---------------- VMESS ----------------

        if line.lower().startswith("vmess://"):

            b64 = line[8:].split("#")[0].strip()
            b64 += "=" * (-len(b64) % 4)

            raw = base64.urlsafe_b64decode(b64)
            data = json.loads(raw.decode("utf-8"))

            return {
                "protocol": "vmess",
                "server": data.get("add"),
                "port": int(data.get("port", 443)),
                "id": data.get("id"),
                "aid": int(data.get("aid", 0)),
                "scy": data.get("scy", "auto"),
                "net": (data.get("net") or "tcp").lower(),
                "security": (data.get("tls") or "none").lower(),
                "host": data.get("host", ""),
                "sni": data.get("sni", ""),
                "path": data.get("path", "/"),
                "mode": data.get("mode", ""),
                "serviceName": data.get("serviceName", ""),
                "alpn": data.get("alpn", ""),
                "fp": data.get("fp", ""),
                "original": line,
            }

        # ---------------- VLESS / TROJAN ----------------

        if line.lower().startswith(("vless://", "trojan://")):

            parsed = urlparse(line)

            params = parse_qs(
                parsed.query,
                keep_blank_values=True
            )

            def get(name, default=""):
                return params.get(name, [default])[0]

            return {
                "protocol": parsed.scheme.lower(),
                "server": parsed.hostname,
                "port": parsed.port or 443,

                "uuid": unquote(parsed.username or ""),
                "password": unquote(parsed.username or ""),

                "net": (
                    get("type") or get("net") or "tcp"
                ).lower(),

                "security": (
                    get("security") or "none"
                ).lower(),

                "sni": get("sni") or parsed.hostname,
                "host": get("host"),

                "path": get("path") or "/",
                "mode": get("mode"),

                "serviceName": (
                    get("serviceName")
                    or get("servicename")
                    or get("path")
                ),

                "alpn": get("alpn"),
                "fp": get("fp"),

                "pbk": get("pbk"),
                "sid": get("sid"),
                "spx": get("spx") or "/",
                "flow": get("flow"),

                "original": line,
            }

    except Exception:
        return None

    return None


# ============================================================
# 4. BUILD XRAY CONFIG
# ============================================================

def make_xray_config(config, local_port):

    net = config.get("net", "tcp").lower()
    security = config.get("security", "none").lower()

    stream = {
        "network": net,
        "security": security,
    }

    # ---------------- TLS ----------------

    if security == "tls":

        tls_settings = {
            "serverName": config.get("sni") or config["server"],
            "allowInsecure": False,
        }

        if config.get("alpn"):
            tls_settings["alpn"] = [
                x.strip()
                for x in config["alpn"].split(",")
                if x.strip()
            ]

        if config.get("fp"):
            tls_settings["fingerprint"] = config["fp"]

        stream["tlsSettings"] = tls_settings

    # ---------------- REALITY ----------------

    elif security == "reality":

        stream["realitySettings"] = {
            "serverName": config.get("sni") or config["server"],
            "fingerprint": config.get("fp") or "chrome",
            "publicKey": config.get("pbk"),
            "shortId": config.get("sid"),
            "spiderX": config.get("spx", "/"),
        }

    # ---------------- WEBSOCKET ----------------

    if net == "ws":

        ws = {
            "path": config.get("path") or "/",
        }

        if config.get("host"):
            ws["headers"] = {
                "Host": config["host"]
            }

        stream["wsSettings"] = ws

    # ---------------- GRPC ----------------

    elif net == "grpc":

        grpc = {
            "serviceName": config.get("serviceName") or "",
        }

        if config.get("mode") == "multi":
            grpc["multiMode"] = True

        stream["grpcSettings"] = grpc

    # ---------------- XHTTP ----------------

    elif net == "xhttp":

        xhttp = {
            "path": config.get("path") or "/",
        }

        if config.get("host"):
            xhttp["host"] = config["host"]

        if config.get("mode"):
            xhttp["mode"] = config["mode"]

        stream["xhttpSettings"] = xhttp

    # ---------------- VLESS ----------------

    if config["protocol"] == "vless":

        user = {
            "id": config["uuid"],
            "encryption": "none",
        }

        if config.get("flow"):
            user["flow"] = config["flow"]

        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": config["server"],
                    "port": config["port"],
                    "users": [user],
                }]
            },
            "streamSettings": stream,
        }

    # ---------------- TROJAN ----------------

    elif config["protocol"] == "trojan":

        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": config["server"],
                    "port": config["port"],
                    "password": config["password"],
                }]
            },
            "streamSettings": stream,
        }

    # ---------------- VMESS ----------------

    elif config["protocol"] == "vmess":

        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": config["server"],
                    "port": config["port"],
                    "users": [{
                        "id": config["id"],
                        "alterId": config["aid"],
                        "security": config["scy"],
                    }],
                }]
            },
            "streamSettings": stream,
        }

    else:
        return None

    return {
        "log": {
            "loglevel": "error"
        },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": local_port,
            "protocol": "http",
            "settings": {},
        }],
        "outbounds": [outbound],
    }


# ============================================================
# 5. HTTP TEST
# ============================================================

def test_once(proxies):

    session = get_session()
    last_error = "no_response"

    for url in TEST_URLS:

        try:

            start = time.perf_counter()

            response = session.get(
                url,
                proxies=proxies,
                timeout=TIMEOUT,
                allow_redirects=False,
                stream=True,
            )

            elapsed = (time.perf_counter() - start) * 1000
            status = response.status_code
            response.close()

            if status in (200, 204):
                return round(elapsed), None

            last_error = f"http_{status}"

        except requests.exceptions.Timeout:
            last_error = "timeout"

        except requests.exceptions.ProxyError:
            last_error = "proxy_error"

        except Exception as e:
            last_error = type(e).__name__

    return None, last_error


# ============================================================
# 6. TEST CONFIG
# ============================================================

def get_free_port():

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_config(index, config):

    local_port = get_free_port()

    config_file = None
    log_file = None
    process = None

    try:

        xray_config = make_xray_config(config, local_port)

        if not xray_config:
            return {
                "ok": False,
                "reason": "make_failed",
                "server": config.get("server"),
            }

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False
        ) as f:

            json.dump(xray_config, f)
            config_file = f.name

        log_file = tempfile.NamedTemporaryFile(
            suffix=".log",
            delete=False
        ).name

        with open(log_file, "w") as log_handle:

            process = subprocess.Popen(
                [XRAY, "run", "-c", config_file],
                stdout=subprocess.DEVNULL,
                stderr=log_handle,
                start_new_session=True,
            )

        started = False

        for _ in range(30):

            if process.poll() is not None:
                break

            try:
                with socket.create_connection(
                    ("127.0.0.1", local_port),
                    timeout=0.3
                ):
                    started = True
                    break

            except OSError:
                time.sleep(0.2)

        if not started:

            reason = "xray_died"

            if log_file and os.path.exists(log_file):
                try:
                    with open(log_file, encoding="utf-8", errors="ignore") as f:
                        message = f.read()[-500:]
                        if message.strip():
                            reason = "xray_error"
                except Exception:
                    pass

            return {
                "ok": False,
                "reason": reason,
                "server": config.get("server"),
            }

        proxies = {
            "http": f"http://127.0.0.1:{local_port}",
            "https": f"http://127.0.0.1:{local_port}",
        }

        latency, error = test_once(proxies)

        if latency is not None and latency <= MAX_LATENCY_MS:

            return {
                "ok": True,
                "latency": latency,
                "line": config["original"],
                "server": config["server"],
                "protocol": config["protocol"],
                "network": config["net"],
            }

        return {
            "ok": False,
            "reason": error,
            "server": config.get("server"),
        }

    except Exception as e:

        return {
            "ok": False,
            "reason": type(e).__name__,
            "server": config.get("server"),
        }

    finally:

        if process:

            try:
                process.terminate()
                process.wait(timeout=1)

            except Exception:

                try:
                    process.kill()
                except Exception:
                    pass

        for path in (config_file, log_file):

            if path and os.path.exists(path):

                try:
                    os.remove(path)
                except Exception:
                    pass


# ============================================================
# 7. MAIN
# ============================================================

def main():

    print("Downloading configurations...", flush=True)

    lines = download_configs()

    configs = []

    for line in lines:

        config = parse_config(line)

        if not config:
            continue

        if not config.get("server"):
            continue

        if config.get("port") != 443:
            continue

        if config.get("security") != "tls":
            continue

        if config.get("net") not in (
            "ws", "xhttp", "grpc", "tcp", "raw"
        ):
            continue

        configs.append(config)

    # Remove duplicates
    unique = {}

    for config in configs:
        unique[config["original"]] = config

    configs = list(unique.values())

    total = len(configs)

    print(
        f"\n[READY] Total configs: {total}",
        flush=True
    )

    if not os.path.isfile(XRAY):
        print(f"[ERROR] Xray binary not found: {XRAY}")
        return

    if not configs:
        print("[ERROR] No supported configurations found.")
        return

    results = []
    completed = 0
    working = 0

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = {
            executor.submit(test_config, i, config): config
            for i, config in enumerate(configs, start=1)
        }

        for future in concurrent.futures.as_completed(futures):

            completed += 1

            try:

                result = future.result()

                if result["ok"]:

                    working += 1
                    results.append(result)

                    print(
                        f"[ONLINE] {result['latency']}ms | "
                        f"{result['protocol']} | "
                        f"{result['network']} | "
                        f"{result['server']}",
                        flush=True
                    )

                else:

                    print(
                        f"[FAILED] "
                        f"{result.get('server')} | "
                        f"{result.get('reason')}",
                        flush=True
                    )

            except Exception as e:

                print(
                    f"[ERROR] {type(e).__name__}",
                    flush=True
                )

            if completed % 10 == 0 or completed == total:

                print(
                    f"\n[PROGRESS] {completed}/{total} | "
                    f"Working: {working} | "
                    f"Remaining: {total-completed}\n",
                    flush=True
                )

    results.sort(key=lambda x: x["latency"])

    with open("working.txt", "w", encoding="utf-8") as f:

        for result in results:
            f.write(result["line"] + "\n")

    print(
        f"\n[DONE] {len(results)} working configurations saved.",
        flush=True
    )


if __name__ == "__main__":
    main()
