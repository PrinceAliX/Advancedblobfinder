#!/usr/bin/env python3
# Joshua Wright jwright@hasborg.com
# Ali Mohammad Mian - Modified for added functionality

import sys
import socket
import requests
import xml.etree.ElementTree as ET
import re
import os

HOSTSUFFIX = ".blob.core.windows.net"
URLPARAM = "?restype=container&comp=list"
URLPARAM_VERSIONS = "?restype=container&comp=list&include=versions"
HEADERS = {"x-ms-version": "2019-12-12"}

def print_blobs(xmlstr):
    blob_names = []
    try:
        root = ET.fromstring(xmlstr)
        for blob in root.iter("Blob"):
            name = blob.find("Name")
            if name is not None:
                print(f"    - {name.text}")
                blob_names.append(name.text)
    except ET.ParseError:
        print("    [!] Failed to parse XML blob list.")
    return blob_names

def resolve_name(hostname):
    try:
        socket.gethostbyname_ex(hostname)
    except:
        return False
    return True

def get_blob_versions(account, container):
    print("    Checking for previous versions...")
    base_url = f"https://{account}{HOSTSUFFIX}/{container}"
    try:
        r_ver = requests.get(base_url + URLPARAM_VERSIONS, headers=HEADERS)
        if r_ver.status_code != 200:
            print(f"    [!] Failed to retrieve versions (HTTP {r_ver.status_code})")
            return []
    except requests.ConnectionError:
        print("    [!] Failed to connect for version check.")
        return []

    versions = []
    try:
        root = ET.fromstring(r_ver.text)
        for blob in root.iter("Blob"):
            name = blob.find("Name").text
            version = blob.find("VersionId")
            is_current = blob.find("IsCurrentVersion")
            if version is not None:
                versions.append({
                    "name": name,
                    "version": version.text,
                    "is_current": (is_current is not None and is_current.text.lower() == "true")
                })
    except ET.ParseError:
        print("    [!] XML parsing failed for versions.")
        return []

    if versions:
        print(f"    [*] Found {len(versions)} versioned blobs:")
        for i, v in enumerate(versions):
            flag = "(current)" if v["is_current"] else ""
            print(f"      {i+1}. {v['name']} @ version {v['version']} {flag}")
    else:
        print("    No previous versions found.")
    return versions

def prompt_download(account, container, versions):
    while True:
        choice = input("    >> Enter number of a version to download (or press ENTER to skip): ")
        if not choice.strip():
            break
        try:
            index = int(choice) - 1
            if index < 0 or index >= len(versions):
                print("    [!] Invalid selection.")
                continue
            selected = versions[index]
            name = selected["name"]
            version = selected["version"]
            url = f"https://{account}{HOSTSUFFIX}/{container}/{name}?versionid={version}"
            filename = f"{os.path.basename(name)}.{version[:6]}.bak"
            print(f"    [+] Downloading to: {filename}")
            r = requests.get(url, headers=HEADERS)
            if r.status_code == 200:
                with open(filename, "wb") as f:
                    f.write(r.content)
                print("    [*] Download successful.")
            else:
                print(f"    [!] Failed to download (HTTP {r.status_code})")
        except ValueError:
            print("    [!] Please enter a valid number.")

def prompt_download_current(account, container, blob_names):
    while True:
        choice = input("    >> Enter number of a current blob to download (or press ENTER to skip): ")
        if not choice.strip():
            break
        try:
            index = int(choice) - 1
            if index < 0 or index >= len(blob_names):
                print("    [!] Invalid selection.")
                continue
            name = blob_names[index]
            url = f"https://{account}{HOSTSUFFIX}/{container}/{name}"
            filename = os.path.basename(name)
            print(f"    [+] Downloading to: {filename}")
            r = requests.get(url, headers=HEADERS)
            if r.status_code == 200:
                with open(filename, "wb") as f:
                    f.write(r.content)
                print("    [*] Download successful.")
            else:
                print(f"    [!] Failed to download (HTTP {r.status_code})")
        except ValueError:
            print("    [!] Please enter a valid number.")

def print_help():
    print("""Azure Blob Access Checker
PoC script to test for publicly accessible Azure Blob containers and versioned objects.

Usage:
    python3 script.py <name list file>

    or for help:
    python3 script.py --help

The name list file should contain lines like:
    storageaccount:containername
    or
    justname
Which is treated as both the account and container name.

When blobs are accessible:
    - Lists regular blob files.
    - Lists versioned blob files.
    - Allows you to selectively download either.
""")

def main():
    if len(sys.argv) != 2 or sys.argv[1] in ("--help", "-h"):
        print_help()
        sys.exit(0)

    with open(sys.argv[1]) as fp:
        for cnt, line in enumerate(fp):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if ":" in line:
                storacct, cntrname = line.split(":")
            else:
                storacct = cntrname = line

            if re.search("[^a-z0-9]", storacct) or len(storacct) < 3 or len(storacct) > 24:
                print(f"[!] Invalid storage account name {storacct}, skipping.")
                continue

            if cntrname != "$web":
                if (re.search("[^a-z0-9\\-]", cntrname) or "--" in cntrname
                        or len(cntrname) < 3 or len(cntrname) > 63):
                    print(f"[!] Invalid container name {cntrname}, skipping.")
                    continue

            fqdn = f"{storacct}{HOSTSUFFIX}"
            if not resolve_name(fqdn):
                continue

            base_url = f"https://{fqdn}/{cntrname}"
            try:
                r = requests.get(base_url + URLPARAM, headers=HEADERS)
            except requests.ConnectionError:
                print(f"[!] Could not connect to {fqdn}")
                continue

            if r.status_code == 200:
                print(f"\n[+] Valid: {storacct}:{cntrname}")
                print("    Current blob objects:")
                blob_names = print_blobs(r.text)
                if blob_names:
                    for i, name in enumerate(blob_names):
                        print(f"      {i+1}. {name}")
                    prompt_download_current(storacct, cntrname, blob_names)

                versions = get_blob_versions(storacct, cntrname)
                if versions:
                    prompt_download(storacct, cntrname, versions)
            elif r.status_code == 403:
                print(f"[!] {storacct}:{cntrname} exists but access is denied (403).")
            elif r.status_code == 404:
                continue
            else:
                print(f"[?] Unexpected response: {r.status_code} from {fqdn}")

if __name__ == "__main__":
    main()
