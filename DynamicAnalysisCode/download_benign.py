#!/usr/bin/env python3
"""
download_benign.py — fetch real, popular VS Code extensions (.vsix) to use as the
BENIGN control set, sourced from the supervisor-provided awesome-vscode list.

It downloads each extension's LATEST .vsix from the official VS Code Marketplace
into  <out>/<publisher.name>/<version>.vsix  — the SAME layout as the malicious
dataset, so run_dataset.js can process it directly.

Usage (on the Ubuntu VM, python3 is already available):
    python3 download_benign.py benign_list.txt ./Benign

Then analyse exactly like the malicious set, appending to the same CSV:
    node run_dataset.js --input ./Benign --output ./results_benign --label 0 \
         --wait 10000 --csv ./results2/all.csv --append
    node evaluate.js ./results2/all.csv

Notes:
  * Only the Python 3 standard library is used (urllib, gzip, json).
  * Extensions not on the Marketplace are skipped with a message — just edit
    benign_list.txt (one "publisher.name" per line; '#' comments allowed).
"""
import sys, os, json, gzip, io, time, urllib.request, urllib.error

GALLERY = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"
QHEAD = {
    "Accept": "application/json;api-version=3.0-preview.1",
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (csn304-benign-fetch)",
}

def http(req, timeout=60):
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
        if r.headers.get("Content-Encoding") == "gzip":
            data = gzip.decompress(data)
        return data, r.headers

def latest_version(pub_name):
    """Query the Marketplace for the most recent version string of pub.name."""
    body = json.dumps({
        "filters": [{"criteria": [{"filterType": 7, "value": pub_name}]}],
        "flags": 914,
    }).encode()
    req = urllib.request.Request(GALLERY, data=body, headers=QHEAD)
    data, _ = http(req)
    j = json.loads(data.decode("utf-8", "replace"))
    results = j.get("results", [])
    exts = results[0].get("extensions", []) if results else []
    if not exts:
        return None
    versions = exts[0].get("versions", [])
    return versions[0]["version"] if versions else None

def download_vsix(pub_name, version, out):
    pub, name = pub_name.split(".", 1)
    url = (f"https://marketplace.visualstudio.com/_apis/public/gallery/"
           f"publishers/{pub}/vsextensions/{name}/{version}/vspackage")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    data, _ = http(req, timeout=120)
    # vspackage is gzip-encoded; http() already de-gzipped → data is the raw .vsix (zip)
    d = os.path.join(out, pub_name)
    os.makedirs(d, exist_ok=True)
    dest = os.path.join(d, f"{version}.vsix")
    with open(dest, "wb") as f:
        f.write(data)
    return dest, len(data)

def main():
    if len(sys.argv) < 2:
        print("usage: python3 download_benign.py <benign_list.txt> [out_dir=./Benign]")
        sys.exit(1)
    list_file = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else "./Benign"
    names = []
    with open(list_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                names.append(line)
    print(f"Downloading {len(names)} benign extensions → {out}\n" + "=" * 60)
    ok = skip = 0
    for i, pn in enumerate(names, 1):
        try:
            if "." not in pn:
                print(f"[{i}/{len(names)}] {pn}  [skip: not publisher.name]"); skip += 1; continue
            v = latest_version(pn)
            if not v:
                print(f"[{i}/{len(names)}] {pn}  [skip: not found on Marketplace]"); skip += 1; continue
            dest, size = download_vsix(pn, v, out)
            print(f"[{i}/{len(names)}] {pn} v{v}  → {size//1024} KB")
            ok += 1
            time.sleep(0.4)  # be polite to the API
        except urllib.error.HTTPError as e:
            print(f"[{i}/{len(names)}] {pn}  [HTTP {e.code}]"); skip += 1
        except Exception as e:
            print(f"[{i}/{len(names)}] {pn}  [error: {e}]"); skip += 1
    print("=" * 60)
    print(f"Done. downloaded={ok}  skipped={skip}  → {out}")

if __name__ == "__main__":
    main()
