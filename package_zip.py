import os
import sys
import shutil
import zipfile
import subprocess
import argparse

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(ROOT_DIR, "src")
BIN_DIR = os.path.join(ROOT_DIR, "bin")

TARGETS = [
    {"arch": "arm64",  "goos": "linux", "goarch": "arm64", "goarm": ""},
    {"arch": "arm",    "goos": "linux", "goarch": "arm",   "goarm": "7"},
    {"arch": "x86",    "goos": "linux", "goarch": "386",   "goarm": ""},
    {"arch": "x86_64", "goos": "linux", "goarch": "amd64", "goarm": ""},
]

FILES_TO_PACK = [
    # Metadata & installer scripts
    "META-INF/com/google/android/update-binary",
    "META-INF/com/google/android/updater-script",
    "module.prop",
    "config.json",
    "customize.sh",
    "service.sh",
    "post-fs-data.sh",
    "action.sh",
    "uninstall.sh",
    "LICENSE",
    "README.md",
    "icon.png",
    
    # Webroot UI
    "webroot/index.html",
    "webroot/config.json",
    "webroot/module_icon.png",
    
    # Multi-arch binaries
    "bin/arm64/tgws",
    "bin/arm/tgws",
    "bin/x86/tgws",
    "bin/x86_64/tgws",
]


def get_module_prop():
    prop_path = os.path.join(ROOT_DIR, "module.prop")
    props = {}
    if os.path.exists(prop_path):
        with open(prop_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    props[k.strip()] = v.strip()
    return props


def find_go_binary():
    # 1. PATH lookup
    go_cmd = shutil.which("go")
    if go_cmd:
        return go_cmd
        
    # 2. Known standard paths
    candidates = [
        r"C:\Program Files\Go\bin\go.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Go\bin\go.exe"),
        os.path.expandvars(r"%USERPROFILE%\go\bin\go.exe"),
        "/usr/local/go/bin/go",
        "/usr/bin/go",
        "/snap/bin/go",
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
            
    return None


def build_binaries():
    print("=" * 60)
    print(">>> [1/2] Inlined Multi-Architecture Go Binary Compilation")
    print("=" * 60)

    go_cmd = find_go_binary()
    if not go_cmd:
        print("[-] Error: Go compiler ('go') not found in PATH or standard directories.")
        print("    Please install Go (https://go.dev/dl/) or add it to PATH.")
        sys.exit(1)

    print(f"Using Go compiler: {go_cmd}")

    for target in TARGETS:
        arch = target["arch"]
        goos = target["goos"]
        goarch = target["goarch"]
        goarm = target["goarm"]

        out_dir = os.path.join(BIN_DIR, arch)
        os.makedirs(out_dir, exist_ok=True)
        out_bin = os.path.join(out_dir, "tgws")

        env = os.environ.copy()
        env["CGO_ENABLED"] = "0"
        env["GOOS"] = goos
        env["GOARCH"] = goarch
        if goarm:
            env["GOARM"] = goarm
        elif "GOARM" in env:
            del env["GOARM"]

        arm_info = f", GOARM={goarm}" if goarm else ""
        print(f"  * Compiling for {arch:<6} (GOOS={goos}, GOARCH={goarch}{arm_info})...", end="", flush=True)

        cmd = [
            go_cmd, "build",
            "-trimpath",
            "-ldflags=-s -w",
            "-o", out_bin,
            "."
        ]

        res = subprocess.run(cmd, cwd=SRC_DIR, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode != 0:
            print(" [FAILED]")
            print(res.stderr)
            sys.exit(1)

        size_mb = os.path.getsize(out_bin) / (1024 * 1024)
        print(f" [OK] -> {size_mb:.2f} MB")

    print("All 4 target architectures built successfully!\n")


def make_zip():
    print("=" * 60)
    print(">>> [2/2] Packaging Magisk/KernelSU/APatch Module Archive")
    print("=" * 60)

    props = get_module_prop()
    mod_id = props.get("id", "teleweb")
    version = props.get("version", "v2.1.48-multiarch")
    
    if not version.startswith("v"):
        version = f"v{version}"
    if "multiarch" not in version:
        version = f"{version}-multiarch"

    zip_filename = f"{mod_id}-{version}.zip"
    output_zip = os.path.join(ROOT_DIR, zip_filename)

    print(f"Target archive: {output_zip}")
    with zipfile.ZipFile(output_zip, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for rel_path in FILES_TO_PACK:
            full_path = os.path.join(ROOT_DIR, rel_path.replace("/", os.sep))
            if not os.path.exists(full_path):
                raise FileNotFoundError(f"Missing required file: {full_path}")

            arcname = rel_path.replace("\\", "/")

            with open(full_path, "rb") as f:
                data = f.read()

            if arcname == "module.prop":
                # Ensure the packaged module.prop contains the pristine base description,
                # never contaminated with dynamic runtime status (matching bindhosts standard).
                lines = data.decode("utf-8").splitlines(keepends=True)
                clean_lines = []
                for line in lines:
                    if line.startswith("description="):
                        clean_lines.append("description=Прозрачный WSS-транспорт для Telegram (DC1-DC5)\n")
                    else:
                        clean_lines.append(line)
                data = "".join(clean_lines).encode("utf-8")

            zinfo = zipfile.ZipInfo(arcname)
            zinfo.compress_type = zipfile.ZIP_DEFLATED

            # Permissions: 0755 for executables/scripts, 0644 for configs/docs
            if arcname.endswith(".sh") or arcname.startswith("bin/") or "/bin/" in arcname or arcname.endswith("update-binary"):
                zinfo.external_attr = 0o100755 << 16
            else:
                zinfo.external_attr = 0o100644 << 16

            zf.writestr(zinfo, data)
            size_mb = len(data) / (1024 * 1024)
            print(f"  + {arcname:<42} ({size_mb:.2f} MB)" if size_mb >= 0.1 else f"  + {arcname:<42} ({len(data)} B)")

    total_mb = os.path.getsize(output_zip) / (1024 * 1024)
    print(f"\n[DONE] Module successfully created: {zip_filename} ({total_mb:.2f} MB)")
    return output_zip


def main():
    parser = argparse.ArgumentParser(description="Build and package TeleWEB Magisk/KernelSU/APatch module.")
    parser.add_argument("--skip-build", action="store_true", help="Skip Go binary compilation and only package the module zip.")
    parser.add_argument("--build-only", action="store_true", help="Only compile Go binaries without creating the module zip.")
    args = parser.parse_args()

    if not args.skip_build:
        build_binaries()

    if not args.build_only:
        make_zip()


if __name__ == "__main__":
    main()
