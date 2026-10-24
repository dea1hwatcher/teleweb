import os
import zipfile

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_ZIP = os.path.join(ROOT_DIR, "teleweb-v2.1.48-multiarch.zip")

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
    
    # Webroot UI
    "webroot/index.html",
    "webroot/config.json",
    "webroot/module_icon.png",
    
    # Multi-arch binaries
    "bin/tgws",
    "bin/arm64/tgws",
    "bin/arm/tgws",
    "bin/x86/tgws",
    "bin/x86_64/tgws",
]

def make_zip():
    print(f"Creating Magisk module zip: {OUTPUT_ZIP}")
    with zipfile.ZipFile(OUTPUT_ZIP, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for rel_path in FILES_TO_PACK:
            full_path = os.path.join(ROOT_DIR, rel_path.replace("/", os.sep))
            if not os.path.exists(full_path):
                raise FileNotFoundError(f"Missing required file: {full_path}")
            
            # Use forward slashes inside ZIP
            arcname = rel_path.replace("\\", "/")
            
            # Read file data
            with open(full_path, "rb") as f:
                data = f.read()
            
            # Create ZipInfo object to preserve Unix permissions
            zinfo = zipfile.ZipInfo(arcname)
            zinfo.compress_type = zipfile.ZIP_DEFLATED
            
            # Determine permission: 0755 for scripts and binaries, 0644 for regular files
            if arcname.endswith(".sh") or arcname.startswith("bin/") or "/bin/" in arcname or arcname.endswith("update-binary"):
                zinfo.external_attr = 0o100755 << 16  # -rwxr-xr-x
            else:
                zinfo.external_attr = 0o100644 << 16  # -rw-r--r--
            
            zf.writestr(zinfo, data)
            size_mb = len(data) / (1024 * 1024)
            print(f"  + {arcname} ({size_mb:.2f} MB)" if size_mb >= 0.1 else f"  + {arcname} ({len(data)} B)")

    zip_size_mb = os.path.getsize(OUTPUT_ZIP) / (1024 * 1024)
    print(f"\nSuccessfully created {OUTPUT_ZIP} ({zip_size_mb:.2f} MB)")

if __name__ == "__main__":
    make_zip()
