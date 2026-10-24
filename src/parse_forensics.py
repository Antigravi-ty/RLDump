#!/usr/bin/env python3
"""
Forensic & Container Metadata Extractor for RLorig.zip.
Extracts:
1. ZIP Central Directory entries, timestamps, CRC32s, and external attributes
2. macOS Finder .DS_Store records (window bounds, sidebar state, logical/physical sizes, modification timestamps)
3. AppleDouble (.__MACOSX/._*) Extended Attributes (ATTR header, bplist00 binary plists, quarantine tokens, provenance IDs, download URLs)
"""

import zipfile
import plistlib
import struct
import datetime
import json
import os
from ds_store import DSStore


def parse_appledouble_file(filepath: str) -> dict:
    with open(filepath, "rb") as fp:
        data = fp.read()
    magic, version, filler, num_entries = struct.unpack(">II16sH", data[:26])
    res = {
        "file": filepath,
        "size_bytes": len(data),
        "magic": f"0x{magic:08X}",
        "version": f"0x{version:08X}",
        "filler_ascii": filler.decode("ascii", errors="replace").strip(),
        "entries": []
    }
    offset = 26
    for _ in range(num_entries):
        eid, eoff, elen = struct.unpack(">III", data[offset:offset + 12])
        offset += 12
        entry_info = {"entry_id": eid, "offset": eoff, "length": elen}
        if eid == 9:
            finder_info = data[eoff:eoff + 32]
            entry_info["finder_info_hex"] = finder_info.hex()
            attr_pos = data.find(b"ATTR", eoff)
            if attr_pos != -1:
                _, debug_tag, total_size, data_start, data_len, _, flags, num_attrs = struct.unpack(
                    ">4sIIII12sHH", data[attr_pos:attr_pos + 36]
                )
                attrs = []
                p = attr_pos + 36
                for _ in range(num_attrs):
                    a_off, a_len, a_flags, a_namelen = struct.unpack(">IIHB", data[p:p + 11])
                    a_name = data[p + 11:p + 11 + a_namelen - 1].decode("utf-8", errors="replace")
                    a_val = data[a_off:a_off + a_len]
                    attr_item = {
                        "name": a_name,
                        "length": a_len,
                        "flags": a_flags,
                        "raw_hex": a_val.hex()
                    }
                    if a_val.startswith(b"bplist00"):
                        pl = plistlib.loads(a_val)
                        attr_item["decoded_plist"] = [
                            x.isoformat() if isinstance(x, datetime.datetime) else str(x)
                            for x in (pl if isinstance(pl, list) else [pl])
                        ]
                    elif a_name == "com.apple.lastuseddate#PS" and len(a_val) == 16:
                        sec, nsec = struct.unpack("<qq", a_val)
                        attr_item["decoded_last_used_utc"] = datetime.datetime.fromtimestamp(
                            sec, datetime.timezone.utc
                        ).isoformat()
                        attr_item["nanoseconds"] = nsec
                    elif a_name == "com.apple.quarantine":
                        qstr = a_val.rstrip(b"\x00").decode("utf-8", errors="replace")
                        parts = qstr.split(";")
                        qtime = int(parts[1], 16) if len(parts) > 1 and parts[1] else 0
                        attr_item["decoded_quarantine"] = {
                            "raw_string": qstr,
                            "flags_hex": parts[0] if len(parts) > 0 else None,
                            "timestamp_hex": parts[1] if len(parts) > 1 else None,
                            "timestamp_utc": datetime.datetime.fromtimestamp(
                                qtime, datetime.timezone.utc
                            ).isoformat() if qtime else None,
                            "agent_app": parts[2] if len(parts) > 2 else None,
                            "event_uuid": parts[3] if len(parts) > 3 else None
                        }
                    attrs.append(attr_item)
                    p = (p + 11 + a_namelen + 3) & ~3
                entry_info["extended_attributes"] = attrs
        res["entries"].append(entry_info)
    return res


def parse_ds_store_file(filepath: str) -> list:
    records = []
    mac_epoch = datetime.datetime(2001, 1, 1, tzinfo=datetime.timezone.utc)
    with DSStore.open(filepath, "r") as d:
        for entry in d:
            val = entry.value
            decoded = None
            if isinstance(val, (bytes, bytearray)):
                if entry.code in (b"moDD", b"modD") and len(val) == 8:
                    secs = struct.unpack("<d", val)[0]
                    decoded = (mac_epoch + datetime.timedelta(seconds=secs)).isoformat()
                val = bytes(val).hex()
            records.append({
                "filename": entry.filename,
                "code": entry.code.decode("ascii", errors="replace"),
                "type": entry.type.decode("ascii", errors="replace") if isinstance(entry.type, bytes) else str(entry.type),
                "value": val,
                "decoded_timestamp_utc": decoded
            })
    return records


def main():
    zip_entries = []
    with zipfile.ZipFile("raw/RLorig.zip", "r") as zf:
        for info in zf.infolist():
            dt = datetime.datetime(*info.date_time)
            zip_entries.append({
                "filename": info.filename,
                "file_size": info.file_size,
                "compress_size": info.compress_size,
                "compress_type": info.compress_type,
                "modified_local": dt.isoformat(),
                "crc32": f"0x{info.CRC:08X}",
                "create_system": info.create_system,
                "external_attr_octal": oct(info.external_attr >> 16)
            })

    ds_records = parse_ds_store_file("raw/RLorig/.DS_Store")

    appledouble_files = []
    for root, _, files in os.walk("/tmp/rldump/__MACOSX"):
        for fn in sorted(files):
            p = os.path.join(root, fn)
            appledouble_files.append(parse_appledouble_file(p))

    forensics = {
        "zip_archive_entries": zip_entries,
        "ds_store_records": ds_records,
        "appledouble_extended_attributes": appledouble_files
    }
    with open("parsed/forensics/macos_and_zip_forensics.json", "w", encoding="utf-8") as fp:
        json.dump(forensics, fp, indent=2, ensure_ascii=False)
    print("Saved parsed/forensics/macos_and_zip_forensics.json")


if __name__ == "__main__":
    main()
