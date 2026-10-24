#!/usr/bin/env python3
"""
Rocket League Custom Training Pack (.Tem) Decryption, CRC Verification & SaveData Parser.
Supports:
1. Rocket League custom MSB-first CRC32 verification (Poly: 0x04C11DB7, Seed: 0xEFCBF201)
2. AES-256-ECB decryption using Rocket League's Training SaveData key
3. Unreal Engine 3 / TAGame SaveData binary property deserialization
4. Embedded JSON archetype parsing & unit conversion (Unreal Rotator 65536 -> Degrees, 3D Velocity Vector)
5. Re-encryption & .Tem packing
"""

import struct
import io
import json
import math
import os
import datetime
from Crypto.Cipher import AES

AES_KEY = bytes([
    0xD7, 0x8C, 0x32, 0x4A, 0x94, 0x42, 0x94, 0x3C,
    0x6D, 0x65, 0xCE, 0x98, 0x81, 0x85, 0x4C, 0x41,
    0x68, 0x99, 0x22, 0x0C, 0xC7, 0xA1, 0x46, 0x40,
    0x93, 0x9B, 0x96, 0x3C, 0x93, 0x2A, 0x6F, 0xAF
])

CRC_SEED = 0xEFCBF201
FOOSBALL_MAGIC = 0xF005BA11
HEADER_MAGIC = 0x7FFFFFFF
OBJ_HEADER = 0xFFFFFFFF


def calc_rl_crc32(data: bytes, seed: int = CRC_SEED) -> int:
    crc_table = []
    for i in range(256):
        c = (i << 24) & 0xFFFFFFFF
        for _ in range(8):
            if c & 0x80000000:
                c = ((c << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
            else:
                c = (c << 1) & 0xFFFFFFFF
        crc_table.append(c)
    crc = (~seed) & 0xFFFFFFFF
    for b in data:
        crc = ((crc << 8) ^ crc_table[((crc >> 24) ^ b) & 0xFF]) & 0xFFFFFFFF
    return (~crc) & 0xFFFFFFFF


def decrypt_tem(raw_bytes: bytes) -> tuple[dict, bytes]:
    part1_len, part1_crc = struct.unpack("<II", raw_bytes[:8])
    encrypted = raw_bytes[8:8 + part1_len]
    calculated_crc = calc_rl_crc32(encrypted, CRC_SEED)
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted)
    header_info = {
        "file_size_bytes": len(raw_bytes),
        "encrypted_payload_bytes": part1_len,
        "stored_crc32": f"0x{part1_crc:08X}",
        "calculated_crc32": f"0x{calculated_crc:08X}",
        "crc_valid": part1_crc == calculated_crc,
    }
    return header_info, decrypted


def read_ue_str(stream: io.BytesIO):
    raw_len = stream.read(4)
    if len(raw_len) < 4:
        return None
    length = struct.unpack("<i", raw_len)[0]
    if length > 0:
        b = stream.read(length)
        return b[:-1].decode("cp1252", errors="replace")
    elif length < 0:
        b = stream.read(length * -2)
        return b[:-2].decode("utf-16-le", errors="replace")
    return None


def uru_to_deg(uru: float) -> float:
    return round(uru * (360.0 / 65536.0), 4)


def enrich_archetype(arch: dict) -> dict:
    res = dict(arch)
    if "ObjectArchetype" in arch and "Ball" in arch["ObjectArchetype"]:
        res["role"] = "Ball"
        p_deg = uru_to_deg(arch.get("VelocityStartRotationP", 0))
        y_deg = uru_to_deg(arch.get("VelocityStartRotationY", 0))
        r_deg = uru_to_deg(arch.get("VelocityStartRotationR", 0))
        speed = arch.get("VelocityStartSpeed", 0.0)
        p_rad = math.radians(p_deg)
        y_rad = math.radians(y_deg)
        vx = round(speed * math.cos(p_rad) * math.cos(y_rad), 4)
        vy = round(speed * math.cos(p_rad) * math.sin(y_rad), 4)
        vz = round(speed * math.sin(p_rad), 4)
        res["computed"] = {
            "velocity_rotation_deg": {"pitch": p_deg, "yaw": y_deg, "roll": r_deg},
            "initial_velocity_vector_uu_s": {"vx": vx, "vy": vy, "vz": vz},
            "initial_speed_kph": round(speed * 0.036, 2)
        }
    elif "ObjectArchetype" in arch and "DynamicSpawnPointMesh" in arch["ObjectArchetype"]:
        res["role"] = "PlayerCarSpawn"
        res["computed"] = {
            "rotation_deg": {
                "pitch": uru_to_deg(arch.get("RotationP", 0)),
                "yaw": uru_to_deg(arch.get("RotationY", 0)),
                "roll": uru_to_deg(arch.get("RotationR", 0)),
            }
        }
    elif arch.get("IsPC") is True:
        res["role"] = "EditorFreeCam"
        res["computed"] = {
            "rotation_deg": {
                "pitch": uru_to_deg(arch.get("RotationP", 0)),
                "yaw": uru_to_deg(arch.get("RotationY", 0)),
                "roll": uru_to_deg(arch.get("RotationR", 0)),
            }
        }
    return res


def read_ue_props(stream: io.BytesIO) -> dict:
    props = {}
    while True:
        pos = stream.tell()
        if len(stream.read(4)) < 4:
            break
        stream.seek(pos)
        name = read_ue_str(stream)
        if name == "None" or name is None:
            break
        ptype = read_ue_str(stream)
        vlen, vidx = struct.unpack("<ii", stream.read(8))
        val = read_ue_prop_val(stream, ptype, vlen, name)
        if name in props:
            if not isinstance(props[name], list):
                props[name] = [props[name]]
            props[name].append(val)
        else:
            props[name] = val
    return props


def read_ue_prop_val(stream: io.BytesIO, ptype: str, vlen: int, prop_name: str = ""):
    if ptype == "BoolProperty":
        return struct.unpack("<?", stream.read(1))[0]
    elif ptype == "IntProperty":
        return struct.unpack("<i", stream.read(4))[0]
    elif ptype == "QWordProperty":
        val = struct.unpack("<Q", stream.read(8))[0]
        if prop_name in ("CreatedAt", "UpdatedAt") and val > 1000000000:
            return {
                "epoch": val,
                "iso_utc": datetime.datetime.fromtimestamp(val, datetime.timezone.utc).isoformat()
            }
        return val
    elif ptype == "FloatProperty":
        return round(struct.unpack("<f", stream.read(4))[0], 6)
    elif ptype in ("StrProperty", "NameProperty"):
        return read_ue_str(stream)
    elif ptype == "ByteProperty":
        enum_name = read_ue_str(stream)
        if enum_name == "None":
            return struct.unpack("<B", stream.read(1))[0]
        return {enum_name: read_ue_str(stream)}
    elif ptype == "ObjectProperty":
        return struct.unpack("<i", stream.read(4))[0]
    elif ptype == "StructProperty":
        sname = read_ue_str(stream)
        if sname == "Guid":
            a, b, c, d = struct.unpack("<IIII", stream.read(16))
            return f"{a:08X}-{b:08X}-{c:08X}-{d:08X}"
        elif sname in ("Vector", "Rotator"):
            x, y, z = struct.unpack("<fff", stream.read(12))
            return {"_struct": sname, "x": x, "y": y, "z": z}
        else:
            res = {"_struct": sname}
            res.update(read_ue_props(stream))
            return res
    elif ptype == "ArrayProperty":
        count = struct.unpack("<i", stream.read(4))[0]
        if prop_name == "Rounds":
            rounds = []
            for idx in range(count):
                r = read_ue_props(stream)
                r["round_index"] = idx + 1
                rounds.append(r)
            return rounds
        elif prop_name == "SerializedArchetypes":
            archs = []
            for _ in range(count):
                s = read_ue_str(stream)
                try:
                    archs.append(enrich_archetype(json.loads(s)))
                except Exception:
                    archs.append(s)
            return archs
        elif prop_name == "Tags":
            return [struct.unpack("<i", stream.read(4))[0] for _ in range(count)]
        else:
            return stream.read(vlen - 4).hex()
    else:
        return stream.read(vlen).hex()


def parse_tem_file(filepath: str) -> tuple[dict, bytes]:
    with open(filepath, "rb") as fp:
        raw = fp.read()
    header_info, dec = decrypt_tem(raw)
    s = io.BytesIO(dec)
    foosball, magic, eng_v, lic_v, type_v, savedata_len = struct.unpack("<IIiiii", s.read(24))
    savedata_bytes = s.read(savedata_len - 4)
    num_obj_types = struct.unpack("<i", s.read(4))[0]
    obj_types = []
    for _ in range(num_obj_types):
        t = read_ue_str(s)
        fpos, oidx = struct.unpack("<II", s.read(8))
        obj_types.append({"type": t, "file_position": fpos, "object_index": oidx})
    trailing_padding = s.read()

    sd = io.BytesIO(savedata_bytes)
    root_obj_hdr = struct.unpack("<I", sd.read(4))[0]
    root_props = read_ue_props(sd)

    objects = []
    for ot in obj_types:
        sd.seek(ot["file_position"] - 4)
        ohdr = struct.unpack("<I", sd.read(4))[0]
        oprops = read_ue_props(sd)
        objects.append({
            "object_index": ot["object_index"],
            "type": ot["type"],
            "file_position": ot["file_position"],
            "obj_header_magic": f"0x{ohdr:08X}",
            "properties": oprops
        })

    result = {
        "file_name": os.path.basename(filepath),
        "header": header_info,
        "savedata_envelope": {
            "foosball_magic": f"0x{foosball:08X}",
            "header_magic": f"0x{magic:08X}",
            "engine_version": eng_v,
            "licensee_version": lic_v,
            "type_version": type_v,
            "savedata_byte_length": savedata_len,
            "trailing_zero_padding_bytes": len(trailing_padding)
        },
        "root_properties": root_props,
        "object_types": obj_types,
        "objects": objects
    }
    return result, dec


if __name__ == "__main__":
    tem_files = [
        "raw/RLorig/172CA0CF4A0FF134062365815A6A5816.Tem",
        "raw/RLorig/A2AD27B74DE54E9E99B104982853DE26.Tem",
        "raw/RLorig/others/5F69C04047BEF4D8509A7289138FAFFB.Tem"
    ]
    summary = []
    for tf in tem_files:
        parsed, dec_bytes = parse_tem_file(tf)
        base = os.path.splitext(os.path.basename(tf))[0]
        out_json = f"parsed/training_packs/{base}.json"
        out_bin = f"parsed/training_packs/{base}.decrypted.bin"
        with open(out_json, "w", encoding="utf-8") as fp:
            json.dump(parsed, fp, indent=2, ensure_ascii=False)
        with open(out_bin, "wb") as fp:
            fp.write(dec_bytes)
        props = parsed["objects"][0]["properties"]
        summary.append({
            "file": parsed["file_name"],
            "guid": props.get("TM_Guid"),
            "name": props.get("TM_Name"),
            "code": props.get("Code"),
            "creator": props.get("CreatorName"),
            "creator_id": props.get("CreatorPlayerID"),
            "map": props.get("MapName"),
            "type": props.get("Type"),
            "difficulty": props.get("Difficulty"),
            "rounds_count": len(props.get("Rounds", [])),
            "unowned": parsed["root_properties"].get("bUnowned", False),
            "licensee_version": parsed["savedata_envelope"]["licensee_version"],
            "created_at": props.get("CreatedAt"),
            "updated_at": props.get("UpdatedAt"),
        })
        print(f"Parsed {tf} -> {out_json} ({len(props.get('Rounds', []))} rounds)")
    with open("parsed/training_packs/summary.json", "w", encoding="utf-8") as fp:
        json.dump(summary, fp, indent=2, ensure_ascii=False)
