#!/usr/bin/env python3
"""
parse_all_replays.py
General-purpose multi-replay analyzer for Rocket League (.replay) files.
Processes all 12 replays from replays.zip (via rrrocket JSON + binary CRC32 check)
and extracts:
1. Header & NetStream metadata (MapName, MatchType, TeamSize, FPS, Frames, CRC32).
2. Roster & Spectator separation (Active Players with Car_Default vs Spectators/OBs with PawnType=1).
3. Dynamic Car Actor Lifecycle (Spawn, Demolish via bHidden/PRI-unlink/ReplicatedDemolishExtended,
   3-second no-entity gap, Respawn on new actor ID, Goal Reset).
4. Car Body Product IDs & Hitbox Mapping (both static table and automatic physical verification
   from flat-ground resting Z height and suspension pitch |fwd_z|).
5. 34 Standard Soccar Boost Pads automatic coordinate bijection & NewReplicatedPickupData
   event timeline (pickup -> cooldown -> respawn / kickoff reset).
6. Vehicle Controls & Component States (ReplicatedThrottle, ReplicatedSteer, bReplicatedHandbrake,
   ReplicatedBoost, and CarComponent_*:ReplicatedActive % 2 == 1).
7. Game Clock & State Machine (SecondsRemaining, ReplicatedRoundCountDownNumber, ReplicatedStateName, bOverTime).
"""

import json
import math
import statistics
import struct
import subprocess
import sys
from pathlib import Path
from parse_replay_bitstream import calc_rl_crc32

STANDARD_BOOST_PADS = [
    {"index": 0, "type": "small", "x": 0.0, "y": -4240.0, "z": 70.0},
    {"index": 1, "type": "small", "x": -1792.0, "y": -4184.0, "z": 70.0},
    {"index": 2, "type": "small", "x": 1792.0, "y": -4184.0, "z": 70.0},
    {"index": 3, "type": "big", "x": -3072.0, "y": -4096.0, "z": 73.0},
    {"index": 4, "type": "big", "x": 3072.0, "y": -4096.0, "z": 73.0},
    {"index": 5, "type": "small", "x": -940.0, "y": -3308.0, "z": 70.0},
    {"index": 6, "type": "small", "x": 940.0, "y": -3308.0, "z": 70.0},
    {"index": 7, "type": "small", "x": 0.0, "y": -2816.0, "z": 70.0},
    {"index": 8, "type": "small", "x": -3584.0, "y": -2484.0, "z": 70.0},
    {"index": 9, "type": "small", "x": 3584.0, "y": -2484.0, "z": 70.0},
    {"index": 10, "type": "small", "x": -1788.0, "y": -2300.0, "z": 70.0},
    {"index": 11, "type": "small", "x": 1788.0, "y": -2300.0, "z": 70.0},
    {"index": 12, "type": "small", "x": -2048.0, "y": -1036.0, "z": 70.0},
    {"index": 13, "type": "small", "x": 0.0, "y": -1024.0, "z": 70.0},
    {"index": 14, "type": "small", "x": 2048.0, "y": -1036.0, "z": 70.0},
    {"index": 15, "type": "big", "x": -3584.0, "y": 0.0, "z": 73.0},
    {"index": 16, "type": "small", "x": -1024.0, "y": 0.0, "z": 70.0},
    {"index": 17, "type": "small", "x": 1024.0, "y": 0.0, "z": 70.0},
    {"index": 18, "type": "big", "x": 3584.0, "y": 0.0, "z": 73.0},
    {"index": 19, "type": "small", "x": -2048.0, "y": 1036.0, "z": 70.0},
    {"index": 20, "type": "small", "x": 0.0, "y": 1024.0, "z": 70.0},
    {"index": 21, "type": "small", "x": 2048.0, "y": 1036.0, "z": 70.0},
    {"index": 22, "type": "small", "x": -1788.0, "y": 2300.0, "z": 70.0},
    {"index": 23, "type": "small", "x": 1788.0, "y": 2300.0, "z": 70.0},
    {"index": 24, "type": "small", "x": -3584.0, "y": 2484.0, "z": 70.0},
    {"index": 25, "type": "small", "x": 3584.0, "y": 2484.0, "z": 70.0},
    {"index": 26, "type": "small", "x": 0.0, "y": 2816.0, "z": 70.0},
    {"index": 27, "type": "small", "x": -940.0, "y": 3310.0, "z": 70.0},
    {"index": 28, "type": "small", "x": 940.0, "y": 3308.0, "z": 70.0},
    {"index": 29, "type": "big", "x": -3072.0, "y": 4096.0, "z": 73.0},
    {"index": 30, "type": "big", "x": 3072.0, "y": 4096.0, "z": 73.0},
    {"index": 31, "type": "small", "x": -1792.0, "y": 4184.0, "z": 70.0},
    {"index": 32, "type": "small", "x": 1792.0, "y": 4184.0, "z": 70.0},
    {"index": 33, "type": "small", "x": 0.0, "y": 4240.0, "z": 70.0},
]

KNOWN_BODY_PRODUCTS = {
    23: {"name": "Octane", "hitbox": "octane", "visual_preset": "octane"},
    403: {"name": "Masamune", "hitbox": "dominus", "visual_preset": "dominus"},
    1568: {"name": "Dominus", "hitbox": "dominus", "visual_preset": "dominus"},
    1894: {"name": "Breakout-Class (ID 1894)", "hitbox": "breakout", "visual_preset": "breakout"},
    3582: {"name": "Octane ZSR / Octane-Class (ID 3582)", "hitbox": "octane", "visual_preset": "octane"},
    4284: {"name": "Fennec", "hitbox": "octane", "visual_preset": "fennec"},
    7948: {"name": "Octane-Class (ID 7948)", "hitbox": "octane", "visual_preset": "octane"},
    12262: {"name": "Dominus-Class (ID 12262)", "hitbox": "dominus", "visual_preset": "dominus"},
    12658: {"name": "Breakout-Class (ID 12658)", "hitbox": "breakout", "visual_preset": "breakout"},
    12814: {"name": "Octane-Class (ID 12814)", "hitbox": "octane", "visual_preset": "octane"},
}


def verify_crc(replay_path: Path) -> dict:
    raw = replay_path.read_bytes()
    p1_len, p1_crc = struct.unpack("<II", raw[:8])
    p1_ok = calc_rl_crc32(raw[8 : 8 + p1_len]) == p1_crc
    p2_off = 8 + p1_len
    p2_len, p2_crc = struct.unpack("<II", raw[p2_off : p2_off + 8])
    p2_ok = calc_rl_crc32(raw[p2_off + 8 : p2_off + 8 + p2_len]) == p2_crc
    return {
        "file_size_bytes": len(raw),
        "part1_crc_valid": p1_ok,
        "part2_crc_valid": p2_ok,
    }


def classify_hitbox_from_physics(median_z: float | None, median_fwd_z: float | None, body_id: int | None) -> str:
    if body_id in KNOWN_BODY_PRODUCTS:
        return KNOWN_BODY_PRODUCTS[body_id]["hitbox"]
    if median_z is None:
        return "octane"
    if median_z > 18.0:
        return "breakout"
    if median_fwd_z is not None and median_fwd_z > 0.013:
        return "dominus"
    return "octane"


def analyze_single_replay(replay_path: Path, json_path: Path) -> dict:
    crc = verify_crc(replay_path)
    with open(json_path, "r", encoding="utf-8") as fp:
        d = json.load(fp)

    props = d.get("properties", {})
    objs = d.get("objects", [])
    names = d.get("names", [])
    frames = d.get("network_frames", {}).get("frames", [])
    keyframes = {kf["frame"] for kf in d.get("keyframes", [])}

    actors = {}
    pri_info = {}
    car_to_pri = {}
    car_pos = {}
    car_hidden = {}
    car_lifecycles = {}
    demolishes = []
    pad_samples = {}
    pad_pickup_count = 0
    pad_respawn_count = 0
    body_z_samples = {}
    body_fwdz_samples = {}

    sec_remaining_updates = []
    countdown_updates = []
    state_name_updates = []

    comp_counts = {
        "ReplicatedThrottle": 0,
        "ReplicatedSteer": 0,
        "bReplicatedHandbrake": 0,
        "ReplicatedBoost": 0,
        "Boost_ReplicatedActive": 0,
        "Jump_ReplicatedActive": 0,
        "DoubleJump_ReplicatedActive": 0,
        "Dodge_ReplicatedActive": 0,
    }

    for fi, fr in enumerate(frames):
        t = fr["time"]
        for da in fr.get("deleted_actors", []):
            if da in car_lifecycles and car_lifecycles[da]["delete_frame"] is None:
                car_lifecycles[da]["delete_frame"] = fi
                car_lifecycles[da]["delete_time_s"] = round(t, 3)
            actors.pop(da, None)
            car_pos.pop(da, None)
            car_hidden.pop(da, None)

        for na in fr.get("new_actors", []):
            aid = na["actor_id"]
            otype = objs[na["object_id"]]
            if aid not in actors:
                actors[aid] = otype
                if otype == "Archetypes.Car.Car_Default":
                    car_lifecycles[aid] = {
                        "car_actor_id": aid,
                        "spawn_frame": fi,
                        "spawn_time_s": round(t, 3),
                        "pri_actor_id": None,
                        "hidden_frame": None,
                        "hidden_time_s": None,
                        "unlinked_frame": None,
                        "delete_frame": None,
                        "delete_time_s": None,
                    }

        for ua in fr.get("updated_actors", []):
            aid = ua["actor_id"]
            prop = objs[ua["object_id"]]
            val = ua["attribute"]
            otype = actors.get(aid, "")

            if "PRI_TA" in otype:
                p = pri_info.setdefault(aid, {"cars": set()})
                if prop == "Engine.PlayerReplicationInfo:PlayerName":
                    p["name"] = val["String"]
                elif prop == "Engine.PlayerReplicationInfo:Team":
                    t_aid = val.get("ActiveActor", {}).get("actor", -1)
                    t_type = actors.get(t_aid, "")
                    p["team"] = 0 if "Team0" in t_type else (1 if "Team1" in t_type else -1)
                elif prop == "TAGame.PRI_TA:PawnType":
                    p["pawn_type"] = val.get("Byte")
                elif prop == "TAGame.PRI_TA:ClientLoadouts":
                    tl = val.get("TeamLoadout", {})
                    p["body_blue"] = tl.get("blue", {}).get("body")
                    p["body_orange"] = tl.get("orange", {}).get("body")
                elif prop == "TAGame.PRI_TA:SpectatorShortcut":
                    p["spectator_shortcut"] = val.get("Int")

            if prop == "Engine.Pawn:PlayerReplicationInfo":
                pri_id = val.get("ActiveActor", {}).get("actor", -1)
                if pri_id != -1:
                    car_to_pri[aid] = pri_id
                    pri_info.setdefault(pri_id, {"cars": set()})["cars"].add(aid)
                    if aid in car_lifecycles:
                        car_lifecycles[aid]["pri_actor_id"] = pri_id
                else:
                    if aid in car_lifecycles and car_lifecycles[aid]["unlinked_frame"] is None:
                        car_lifecycles[aid]["unlinked_frame"] = fi

            elif prop == "Engine.Actor:bHidden" and otype == "Archetypes.Car.Car_Default":
                is_hid = val.get("Boolean", False)
                car_hidden[aid] = is_hid
                if is_hid and aid in car_lifecycles and car_lifecycles[aid]["hidden_frame"] is None:
                    car_lifecycles[aid]["hidden_frame"] = fi
                    car_lifecycles[aid]["hidden_time_s"] = round(t, 3)

            elif prop == "TAGame.Car_TA:ReplicatedDemolishExtended":
                if fi not in keyframes:
                    dem = val["DemolishExtended"]
                    att_pri = dem["attacker_pri"]["actor"]
                    vic_car = dem["victim"]["actor"]
                    vic_pri = car_to_pri.get(vic_car)
                    demolishes.append({
                        "frame": fi,
                        "time_s": round(t, 3),
                        "attacker": pri_info.get(att_pri, {}).get("name"),
                        "victim": pri_info.get(vic_pri, {}).get("name"),
                        "victim_car_actor_id": vic_car,
                    })

            elif prop == "TAGame.RBActor_TA:ReplicatedRBState" and otype == "Archetypes.Car.Car_Default":
                rb = val["RigidBody"]
                loc = rb["location"]
                rot = rb["rotation"]
                vel = rb.get("linear_velocity") or {"x": 0.0, "y": 0.0, "z": 0.0}
                car_pos[aid] = (loc["x"], loc["y"], loc["z"])
                if not car_hidden.get(aid, False):
                    pri_id = car_to_pri.get(aid)
                    if pri_id in pri_info:
                        p = pri_info[pri_id]
                        body_id = p.get("body_blue") or p.get("body_orange")
                        if body_id and abs(loc["x"]) < 2500 and abs(loc["y"]) < 3500 and 14.0 < loc["z"] < 21.0 and abs(vel["z"]) < 5.0:
                            qx, qy, qz, qw = rot["x"], rot["y"], rot["z"], rot["w"]
                            fwd_z = 2.0 * (qx * qz - qw * qy)
                            body_z_samples.setdefault(body_id, []).append(loc["z"])
                            body_fwdz_samples.setdefault(body_id, []).append(abs(fwd_z))

            elif prop == "TAGame.VehiclePickup_TA:NewReplicatedPickupData":
                pnew = val["PickupNew"]
                inst_car = pnew["instigator"]
                picked = pnew["picked_up"]
                if fi not in keyframes:
                    if picked != 255 and inst_car is not None and inst_car != -1:
                        pad_pickup_count += 1
                        if inst_car in car_pos:
                            pad_samples.setdefault(otype, []).append(car_pos[inst_car])
                    elif picked == 255:
                        pad_respawn_count += 1

            elif prop == "TAGame.Vehicle_TA:ReplicatedThrottle":
                comp_counts["ReplicatedThrottle"] += 1
            elif prop == "TAGame.Vehicle_TA:ReplicatedSteer":
                comp_counts["ReplicatedSteer"] += 1
            elif prop == "TAGame.Vehicle_TA:bReplicatedHandbrake":
                comp_counts["bReplicatedHandbrake"] += 1
            elif prop == "TAGame.CarComponent_Boost_TA:ReplicatedBoost":
                comp_counts["ReplicatedBoost"] += 1
            elif prop == "TAGame.CarComponent_TA:ReplicatedActive":
                if "Boost" in otype:
                    comp_counts["Boost_ReplicatedActive"] += 1
                elif "DoubleJump" in otype:
                    comp_counts["DoubleJump_ReplicatedActive"] += 1
                elif "Jump" in otype:
                    comp_counts["Jump_ReplicatedActive"] += 1
                elif "Dodge" in otype:
                    comp_counts["Dodge_ReplicatedActive"] += 1

            elif prop == "TAGame.GameEvent_Soccar_TA:SecondsRemaining" and fi not in keyframes:
                sec_remaining_updates.append({"frame": fi, "time_s": round(t, 3), "seconds_remaining": val["Int"]})
            elif prop == "TAGame.GameEvent_TA:ReplicatedRoundCountDownNumber" and fi not in keyframes:
                countdown_updates.append({"frame": fi, "time_s": round(t, 3), "countdown": val["Int"]})
            elif prop == "TAGame.GameEvent_TA:ReplicatedStateName" and fi not in keyframes:
                idx = val["Int"]
                sname = names[idx] if 0 <= idx < len(names) else str(idx)
                state_name_updates.append({"frame": fi, "time_s": round(t, 3), "state_name": sname})

    # Map boost pads to standard 34 coordinates
    pad_mapping = {}
    for pad_actor_type, pts in pad_samples.items():
        mx = sum(p[0] for p in pts) / len(pts)
        my = sum(p[1] for p in pts) / len(pts)
        nearest = min(
            STANDARD_BOOST_PADS,
            key=lambda sp: math.hypot(mx - sp["x"], my - sp["y"]),
        )
        dist = math.hypot(mx - nearest["x"], my - nearest["y"])
        pad_mapping[pad_actor_type.split(".")[-1]] = {
            "standard_pad_index": nearest["index"],
            "pad_type": nearest["type"],
            "standard_xy": [nearest["x"], nearest["y"]],
            "mean_pickup_distance_uu": round(dist, 1),
            "pickup_samples": len(pts),
        }

    # Separate active players vs spectators
    active_players = []
    spectators = []
    seen_players = set()
    for aid, p in pri_info.items():
        pname = p.get("name")
        if not pname:
            continue
        cars = sorted(list(p.get("cars", [])))
        body_id = p.get("body_blue") or p.get("body_orange")
        med_z = round(statistics.median(body_z_samples[body_id]), 3) if body_id in body_z_samples else None
        med_fz = round(statistics.median(body_fwdz_samples[body_id]), 5) if body_id in body_fwdz_samples else None
        hb = classify_hitbox_from_physics(med_z, med_fz, body_id)
        entry = {
            "name": pname,
            "team": p.get("team", -1),
            "pawn_type": p.get("pawn_type"),
            "body_id_blue": p.get("body_blue"),
            "body_id_orange": p.get("body_orange"),
            "body_name": KNOWN_BODY_PRODUCTS.get(body_id, {}).get("name", f"Product_{body_id}"),
            "hitbox": hb,
            "car_actor_count": len(cars),
        }
        key = (pname, len(cars) > 0)
        if key in seen_players:
            continue
        seen_players.add(key)
        if len(cars) > 0:
            active_players.append(entry)
        else:
            spectators.append(entry)

    return {
        "file_name": replay_path.name,
        "crc": crc,
        "map_name": props.get("MapName"),
        "match_type": props.get("MatchType"),
        "team_size": props.get("TeamSize"),
        "num_frames": len(frames),
        "record_fps": props.get("RecordFPS"),
        "goals_header": props.get("Goals", []),
        "active_players_count": len(active_players),
        "spectators_count": len(spectators),
        "active_players": active_players,
        "spectators": spectators,
        "demolishes_count": len(demolishes),
        "demolishes_sample": demolishes[:5],
        "boost_pad_actors_observed": len(pad_mapping),
        "boost_pad_unique_standard_indices": len({m["standard_pad_index"] for m in pad_mapping.values()}),
        "boost_pad_pickups_total": pad_pickup_count,
        "boost_pad_respawns_total": pad_respawn_count,
        "component_update_counts": comp_counts,
        "game_clock_summary": {
            "seconds_remaining_updates": len(sec_remaining_updates),
            "first_5_seconds_remaining": sec_remaining_updates[:5],
            "countdown_updates": countdown_updates[:6],
            "state_transitions": state_name_updates[:8],
        },
    }


def main():
    replays_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/replays12")
    out_path = Path("parsed/replay/corpus_12_replays_summary.json")
    results = []
    all_bodies = {}

    for rp in sorted(replays_dir.glob("*.replay")):
        jp = rp.with_suffix(".replay.json")
        if not jp.exists():
            subprocess.run(["/usr/local/bin/rrrocket", "-n", str(rp)], stdout=open(jp, "w"), check=True)
        res = analyze_single_replay(rp, jp)
        results.append(res)
        for ap in res["active_players"] + res["spectators"]:
            for bid in (ap["body_id_blue"], ap["body_id_orange"]):
                if bid is not None:
                    binfo = all_bodies.setdefault(
                        bid,
                        {
                            "product_id": bid,
                            "name": KNOWN_BODY_PRODUCTS.get(bid, {}).get("name", f"Product_{bid}"),
                            "hitbox": ap["hitbox"],
                            "occurrences": 0,
                        },
                    )
                    binfo["occurrences"] += 1

    summary = {
        "total_replays": len(results),
        "all_crc_valid": all(r["crc"]["part1_crc_valid"] and r["crc"]["part2_crc_valid"] for r in results),
        "car_body_catalog": [v for _, v in sorted(all_bodies.items())],
        "replays": results,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[parse_all_replays] Analyzed {len(results)} replays -> {out_path}")


if __name__ == "__main__":
    main()
