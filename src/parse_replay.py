#!/usr/bin/env python3
"""
Rocket League Replay (.replay) Deep Parser & NetStream Telemetry Extractor.
Uses rrrocket (boxcars) JSON output + custom binary header & CRC verification +
CHN_Stadium_P map boost pad layout to extract:
- Header & Content CRC32 verification (Seed: 0xEFCBF201, Poly: 0x04C11DB7)
- Server & Match metadata (ServerName, GameServerID, Region, MatchGUID, BuildVersion, BakkesMod logs)
- Full Roster of all 14 connected accounts (6 RLCS Players + 2 RLCS Referees + 6 Broadcast Observers)
- Full Loadout Item IDs, Paint IDs, Team Edition IDs, User Colors (ARGB hex), and Titles
- Camera Settings (FOV, Height, Angle, Distance, Stiffness, Swivel, Transition) & Steering Sensitivity
- Timeline of Goals, Saves, Epic Saves, Demolishes (with 3D attacker/victim velocities), Boost Pad Pickups
- Aggregated Per-Player Physics & Boost Telemetry (Speed, Elevation/Airborne %, Boost Pad Big/Small/Stolen counts)
"""

import json
import math
import struct
import datetime
import csv
import os
from parse_tem import calc_rl_crc32

REPLAY_PATH = "raw/RLorig/3adc59ea-2a3d-49b0-bd92-15f0d27bb3f6.replay"
FULL_JSON_PATH = "/tmp/rldump/replay_full.json"
HEADER_JSON_PATH = "/tmp/rldump/replay_header.json"
PADS_JSON_PATH = "src/CHN_Stadium_P.json"

BODY_NAMES = {
    23: "Octane",
    1568: "Dominus",
    4284: "Fennec"
}

PAINT_NAMES = {
    1: "Crimson", 2: "Lime", 3: "Black", 4: "Sky Blue", 5: "Cobalt",
    6: "Burnt Sienna", 7: "Forest Green", 8: "Purple", 9: "Pink",
    10: "Orange", 11: "Grey", 12: "Titanium White", 13: "Saffron", 14: "Gold"
}


def verify_replay_crc(filepath: str) -> dict:
    with open(filepath, "rb") as fp:
        raw = fp.read()
    p1_len, p1_crc = struct.unpack("<II", raw[:8])
    p1_data = raw[8:8 + p1_len]
    p1_calc = calc_rl_crc32(p1_data)

    p2_offset = 8 + p1_len
    p2_len, p2_crc = struct.unpack("<II", raw[p2_offset:p2_offset + 8])
    p2_data = raw[p2_offset + 8:p2_offset + 8 + p2_len]
    p2_calc = calc_rl_crc32(p2_data)

    return {
        "file_size_bytes": len(raw),
        "part1_header": {
            "length_bytes": p1_len,
            "stored_crc32": f"0x{p1_crc:08X}",
            "calculated_crc32": f"0x{p1_calc:08X}",
            "crc_valid": p1_crc == p1_calc
        },
        "part2_content": {
            "length_bytes": p2_len,
            "stored_crc32": f"0x{p2_crc:08X}",
            "calculated_crc32": f"0x{p2_calc:08X}",
            "crc_valid": p2_crc == p2_calc
        }
    }


def main():
    crc_info = verify_replay_crc(REPLAY_PATH)
    with open(HEADER_JSON_PATH, "r", encoding="utf-8") as fp:
        header_data = json.load(fp)
    with open(FULL_JSON_PATH, "r", encoding="utf-8") as fp:
        rep = json.load(fp)
    with open(PADS_JSON_PATH, "r", encoding="utf-8") as fp:
        pad_info = {p["Name"]: p for p in json.load(fp)}

    objs = rep["objects"]
    names = rep["names"]
    frames = rep["network_frames"]["frames"]
    keyframes = {kf["frame"] for kf in rep["keyframes"]}

    # Copy header JSON to parsed/replay/
    with open("parsed/replay/replay_header.json", "w", encoding="utf-8") as fp:
        json.dump(header_data, fp, indent=2, ensure_ascii=False)

    # Track actors and attributes across all 9,379 frames
    actors = {}
    pri_actors = {}
    cams = {}
    pri_to_cam = {}
    gri_props = {}
    reservations = []
    team_props = {}
    game_event_props = {}
    car_to_pri = {}
    boost_to_car = {}
    pri_names = {}
    team_paints = {}

    stat_events = []
    demolishes = []
    explosions = []
    pad_state = {}
    pad_events = []

    player_pads = {p: {"big": 0, "small": 0, "stolen_big": 0, "stolen_small": 0, "total_boost_from_pads": 0}
                   for p in ["vatira", "Atow", "juicy", "dralii", "Rw9", "Kiileerrz"]}
    player_team = {"vatira": 0, "Atow": 0, "juicy": 0, "dralii": 1, "Rw9": 1, "Kiileerrz": 1}

    ball_states = []
    car_states = {}
    boost_updates = {}

    for fi, fr in enumerate(frames):
        t = fr["time"]
        for da in fr.get("deleted_actors", []):
            actors.pop(da, None)
        for na in fr.get("new_actors", []):
            aid = na["actor_id"]
            otype = objs[na["object_id"]]
            actors[aid] = {"type": otype, "props": {}}
            if "PRI_TA" in otype:
                pri_actors.setdefault(aid, {})

        for ua in fr.get("updated_actors", []):
            aid = ua["actor_id"]
            prop = objs[ua["object_id"]]
            val = ua["attribute"]
            atype = actors.get(aid, {}).get("type", "")

            if aid in actors:
                actors[aid]["props"][prop] = val
            if aid in pri_actors:
                pri_actors[aid][prop] = val

            if prop == "Engine.PlayerReplicationInfo:PlayerName":
                pri_names[aid] = val["String"]
            elif prop == "Engine.Pawn:PlayerReplicationInfo":
                pri_id = val.get("ActiveActor", {}).get("actor")
                if pri_id is not None and pri_id != -1:
                    car_to_pri[aid] = pri_id
            elif prop == "TAGame.CarComponent_TA:Vehicle":
                car_id = val.get("ActiveActor", {}).get("actor")
                if car_id is not None and car_id != -1:
                    boost_to_car[aid] = car_id
            elif prop == "TAGame.CameraSettingsActor_TA:ProfileSettings":
                cams[aid] = val["CamSettings"]
            elif prop == "TAGame.CameraSettingsActor_TA:PRI":
                pri_id = val.get("ActiveActor", {}).get("actor")
                if pri_id is not None:
                    pri_to_cam[pri_id] = aid
            elif prop == "ProjectX.GRI_X:Reservations" and fi == 0:
                reservations.append(val["Reservation"])
            elif "GRI" in prop or "GameReplicationInfo" in prop:
                if prop != "ProjectX.GRI_X:Reservations":
                    gri_props[prop] = val
            elif "Team" in atype:
                team_props.setdefault(atype, {})[prop] = val
            elif "GameEvent" in atype:
                game_event_props[prop] = val

            if prop == "TAGame.Car_TA:TeamPaint":
                pri_id = car_to_pri.get(aid)
                pname = pri_names.get(pri_id)
                if pname:
                    team_paints[pname] = val["TeamPaint"]
            elif prop == "TAGame.GameEvent_Soccar_TA:ReplicatedStatEvent":
                oid = val["StatEvent"]["object_id"]
                if 0 <= oid < len(objs) and fi not in keyframes:
                    stat_events.append({"frame": fi, "time_s": round(t, 3), "event": objs[oid]})
            elif prop == "TAGame.Ball_TA:ReplicatedExplosionDataExtended":
                if fi not in keyframes:
                    exp = val["ExtendedExplosion"]
                    scorer_pri = exp["secondary_actor"]
                    explosions.append({
                        "frame": fi,
                        "time_s": round(t, 3),
                        "scorer": pri_names.get(scorer_pri, f"actor_{scorer_pri}"),
                        "goal_explosion_object": objs[exp["explosion"]["actor"]] if 0 <= exp["explosion"]["actor"] < len(objs) else exp["explosion"]["actor"],
                        "location": exp["explosion"]["location"]
                    })
            elif prop == "TAGame.Car_TA:ReplicatedDemolishExtended":
                d = val["DemolishExtended"]
                att_pri = d["attacker_pri"]["actor"]
                vic_car = d["victim"]["actor"]
                vic_pri = car_to_pri.get(vic_car)
                att_name = pri_names.get(att_pri, f"pri_{att_pri}")
                vic_name = pri_names.get(vic_pri, f"car_{vic_car}")
                av = d["attacker_velocity"]
                vv = d["victim_velocity"]
                att_speed = round(math.sqrt(av["x"]**2 + av["y"]**2 + av["z"]**2) * 100.0, 2)
                vic_speed = round(math.sqrt(vv["x"]**2 + vv["y"]**2 + vv["z"]**2) * 100.0, 2)
                if not demolishes or (demolishes[-1]["attacker"] != att_name or demolishes[-1]["victim"] != vic_name or abs(t - demolishes[-1]["time_s"]) > 5.0):
                    demolishes.append({
                        "frame": fi,
                        "time_s": round(t, 3),
                        "attacker": att_name,
                        "victim": vic_name,
                        "attacker_velocity": av,
                        "attacker_speed_uu_s": att_speed,
                        "victim_velocity": vv,
                        "victim_speed_uu_s": vic_speed
                    })
            elif prop == "TAGame.VehiclePickup_TA:NewReplicatedPickupData":
                pnew = val["PickupNew"]
                inst_car = pnew["instigator"]
                picked = pnew["picked_up"]
                pad_name = actors.get(aid, {}).get("type", "")
                prev = pad_state.get(pad_name, (None, 255))
                if picked != 255 and inst_car is not None and prev != (inst_car, picked) and fi not in keyframes:
                    pri_id = car_to_pri.get(inst_car)
                    pname = pri_names.get(pri_id)
                    if pname in player_pads and pad_name in pad_info:
                        pinfo = pad_info[pad_name]
                        is_big = pinfo["BoostAmount"] > 0.5
                        y = pinfo["Location"]["Y"]
                        is_stolen = (player_team[pname] == 0 and y > 1000) or (player_team[pname] == 1 and y < -1000)
                        if is_big:
                            player_pads[pname]["big"] += 1
                            player_pads[pname]["total_boost_from_pads"] += 100
                            if is_stolen:
                                player_pads[pname]["stolen_big"] += 1
                        else:
                            player_pads[pname]["small"] += 1
                            player_pads[pname]["total_boost_from_pads"] += 12
                            if is_stolen:
                                player_pads[pname]["stolen_small"] += 1
                        pad_events.append({
                            "frame": fi,
                            "time_s": round(t, 3),
                            "player": pname,
                            "pad_name": pad_name.split(".")[-1],
                            "pad_type": "Big (100)" if is_big else "Small (12)",
                            "location": pinfo["Location"],
                            "is_stolen": is_stolen
                        })
                pad_state[pad_name] = (inst_car, picked)
            elif prop == "TAGame.CarComponent_Boost_TA:ReplicatedBoost":
                car_id = boost_to_car.get(aid)
                pri_id = car_to_pri.get(car_id)
                pname = pri_names.get(pri_id)
                if pname:
                    b_amt = round(val["ReplicatedBoost"]["boost_amount"] / 255.0 * 100.0, 1)
                    boost_updates.setdefault(pname, []).append((fi, round(t, 3), b_amt))
            elif prop == "TAGame.RBActor_TA:ReplicatedRBState":
                rb = val["RigidBody"]
                loc = rb["location"]
                lin = rb.get("linear_velocity") or {"x": 0.0, "y": 0.0, "z": 0.0}
                if "Ball" in atype:
                    ball_states.append((fi, round(t, 4), loc["x"], loc["y"], loc["z"], lin["x"], lin["y"], lin["z"]))
                elif "Car" in atype:
                    pri_id = car_to_pri.get(aid)
                    pname = pri_names.get(pri_id)
                    if pname:
                        car_states.setdefault(pname, []).append((fi, round(t, 4), loc["x"], loc["y"], loc["z"], lin["x"], lin["y"], lin["z"]))

    # Build complete participants table by PlayerID
    by_pid = {}
    for aid, p in pri_actors.items():
        pid = p.get("Engine.PlayerReplicationInfo:PlayerID", {}).get("Int")
        if pid is not None:
            by_pid.setdefault(pid, {"actor_ids": [], "props": {}})
            if aid not in by_pid[pid]["actor_ids"]:
                by_pid[pid]["actor_ids"].append(aid)
            by_pid[pid]["props"].update(p)

    participants = []
    for pid, info in sorted(by_pid.items()):
        p = info["props"]
        pname = p.get("Engine.PlayerReplicationInfo:PlayerName", {}).get("String")
        title_idx = p.get("TAGame.PRI_TA:Title", {}).get("Int")
        title_str = names[title_idx] if title_idx is not None and 0 <= title_idx < len(names) else None
        cam_actor = p.get("TAGame.PRI_TA:PersistentCamera", {}).get("ActiveActor", {}).get("actor")
        cam_cfg = cams.get(cam_actor)
        if not cam_cfg:
            for aid in info["actor_ids"]:
                if aid in pri_to_cam and pri_to_cam[aid] in cams:
                    cam_cfg = cams[pri_to_cam[aid]]
        team_actor = p.get("Engine.PlayerReplicationInfo:Team", {}).get("ActiveActor", {}).get("actor")
        role = "Player (Team 0 - KARMINE CORP)" if team_actor == 45 else ("Player (Team 1 - TEAM FALCONS)" if team_actor == 44 else "Spectator / Referee / Observer")
        loadout_blue = p.get("TAGame.PRI_TA:ClientLoadouts", {}).get("TeamLoadout", {}).get("blue", {})
        loadout_orange = p.get("TAGame.PRI_TA:ClientLoadouts", {}).get("TeamLoadout", {}).get("orange", {})
        online_blue = p.get("TAGame.PRI_TA:ClientLoadoutsOnline", {}).get("LoadoutsOnline", {}).get("blue", [])

        # Parse online attributes cleanly
        decoded_online_attrs = []
        for slot_idx, slot_attrs in enumerate(online_blue):
            for attr in slot_attrs:
                obj_name = objs[attr["object_ind"]] if 0 <= attr["object_ind"] < len(objs) else str(attr["object_ind"])
                val = attr["value"]
                if "NewPaint" in val:
                    val = {"paint_id": val["NewPaint"], "paint_name": PAINT_NAMES.get(val["NewPaint"], "Unknown")}
                elif "NewColor" in val:
                    c = val["NewColor"]
                    val = {"raw_uint32": c, "argb_hex": f"#{c:08X}"}
                decoded_online_attrs.append({"slot_index": slot_idx, "attribute_class": obj_name, "value": val})

        participant_entry = {
            "player_id": pid,
            "name": pname,
            "anonymized_name": p.get("TAGame.PRI_TA:AnonymizedName", {}).get("String"),
            "role": role,
            "platform_unique_id": p.get("Engine.PlayerReplicationInfo:UniqueId", {}).get("UniqueId"),
            "epic_puid": p.get("TAGame.PRI_TA:EpicPUID", {}).get("String"),
            "club_id": p.get("TAGame.PRI_TA:ClubID", {}).get("Int64"),
            "spectator_shortcut": p.get("TAGame.PRI_TA:SpectatorShortcut", {}).get("Int"),
            "steering_sensitivity": p.get("TAGame.PRI_TA:SteeringSensitivity", {}).get("Float"),
            "title": title_str,
            "ping_raw_byte": p.get("Engine.PlayerReplicationInfo:Ping", {}).get("Byte"),
            "camera_settings": cam_cfg,
            "loadout_blue": {
                **loadout_blue,
                "body_name": BODY_NAMES.get(loadout_blue.get("body"), f"ID_{loadout_blue.get('body')}")
            } if loadout_blue else None,
            "loadout_orange": {
                **loadout_orange,
                "body_name": BODY_NAMES.get(loadout_orange.get("body"), f"ID_{loadout_orange.get('body')}")
            } if loadout_orange else None,
            "online_product_attributes": decoded_online_attrs,
            "team_paint": team_paints.get(pname),
        }

        if pname in car_states:
            st = car_states[pname]
            speeds = [math.sqrt(vx**2 + vy**2 + vz**2) for _, _, _, _, _, vx, vy, vz in st]
            supersonic_count = sum(1 for s in speeds if s >= 2200.0)
            airborne_count = sum(1 for _, _, _, _, z, _, _, _ in st if z > 25.0)
            high_aerial_count = sum(1 for _, _, _, _, z, _, _, _ in st if z > 300.0)
            offense_half_count = sum(1 for _, _, _, y, _, _, _, _ in st if (y > 0 if player_team[pname] == 0 else y < 0))
            b_list = [b for _, _, b in boost_updates.get(pname, [])]
            participant_entry["telemetry_summary"] = {
                "position_samples": len(st),
                "avg_speed_uu_s": round(sum(speeds) / len(speeds), 2),
                "avg_speed_kph": round((sum(speeds) / len(speeds)) * 0.036, 2),
                "max_speed_uu_s": round(max(speeds), 2),
                "supersonic_pct": round(supersonic_count / len(st) * 100.0, 2),
                "avg_elevation_z": round(sum(z for _, _, _, _, z, _, _, _ in st) / len(st), 2),
                "max_elevation_z": round(max(z for _, _, _, _, z, _, _, _ in st), 2),
                "airborne_pct": round(airborne_count / len(st) * 100.0, 2),
                "high_aerial_pct": round(high_aerial_count / len(st) * 100.0, 2),
                "offensive_half_pct": round(offense_half_count / len(st) * 100.0, 2),
                "avg_boost_amount": round(sum(b_list) / len(b_list), 1) if b_list else None,
                "boost_pads": player_pads.get(pname)
            }
            participant_entry["match_stats"] = {
                "score": p.get("TAGame.PRI_TA:MatchScore", {}).get("Int", 0),
                "goals": p.get("TAGame.PRI_TA:MatchGoals", {}).get("Int", 0),
                "assists": p.get("TAGame.PRI_TA:MatchAssists", {}).get("Int", 0),
                "saves": p.get("TAGame.PRI_TA:MatchSaves", {}).get("Int", 0),
                "shots": p.get("TAGame.PRI_TA:MatchShots", {}).get("Int", 0),
                "demolishes_inflicted": p.get("TAGame.PRI_TA:MatchDemolishes", {}).get("Int", 0),
                "times_demolished": p.get("TAGame.PRI_TA:SelfDemolitions", {}).get("Int", 0),
                "total_game_time_played_s": p.get("TAGame.PRI_TA:TotalGameTimePlayed", {}).get("Float")
            }

        participants.append(participant_entry)

    # Save comprehensive analytics JSON
    analytics = {
        "crc_verification": crc_info,
        "match_metadata": {
            "replay_name": header_data["properties"].get("ReplayName"),
            "replay_id": header_data["properties"].get("Id"),
            "match_guid": header_data["properties"].get("MatchGUID"),
            "build_version": header_data["properties"].get("BuildVersion"),
            "build_id": header_data["properties"].get("BuildID"),
            "changelist": header_data["properties"].get("Changelist"),
            "engine_version": header_data["major_version"],
            "licensee_version": header_data["minor_version"],
            "net_version": header_data["net_version"],
            "replay_version": header_data["properties"].get("ReplayVersion"),
            "game_version": header_data["properties"].get("GameVersion"),
            "map_name": header_data["properties"].get("MapName"),
            "match_type": header_data["properties"].get("MatchType"),
            "date_local": header_data["properties"].get("Date"),
            "game_start_time_iso": header_data["debug_info"][1]["text"] if len(header_data.get("debug_info", [])) > 1 else None,
            "match_start_epoch": int(header_data["properties"].get("MatchStartEpoch", 0)),
            "match_start_utc": datetime.datetime.fromtimestamp(int(header_data["properties"].get("MatchStartEpoch", 0)), datetime.timezone.utc).isoformat(),
            "total_seconds_played": header_data["properties"].get("TotalSecondsPlayed"),
            "record_fps": header_data["properties"].get("RecordFPS"),
            "num_frames": header_data["properties"].get("NumFrames"),
            "max_channels": header_data["properties"].get("MaxChannels"),
            "server_name": gri_props.get("Engine.GameReplicationInfo:ServerName", {}).get("String"),
            "game_server_id": gri_props.get("ProjectX.GRI_X:GameServerID", {}).get("String"),
            "server_region": gri_props.get("ProjectX.GRI_X:ReplicatedServerRegion", {}).get("String"),
            "playlist_id": gri_props.get("ProjectX.GRI_X:ReplicatedGamePlaylist", {}).get("Int"),
            "mutator_index": gri_props.get("ProjectX.GRI_X:ReplicatedGameMutatorIndex", {}).get("Int"),
            "team_0_name": team_props.get("Archetypes.Teams.Team0", {}).get("TAGame.Team_TA:CustomTeamName", {}).get("String"),
            "team_0_score": header_data["properties"].get("Team0Score", 0),
            "team_1_name": team_props.get("Archetypes.Teams.Team1", {}).get("TAGame.Team_TA:CustomTeamName", {}).get("String"),
            "team_1_score": header_data["properties"].get("Team1Score", 0),
            "bakkesmod_debug_info": header_data.get("debug_info", [])
        },
        "lobby_reservations_frame0": reservations,
        "participants": participants,
        "events": {
            "goals": explosions,
            "demolishes": demolishes,
            "stat_events": stat_events,
            "tick_marks": header_data.get("tick_marks", []),
            "highlights": header_data["properties"].get("HighLights", []),
            "boost_pad_pickups_count": len(pad_events),
            "boost_pad_pickups_sample": pad_events[:50]
        }
    }

    with open("parsed/replay/replay_analytics.json", "w", encoding="utf-8") as fp:
        json.dump(analytics, fp, indent=2, ensure_ascii=False)

    with open("parsed/replay/boost_pad_pickups.json", "w", encoding="utf-8") as fp:
        json.dump(pad_events, fp, indent=2, ensure_ascii=False)

    # Save Ball trajectory CSV
    with open("parsed/replay/ball_trajectory.csv", "w", newline="", encoding="utf-8") as fp:
        writer = csv.writer(fp)
        writer.writerow(["frame", "time_s", "x", "y", "z", "vx", "vy", "vz", "speed_uu_s"])
        for fi, t, x, y, z, vx, vy, vz in ball_states:
            spd = round(math.sqrt(vx**2 + vy**2 + vz**2), 2)
            writer.writerow([fi, t, round(x, 2), round(y, 2), round(z, 2), round(vx, 2), round(vy, 2), round(vz, 2), spd])

    print("Saved parsed/replay/replay_analytics.json, boost_pad_pickups.json, ball_trajectory.csv")


if __name__ == "__main__":
    main()
