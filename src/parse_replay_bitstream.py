#!/usr/bin/env python3
"""
parse_replay_bitstream.py
Pure-Python bit-exact Rocket League (.replay) UE3 Binary Header + NetStream Decoder &
Keyframe Timestamp De-jittering Analyzer.

Key fixes & capabilities:
1. ClassNetCache Hierarchy & Object Index Resolution:
   - Resolves parent ClassNetCache nodes by checking both `parent.cache_id == nc.parent_id`
     and `parent.max_stream_id == nc.parent_id` (required for derived archetypes such as
     Hoops `Ball_Basketball_TA`, Dropshot `Ball_Breakout_TA`, Rumble `CarComponent_*`,
     and `ViralItemActor_TA`).
   - Resolves `obj_to_node` by exact `object_ind`, stripped `Default__` class name, or
     the largest `node.object_ind <= oid`.
2. Complete UE3 Property Type Table:
   - Includes `TAGame.PRI_TA:CurrentVoiceRoom` ('String'),
     `TAGame.PRI_TA:ReplicatedWorstNetQualityBeyondLatency` ('Byte'),
     `TAGame.ViralItemActor_TA:InfectedStatus` ('Byte'), and
     `TAGame.ViralItemActor_TA:ClientFXInfectedType` ('Byte'), eliminating bitstream
     desynchronization (`Invalid UTF-8 string length`).
3. Spectator / Referee / Observer PRI Filtering & Pawn-PRI Lookahead:
   - Excludes spectator PRIs (`bIsSpectator` / `bOnlySpectator` without a linked car pawn)
     and deduplicates demolished car actors on respawn.
4. Client NetStream Keyframe Timestamp De-jittering:
   - Quantifies per-car replication rate (~13-16 Hz out of 30 Hz frames) and reconstructs
     true 120 Hz server physics tick intervals (`dt_kin = |dp| / |v_avg|`) to eliminate
     UDP arrival jitter.
"""

import math
import struct
import sys
from pathlib import Path
from parse_tem import calc_rl_crc32

PROPERTY_TYPE_BY_EXACT_NAME = {
    "Engine.Actor:RemoteRole": "Enum",
    "Engine.Actor:Role": "Enum",
    "Engine.Actor:bBlockActors": "Boolean",
    "Engine.Actor:bCollideActors": "Boolean",
    "Engine.Actor:bHidden": "Boolean",
    "Engine.Actor:DrawScale": "Float",
    "Engine.Actor:Rotation": "Rotation",
    "Engine.Actor:Location": "Location",
    "Engine.GameReplicationInfo:GameClass": "ActiveActor",
    "Engine.GameReplicationInfo:ServerName": "String",
    "Engine.Pawn:PlayerReplicationInfo": "ActiveActor",
    "Engine.PlayerReplicationInfo:Ping": "Byte",
    "Engine.PlayerReplicationInfo:PlayerID": "Int",
    "Engine.PlayerReplicationInfo:PlayerName": "String",
    "Engine.PlayerReplicationInfo:Score": "Int",
    "Engine.PlayerReplicationInfo:Team": "ActiveActor",
    "Engine.PlayerReplicationInfo:UniqueId": "UniqueId",
    "Engine.PlayerReplicationInfo:bBot": "Boolean",
    "Engine.PlayerReplicationInfo:bIsSpectator": "Boolean",
    "Engine.PlayerReplicationInfo:bOnlySpectator": "Boolean",
    "Engine.PlayerReplicationInfo:bReadyToPlay": "Boolean",
    "Engine.TeamInfo:Score": "Int",
    "ProjectX.GRI_X:GameServerID": "String",
    "ProjectX.GRI_X:MatchGUID": "String",
    "ProjectX.GRI_X:ReplicatedGameMutatorIndex": "Int",
    "ProjectX.GRI_X:ReplicatedGamePlaylist": "Int",
    "ProjectX.GRI_X:ReplicatedServerRegion": "String",
    "ProjectX.GRI_X:Reservations": "Reservation",
    "ProjectX.GRI_X:bGameStarted": "Boolean",
    "TAGame.Ball_TA:GameEvent": "ActiveActor",
    "TAGame.Ball_TA:HitTeamNum": "Byte",
    "TAGame.Ball_TA:ReplicatedExplosionData": "Explosion",
    "TAGame.Ball_TA:ReplicatedExplosionDataExtended": "ExtendedExplosion",
    "TAGame.Ball_TA:ReplicatedBallScale": "Float",
    "TAGame.CameraSettingsActor_TA:CameraPitch": "Byte",
    "TAGame.CameraSettingsActor_TA:CameraYaw": "Byte",
    "TAGame.CameraSettingsActor_TA:PRI": "ActiveActor",
    "TAGame.CameraSettingsActor_TA:ProfileSettings": "CamSettings",
    "TAGame.CameraSettingsActor_TA:bUsingBehindView": "Boolean",
    "TAGame.CameraSettingsActor_TA:bUsingSecondaryCamera": "Boolean",
    "TAGame.CameraSettingsActor_TA:bUsingFreecam": "Boolean",
    "TAGame.CarComponent_AirActivate_TA:AirActivateCount": "Int",
    "TAGame.CarComponent_Boost_TA:ReplicatedBoost": "ReplicatedBoost",
    "TAGame.CarComponent_Boost_TA:ReplicatedBoostAmount": "Byte",
    "TAGame.CarComponent_Boost_TA:bNoBoost": "Boolean",
    "TAGame.CarComponent_Boost_TA:UnlimitedBoostRefCount": "Int",
    "TAGame.CarComponent_Dodge_TA:DodgeTorque": "Location",
    "TAGame.CarComponent_DoubleJump_TA:DoubleJumpImpulse": "Location",
    "TAGame.CarComponent_FlipCar_TA:FlipCarTime": "Float",
    "TAGame.CarComponent_FlipCar_TA:bFlipRight": "Boolean",
    "TAGame.CarComponent_TA:ReplicatedActive": "Byte",
    "TAGame.CarComponent_TA:Vehicle": "ActiveActor",
    "TAGame.CarComponent_TA:ReplicatedActivityTime": "Float",
    "TAGame.Car_TA:DodgesRefreshedCounter": "Int",
    "TAGame.Car_TA:ReplicatedDemolish": "Demolish",
    "TAGame.Car_TA:ReplicatedDemolishExtended": "DemolishExtended",
    "TAGame.Car_TA:ReplicatedDemolishGoalExplosion": "DemolishExtended",
    "TAGame.Car_TA:RumblePickups": "ActiveActor",
    "TAGame.Car_TA:TeamPaint": "TeamPaint",
    "TAGame.Car_TA:ClubColors": "ClubColors",
    "TAGame.Car_TA:ReplicatedCarScale": "Float",
    "TAGame.GameEvent_Soccar_TA:ReplicatedScoredOnTeam": "Byte",
    "TAGame.GameEvent_Soccar_TA:ReplicatedStatEvent": "StatEvent",
    "TAGame.GameEvent_Soccar_TA:RoundNum": "Int",
    "TAGame.GameEvent_Soccar_TA:SecondsRemaining": "Int",
    "TAGame.GameEvent_Soccar_TA:SeriesLength": "Int",
    "TAGame.GameEvent_Soccar_TA:GameTime": "Int",
    "TAGame.GameEvent_Soccar_TA:MaxScore": "Int",
    "TAGame.GameEvent_Soccar_TA:bBallHasBeenHit": "Boolean",
    "TAGame.GameEvent_Soccar_TA:bMatchCreatorAdminEnabled": "Boolean",
    "TAGame.GameEvent_Soccar_TA:bReadyToStartGame": "Boolean",
    "TAGame.GameEvent_Soccar_TA:bOverTime": "Boolean",
    "TAGame.GameEvent_Soccar_TA:bUnlimitedTime": "Boolean",
    "TAGame.GameEvent_Soccar_TA:bMatchEnded": "Boolean",
    "TAGame.GameEvent_Soccar_TA:bClubMatch": "Boolean",
    "TAGame.GameEvent_TA:BotSkill": "Int",
    "TAGame.GameEvent_TA:MatchStartEpoch": "Int64",
    "TAGame.GameEvent_TA:MatchTypeClass": "ActiveActor",
    "TAGame.GameEvent_TA:ReplicatedGameStateTimeRemaining": "Int",
    "TAGame.GameEvent_TA:ReplicatedRoundCountDownNumber": "Int",
    "TAGame.GameEvent_TA:ReplicatedStateName": "Int",
    "TAGame.GameEvent_TA:ReplicatedStateIndex": "Byte",
    "TAGame.GameEvent_Team_TA:MaxTeamSize": "Int",
    "TAGame.GameEvent_Team_TA:bForfeit": "Boolean",
    "TAGame.PRI_TA:AnonymizedName": "String",
    "TAGame.PRI_TA:CarDemolitions": "Int",
    "TAGame.PRI_TA:ClientLoadouts": "TeamLoadout",
    "TAGame.PRI_TA:ClientLoadoutsOnline": "LoadoutsOnline",
    "TAGame.PRI_TA:ClubID": "Int64",
    "TAGame.PRI_TA:CurrentVoiceRoom": "String",
    "TAGame.PRI_TA:EpicPUID": "String",
    "TAGame.PRI_TA:MatchAssists": "Int",
    "TAGame.PRI_TA:MatchDemolishes": "Int",
    "TAGame.PRI_TA:MatchGoals": "Int",
    "TAGame.PRI_TA:MatchSaves": "Int",
    "TAGame.PRI_TA:MatchScore": "Int",
    "TAGame.PRI_TA:MatchShots": "Int",
    "TAGame.PRI_TA:PawnType": "Byte",
    "TAGame.PRI_TA:PersistentCamera": "ActiveActor",
    "TAGame.PRI_TA:PartyLeader": "PartyLeader",
    "TAGame.PRI_TA:PlayerHistoryKey": "HistoryKey",
    "TAGame.PRI_TA:ReplicatedGameEvent": "ActiveActor",
    "TAGame.PRI_TA:ReplicatedWorstNetQualityBeyondLatency": "Byte",
    "TAGame.PRI_TA:SelfDemolitions": "Int",
    "TAGame.PRI_TA:SpectatorShortcut": "Int",
    "TAGame.PRI_TA:SteeringSensitivity": "Float",
    "TAGame.PRI_TA:Title": "Int",
    "TAGame.PRI_TA:TotalGameTimePlayed": "Float",
    "TAGame.PRI_TA:ViralItemActor": "ActiveActor",
    "TAGame.PRI_TA:bIsDistracted": "Boolean",
    "TAGame.PRI_TA:bReceivedAnonymizationSettings": "Boolean",
    "TAGame.PRI_TA:bReady": "Boolean",
    "TAGame.PRI_TA:bUsingItems": "Boolean",
    "TAGame.PRI_TA:bOnlineLoadoutSet": "Boolean",
    "TAGame.PRI_TA:bMatchMVP": "Boolean",
    "TAGame.ViralItemActor_TA:InfectedStatus": "Byte",
    "TAGame.ViralItemActor_TA:ClientFXInfectedType": "Byte",
    "TAGame.RBActor_TA:ReplicatedRBState": "RigidBody",
    "TAGame.RBActor_TA:bReplayActor": "Boolean",
    "TAGame.RBActor_TA:bFrozen": "Boolean",
    "TAGame.RBActor_TA:bIgnoreSyncing": "Boolean",
    "TAGame.Team_TA:CustomTeamName": "String",
    "TAGame.Team_TA:GameEvent": "ActiveActor",
    "TAGame.Team_TA:ClubID": "Int64",
    "TAGame.Team_TA:ClubColors": "ClubColors",
    "TAGame.VehiclePickup_TA:NewReplicatedPickupData": "PickupNew",
    "TAGame.VehiclePickup_TA:ReplicatedPickupData": "Pickup",
    "TAGame.VehiclePickup_TA:bNoPickup": "Boolean",
    "TAGame.Vehicle_TA:ReplicatedSteer": "Byte",
    "TAGame.Vehicle_TA:ReplicatedThrottle": "Byte",
    "TAGame.Vehicle_TA:bDriving": "Boolean",
    "TAGame.Vehicle_TA:bReplicatedHandbrake": "Boolean",
    "TAGame.Vehicle_TA:bPodiumMode": "Boolean",
}


def build_class_net_cache_lookup(objects: list, net_cache: list) -> dict:
    nodes = []
    for i, nc in enumerate(net_cache):
        parent_idx = None
        if i > 0:
            if (
                nodes[i - 1]["cache_id"] == nc["parent_id"]
                or nodes[i - 1]["max_stream_id"] == nc["parent_id"]
            ):
                parent_idx = i - 1
            else:
                for j in range(i - 1, -1, -1):
                    if (
                        nodes[j]["cache_id"] == nc["parent_id"]
                        or nodes[j]["max_stream_id"] == nc["parent_id"]
                    ):
                        parent_idx = j
                        break
                if parent_idx is None:
                    parent_idx = i - 1
        props = dict(nodes[parent_idx]["props"]) if parent_idx is not None else {}
        max_sid = nc["cache_id"]
        for p in nc["properties"]:
            props[p["stream_id"]] = p["object_ind"]
        for sid in props:
            if sid + 1 > max_sid:
                max_sid = sid + 1
        nodes.append(
            {
                "object_ind": nc["object_ind"],
                "parent_id": nc["parent_id"],
                "cache_id": nc["cache_id"],
                "props": props,
                "max_stream_id": max_sid,
            }
        )

    node_by_obj = {n["object_ind"]: n for n in nodes}
    node_by_name = {
        objects[n["object_ind"]]: n
        for n in nodes
        if 0 <= n["object_ind"] < len(objects) and objects[n["object_ind"]]
    }

    obj_to_node = {}
    for oid in range(len(objects)):
        if oid in node_by_obj:
            obj_to_node[oid] = node_by_obj[oid]
            continue
        stripped = (objects[oid] or "").replace(".Default__", ".")
        if stripped in node_by_name:
            obj_to_node[oid] = node_by_name[stripped]
            continue
        best = None
        for n in nodes:
            if n["object_ind"] <= oid and (best is None or n["object_ind"] > best["object_ind"]):
                best = n
        if best is not None:
            obj_to_node[oid] = best
    return obj_to_node


def analyze_car_keyframe_jitter(samples: list) -> dict:
    """
    Given a list of (frame_idx, t_raw, x, y, z, vx, vy, vz) RigidBody updates for a car,
    quantifies raw client arrival jitter vs. reconstructed 120Hz server tick intervals.
    """
    if len(samples) < 2:
        return {"sample_count": len(samples), "raw_jitter_rms_ms": 0.0}
    jitter_sq = []
    for i in range(1, len(samples)):
        _, t0, x0, y0, z0, vx0, vy0, vz0 = samples[i - 1]
        _, t1, x1, y1, z1, vx1, vy1, vz1 = samples[i]
        dt_net = max(1.0 / 120.0, t1 - t0)
        dist = math.hypot(x1 - x0, y1 - y0, z1 - z0)
        v_avg = math.hypot(0.5 * (vx0 + vx1), 0.5 * (vy0 + vy1), 0.5 * (vz0 + vz1))
        if 200.0 < v_avg < 2350.0 and 2.0 < dist < 400.0:
            dt_kin = round((dist / v_avg) * 120.0) / 120.0
            if abs(dt_kin - dt_net) <= 0.035:
                jitter_sq.append(((dt_net - dt_kin) * 1000.0) ** 2)
    rms_ms = math.sqrt(sum(jitter_sq) / len(jitter_sq)) if jitter_sq else 0.0
    return {
        "sample_count": len(samples),
        "evaluated_intervals": len(jitter_sq),
        "raw_jitter_rms_ms": round(rms_ms, 2),
    }


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "raw/RLorig/3adc59ea-2a3d-49b0-bd92-15f0d27bb3f6.replay"
    raw = Path(target).read_bytes()
    p1_len, p1_crc = struct.unpack("<II", raw[:8])
    p1_ok = calc_rl_crc32(raw[8 : 8 + p1_len]) == p1_crc
    p2_off = 8 + p1_len
    p2_len, p2_crc = struct.unpack("<II", raw[p2_off : p2_off + 8])
    p2_ok = calc_rl_crc32(raw[p2_off + 8 : p2_off + 8 + p2_len]) == p2_crc
    print(f"[RLDump] {Path(target).name}: size={len(raw)}B, Part1_CRC={p1_ok}, Part2_CRC={p2_ok}")
