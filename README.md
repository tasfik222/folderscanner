Python code : 

"""
folder_scanner.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Anti-Cheat Folder / Full PC Scanner
  • Folder path দাও → সব EXE/DLL/SYS/DRV recursive scan
  • প্রতিটি file এর String, Entropy, Import, Hash analyze
  • Suspicious file গুলো risk অনুযায়ী সাজানো list
  • Full detail report + Export (TXT / HTML / JSON)
  • Multi-thread scan — fast
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import os, sys, math, struct, hashlib, re, json, threading, ctypes, queue, time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed

# ══════════════════════════════════════════════════════════════
# COLORS & FONTS
# ══════════════════════════════════════════════════════════════
BG     = "#0d1117"
PANEL  = "#161b22"
PANEL2 = "#1c2128"
BORDER = "#30363d"
FG     = "#e6edf3"
DIM    = "#8b949e"
BLUE   = "#58a6ff"
GREEN  = "#3fb950"
RED    = "#f85149"
ORANGE = "#d29922"
YELLOW = "#e3b341"
PURPLE = "#bc8cff"
MONO   = ("Consolas", 9)
MONO_B = ("Consolas", 9, "bold")
UI     = ("Segoe UI", 9)
UI_B   = ("Segoe UI", 9, "bold")

SCAN_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".drv", ".ocx",
    ".cpl", ".scr", ".com", ".ax", ".acm",
}

# ══════════════════════════════════════════════════════════════
# RISK
# ══════════════════════════════════════════════════════════════
class Risk(Enum):
    CLEAN    = ("CLEAN",    "#3fb950", "✅", 0)
    LOW      = ("LOW",      "#58a6ff", "ℹ",  1)
    MEDIUM   = ("MEDIUM",   "#e3b341", "⚠",  2)
    HIGH     = ("HIGH",     "#d29922", "🔶", 3)
    CRITICAL = ("CRITICAL", "#f85149", "🚨", 4)
    def __init__(self, label, color, icon, score):
        self.label = label; self.color = color
        self.icon  = icon;  self.score = score

@dataclass
class Finding:
    category : str
    risk     : Risk
    title    : str
    detail   : str
    evidence : list = field(default_factory=list)

@dataclass
class FileResult:
    path         : str
    size         : int
    sha256       : str
    md5          : str
    file_type    : str
    arch         : str
    compile_time : str
    is_packed    : bool
    overall_risk : Risk
    findings     : list = field(default_factory=list)
    imports      : list = field(default_factory=list)
    sections     : list = field(default_factory=list)
    strings_found: list = field(default_factory=list)
    error        : str  = ""
    scan_time_ms : float = 0.0

# ══════════════════════════════════════════════════════════════
# DATABASES
# ══════════════════════════════════════════════════════════════
CHEAT_STRINGS = {
    # Original entries
    "aimbot":Risk.CRITICAL, "aim bot":Risk.CRITICAL,
    "wallhack":Risk.CRITICAL, "wall hack":Risk.CRITICAL,
    "speedhack":Risk.CRITICAL, "speed hack":Risk.CRITICAL,
    "triggerbot":Risk.CRITICAL, "trigger bot":Risk.CRITICAL,
    "spinbot":Risk.CRITICAL, "godmode":Risk.CRITICAL,
    "god mode":Risk.CRITICAL, "norecoil":Risk.HIGH,
    "no recoil":Risk.HIGH, "nospread":Risk.HIGH,
    "bunnyhop":Risk.HIGH, "bhop":Risk.MEDIUM,
    "autofire":Risk.HIGH, "rapidfire":Risk.HIGH,
    "rapid fire":Risk.HIGH, "radarhack":Risk.HIGH,
    "esp hack":Risk.CRITICAL, "silent aim":Risk.CRITICAL,
    "magic bullet":Risk.CRITICAL, "infinite ammo":Risk.CRITICAL,
    "noclip":Risk.HIGH, "bypass anticheat":Risk.CRITICAL,
    "anticheat bypass":Risk.CRITICAL, "eac bypass":Risk.CRITICAL,
    "battleye bypass":Risk.CRITICAL, "vac bypass":Risk.CRITICAL,
    "undetected":Risk.HIGH, "hvh":Risk.HIGH,
    "writeprocessmemory":Risk.HIGH, "readprocessmemory":Risk.HIGH,
    "createremotethread":Risk.CRITICAL, "virtualalloc":Risk.MEDIUM,
    "ntwritevirtualmemory":Risk.HIGH, "manualmapping":Risk.CRITICAL,
    "dll inject":Risk.CRITICAL, "dllinjection":Risk.CRITICAL,
    "loadlibrarya":Risk.HIGH, "injector":Risk.HIGH,
    "setwindowshookex":Risk.HIGH, "minhook":Risk.HIGH,
    "cheatengine":Risk.CRITICAL, "cheat engine":Risk.CRITICAL,
    "gameguardian":Risk.CRITICAL, "artmoney":Risk.HIGH,
    "x64dbg":Risk.HIGH, "ollydbg":Risk.HIGH,
    "processhacker":Risk.HIGH, "themida":Risk.MEDIUM,
    "vmprotect":Risk.MEDIUM, "upx0":Risk.LOW, "upx!":Risk.LOW,
    "frida-gadget":Risk.HIGH, "frida":Risk.HIGH,
    "bone esp":Risk.CRITICAL, "player esp":Risk.CRITICAL,
    "loot esp":Risk.HIGH, "unlock all":Risk.MEDIUM,
    "antiaim":Risk.CRITICAL, "anti aim":Risk.CRITICAL,
    "fake lag":Risk.HIGH, "fakelag":Risk.HIGH,
    "lag switch":Risk.CRITICAL, "lagswitch":Risk.CRITICAL,
    "cvars":Risk.MEDIUM, "cvar unlocker":Risk.HIGH,
    "force crosshair":Risk.MEDIUM, "thirdperson":Risk.MEDIUM,
    "third person":Risk.MEDIUM, "wireframe":Risk.HIGH,
    "chams":Risk.HIGH, "glow esp":Risk.HIGH,
    "glowhack":Risk.HIGH, "glow hack":Risk.HIGH,
    "noflash":Risk.HIGH, "no flash":Risk.HIGH,
    "nosmoke":Risk.HIGH, "no smoke":Risk.HIGH,
    "removesmoke":Risk.HIGH, "remove smoke":Risk.HIGH,
    "fullbright":Risk.MEDIUM, "brightness cheat":Risk.MEDIUM,
    "nightmode":Risk.MEDIUM, "night mode":Risk.MEDIUM,
    "skinchanger":Risk.HIGH, "skin changer":Risk.HIGH,
    "model changer":Risk.HIGH, "viewmodel changer":Risk.MEDIUM,
    "knife changer":Risk.HIGH, "weapon skin":Risk.MEDIUM,
    "medal detector":Risk.HIGH, "achievement unlocker":Risk.MEDIUM,
    "rank revealer":Risk.HIGH, "mmr checker":Risk.MEDIUM,
    "trust factor":Risk.HIGH, "trustfactor bypass":Risk.CRITICAL,
    "prime bypass":Risk.CRITICAL, "nonprime bypass":Risk.HIGH,
    "movement recorder":Risk.MEDIUM, "strafe helper":Risk.MEDIUM,
    "auto strafer":Risk.HIGH, "circle strafe":Risk.HIGH,
    "backtrack":Risk.CRITICAL, "back track":Risk.CRITICAL,
    "lag compensation":Risk.HIGH, "interpolation":Risk.MEDIUM,
    "extrapolation":Risk.MEDIUM, "prediction error":Risk.MEDIUM,
    "fov changer":Risk.MEDIUM, "fov slider":Risk.LOW,
    "aspect ratio":Risk.LOW, "zoom hack":Risk.HIGH,
    "no zoom":Risk.MEDIUM, "scope removal":Risk.MEDIUM,
    "scope remover":Risk.MEDIUM, "crosshair editor":Risk.LOW,
    "crosshair generator":Risk.LOW, "sound esp":Risk.HIGH,
    "sound hack":Risk.HIGH, "footstep amplifier":Risk.MEDIUM,
    "sound occlusion":Risk.MEDIUM, "wallbang helper":Risk.HIGH,
    "auto bhop":Risk.HIGH, "autobhop":Risk.HIGH,
    "edge jump":Risk.HIGH, "edgejump":Risk.HIGH,
    "longjump":Risk.HIGH, "long jump":Risk.HIGH,
    "strafe optimizer":Risk.MEDIUM, "air strafe":Risk.MEDIUM,
    "ground strafe":Risk.MEDIUM, "jump stats":Risk.LOW,
    "velocity graph":Risk.LOW, "duck jump":Risk.MEDIUM,
    "cjump":Risk.MEDIUM, "count jump":Risk.MEDIUM,
    "stack jump":Risk.MEDIUM, "multihack":Risk.CRITICAL,
    "multi hack":Risk.CRITICAL, "legit cheat":Risk.HIGH,
    "rage cheat":Risk.CRITICAL, "semi-rage":Risk.HIGH,
    "semi rage":Risk.HIGH, "config loader":Risk.MEDIUM,
    "lua executor":Risk.HIGH, "lua script":Risk.MEDIUM,
    "lua injector":Risk.CRITICAL, "config system":Risk.MEDIUM,
    "menu key":Risk.LOW, "cheat menu":Risk.MEDIUM,
    "visuals":Risk.HIGH, "misc visuals":Risk.MEDIUM,
    "world visuals":Risk.MEDIUM, "player visuals":Risk.HIGH,
    "item visuals":Risk.MEDIUM, "dropped items":Risk.MEDIUM,
    "nade prediction":Risk.MEDIUM, "grenade helper":Risk.MEDIUM,
    "impact points":Risk.MEDIUM, "bullet tracers":Risk.MEDIUM,
    "penetration cross":Risk.HIGH, "pen cross":Risk.HIGH,
    "autowall":Risk.HIGH, "auto wall":Risk.HIGH,
    "damage indicator":Risk.MEDIUM, "damage output":Risk.MEDIUM,
    "health based":Risk.MEDIUM, "healthbar":Risk.MEDIUM,
    "armor indicator":Risk.LOW, "weapon indicator":Risk.LOW,
    "ammo counter":Risk.LOW, "distance indicator":Risk.LOW,
    "snaplines":Risk.HIGH, "snap lines":Risk.HIGH,
    "tracers":Risk.HIGH, "line esp":Risk.HIGH,
    "bounding box":Risk.HIGH, "box esp":Risk.HIGH,
    "corner esp":Risk.HIGH, "rounded esp":Risk.HIGH,
    "3d box":Risk.HIGH, "3d esp":Risk.HIGH,
    "name esp":Risk.MEDIUM, "name tags":Risk.MEDIUM,
    "head dot":Risk.MEDIUM, "head esp":Risk.MEDIUM,
    "eye tracker":Risk.MEDIUM, "eye lines":Risk.MEDIUM,
    "look direction":Risk.MEDIUM, "aim direction":Risk.MEDIUM,
    "fov circle":Risk.MEDIUM, "aim fov":Risk.MEDIUM,
    "crosshair dot":Risk.LOW, "crosshair editor":Risk.LOW,
    "recoil crosshair":Risk.MEDIUM, "recoil control":Risk.HIGH,
    "rcs":Risk.HIGH, "recoil control system":Risk.HIGH,
    "pixel aim":Risk.CRITICAL, "color aim":Risk.CRITICAL,
    "color aimbot":Risk.CRITICAL, "colorbot":Risk.CRITICAL,
    "trigger color":Risk.CRITICAL, "color trigger":Risk.CRITICAL,
    "visible check":Risk.HIGH, "visibility check":Risk.HIGH,
    "smoke check":Risk.HIGH, "flash check":Risk.HIGH,
    "target selection":Risk.HIGH, "target priority":Risk.HIGH,
    "hitbox selection":Risk.HIGH, "hitbox priority":Risk.HIGH,
    "multipoint":Risk.HIGH, "multi point":Risk.HIGH,
    "scale hitboxes":Risk.MEDIUM, "point scale":Risk.MEDIUM,
    "head scale":Risk.MEDIUM, "body scale":Risk.MEDIUM,
    "pelvis scale":Risk.MEDIUM, "feet scale":Risk.MEDIUM,
    "autostop":Risk.HIGH, "auto stop":Risk.HIGH,
    "autoscope":Risk.HIGH, "auto scope":Risk.HIGH,
    "autocock":Risk.MEDIUM, "auto cock":Risk.MEDIUM,
    "autoshoot":Risk.HIGH, "auto shoot":Risk.HIGH,
    "double tap":Risk.HIGH, "doubletap":Risk.HIGH,
    "hideshots":Risk.CRITICAL, "hide shots":Risk.CRITICAL,
    "shot distribution":Risk.HIGH, "spread control":Risk.HIGH,
    "nospread":Risk.HIGH, "no spread":Risk.HIGH,
    "norecoil":Risk.HIGH, "no recoil":Risk.HIGH,
    "first shot":Risk.HIGH, "first bullet":Risk.HIGH,
    "accuracy boost":Risk.HIGH, "accuracy fix":Risk.MEDIUM,
    "movement fix":Risk.HIGH, "movement correction":Risk.HIGH,
    "quick stop":Risk.HIGH, "quickstop":Risk.HIGH,
    "fast stop":Risk.HIGH, "faststop":Risk.HIGH,
    "prediction":Risk.HIGH, "movement prediction":Risk.HIGH,
    "ballistic prediction":Risk.MEDIUM, "bullet drop":Risk.MEDIUM,
    "gravity prediction":Risk.MEDIUM, "travel time":Risk.MEDIUM,
    "velocity prediction":Risk.MEDIUM, "target prediction":Risk.HIGH,
    
    # Cheat seller undetectable strings (obfuscated/spelled variations)
    "a1mb0t":Risk.CRITICAL, "a1m b0t":Risk.CRITICAL,
    "w4llh4ck":Risk.CRITICAL, "w4ll h4ck":Risk.CRITICAL,
    "tr1gg3rb0t":Risk.CRITICAL, "tr1gg3r b0t":Risk.CRITICAL,
    "sp33dh4ck":Risk.CRITICAL, "sp33d h4ck":Risk.CRITICAL,
    "tr1gg3rh4ck":Risk.CRITICAL, "tr1gg3r h4ck":Risk.CRITICAL,
    "tr1p h4ck":Risk.CRITICAL, "tr1ph4ck":Risk.CRITICAL,
    "3sp":Risk.HIGH, "3sp h4ck":Risk.CRITICAL,
    "wh":Risk.HIGH, "wh4ck":Risk.CRITICAL,
    "esp hack":Risk.CRITICAL, "esp h4ck":Risk.CRITICAL,
    "ahk script":Risk.MEDIUM, "auto hotkey":Risk.MEDIUM,
    "ahk bot":Risk.MEDIUM, "ahk cheat":Risk.HIGH,
    "logitech script":Risk.MEDIUM, "lgs script":Risk.MEDIUM,
    "ghub script":Risk.MEDIUM, "razersynapse":Risk.MEDIUM,
    "cronus zen":Risk.HIGH, "cronusmax":Risk.HIGH,
    "xim apex":Risk.HIGH, "xim4":Risk.HIGH,
    "titan one":Risk.HIGH, "titan two":Risk.HIGH,
    "reWASD":Risk.MEDIUM, "joy2key":Risk.LOW,
    "python cheat":Risk.HIGH, "py cheat":Risk.HIGH,
    "python hack":Risk.HIGH, "py hack":Risk.HIGH,
    "external crosshair":Risk.LOW, "external radar":Risk.MEDIUM,
    "overlay hack":Risk.HIGH, "overlay cheat":Risk.HIGH,
    "transparent overlay":Risk.HIGH, "opengl overlay":Risk.HIGH,
    "dx overlay":Risk.HIGH, "directx hook":Risk.HIGH,
    "d3d hook":Risk.HIGH, "d3d11 hook":Risk.HIGH,
    "opengl hook":Risk.HIGH, "vulkan hook":Risk.HIGH,
    "imgui hack":Risk.HIGH, "imgui menu":Risk.HIGH,
    "dear imgui":Risk.MEDIUM, "cef menu":Risk.MEDIUM,
    "html menu":Risk.MEDIUM, "js menu":Risk.MEDIUM,
    "lua menu":Risk.MEDIUM, "lua script":Risk.MEDIUM,
    "gui menu":Risk.MEDIUM, "stealth injector":Risk.CRITICAL,
    "stealth dll":Risk.CRITICAL, "hidden injector":Risk.CRITICAL,
    "kernel injector":Risk.CRITICAL, "kernel cheat":Risk.CRITICAL,
    "kernel hack":Risk.CRITICAL, "driver cheat":Risk.CRITICAL,
    "driver hack":Risk.CRITICAL, "mapper":Risk.CRITICAL,
    "kdmapper":Risk.CRITICAL, "ekdmapper":Risk.CRITICAL,
    "vulnerable driver":Risk.CRITICAL, "gzdrv":Risk.HIGH,
    "hwid spoof":Risk.CRITICAL, "hwid spoofer":Risk.CRITICAL,
    "hwid bypass":Risk.CRITICAL, "hwid changer":Risk.CRITICAL,
    "guid spoof":Risk.CRITICAL, "serial spoof":Risk.CRITICAL,
    "volumeid":Risk.HIGH, "mac spoof":Risk.HIGH,
    "mac changer":Risk.HIGH, "smbios":Risk.HIGH,
    "disk spoof":Risk.CRITICAL, "disk id":Risk.HIGH,
    "registry cleaner":Risk.MEDIUM, "trace cleaner":Risk.HIGH,
    "log cleaner":Risk.HIGH, "anticheat cleaner":Risk.HIGH,
    "eac cleaner":Risk.HIGH, "be cleaner":Risk.HIGH,
    "vac cleaner":Risk.HIGH, "faceit cleaner":Risk.HIGH,
    "esportal cleaner":Risk.HIGH, "fiveguard":Risk.HIGH,
    "ezfrags":Risk.CRITICAL, "interwebz":Risk.CRITICAL,
    "gamesense":Risk.CRITICAL, "gamesense.pub":Risk.CRITICAL,
    "skeet.cc":Risk.CRITICAL, "skeet cheat":Risk.CRITICAL,
    "onetap":Risk.CRITICAL, "onetap.su":Risk.CRITICAL,
    "fatality":Risk.CRITICAL, "fatality.win":Risk.CRITICAL,
    "neverlose":Risk.CRITICAL, "neverlose.cc":Risk.CRITICAL,
    "aimware":Risk.CRITICAL, "aimware.net":Risk.CRITICAL,
    "primordial":Risk.CRITICAL, "primordial.gg":Risk.CRITICAL,
    "legendware":Risk.HIGH, "legendware.cc":Risk.HIGH,
    "iniuria":Risk.CRITICAL, "iniuria.us":Risk.CRITICAL,
    "memesense":Risk.HIGH, "memesense.gg":Risk.HIGH,
    "novoline":Risk.HIGH, "novolinehook":Risk.HIGH,
    "vape v4":Risk.HIGH, "vape.gg":Risk.HIGH,
    "vape client":Risk.HIGH, "vape lite":Risk.HIGH,
    "whitecheat":Risk.HIGH, "white cheat":Risk.HIGH,
    "white aim":Risk.HIGH, "darkstorm":Risk.HIGH,
    "darkstorm cheat":Risk.HIGH, "cracked cheat":Risk.MEDIUM,
    "cracked aimware":Risk.HIGH, "free cheat":Risk.MEDIUM,
    "free hack":Risk.MEDIUM, "paste cheat":Risk.MEDIUM,
    "pastebin cheat":Risk.MEDIUM, "leaked cheat":Risk.MEDIUM,
    "cheat source":Risk.MEDIUM, "hack source":Risk.MEDIUM,
    
    # Obfuscation patterns - character substitutions
    "a1mb0t":Risk.CRITICAL, "41mb0t":Risk.CRITICAL,
    "w4llh4x":Risk.CRITICAL, "w411h4x":Risk.CRITICAL,
    "tr1gg3rh4x":Risk.CRITICAL, "tr1gg3r":Risk.HIGH,
    "3sp":Risk.HIGH, "35p":Risk.HIGH,
    "wh":Risk.MEDIUM, "whx":Risk.HIGH,
    "esp":Risk.HIGH, "3sp hack":Risk.CRITICAL,
    "radar hack":Risk.HIGH, "r4d4r h4ck":Risk.HIGH,
    "chams":Risk.HIGH, "ch4ms":Risk.HIGH,
    "glow":Risk.HIGH, "gl0w":Risk.HIGH,
    "trigger":Risk.HIGH, "tr1gg3r":Risk.HIGH,
    "bunnyhop":Risk.HIGH, "bunny h0p":Risk.HIGH,
    "bhop":Risk.MEDIUM, "bh0p":Risk.MEDIUM,
    "autofire":Risk.HIGH, "aut0f1re":Risk.HIGH,
    "rapidfire":Risk.HIGH, "rap1df1re":Risk.HIGH,
    "norecoil":Risk.HIGH, "n0rec01l":Risk.HIGH,
    "nospread":Risk.HIGH, "n0spr3ad":Risk.HIGH,
    "silent aim":Risk.CRITICAL, "s1lent a1m":Risk.CRITICAL,
    "silent":Risk.HIGH, "s1lent":Risk.HIGH,
    "aim assist":Risk.MEDIUM, "a1m ass1st":Risk.MEDIUM,
    "aim helper":Risk.MEDIUM, "a1m h3lp3r":Risk.MEDIUM,
    "wallhack":Risk.CRITICAL, "wallhax":Risk.CRITICAL,
    "wireframe":Risk.HIGH, "w1r3fr4me":Risk.HIGH,
    "nightmode":Risk.MEDIUM, "n1ghtm0de":Risk.MEDIUM,
    "fullbright":Risk.MEDIUM, "fullbr1ght":Risk.MEDIUM,
    "nosmoke":Risk.HIGH, "n0sm0ke":Risk.HIGH,
    "noflash":Risk.HIGH, "n0fl4sh":Risk.HIGH,
    "nohands":Risk.MEDIUM, "n0h4nds":Risk.MEDIUM,
    "noscope":Risk.MEDIUM, "n0sc0pe":Risk.MEDIUM,
    
    # Additional cheat seller terms
    "undetected cheat":Risk.HIGH, "ud cheat":Risk.HIGH,
    "undetected hack":Risk.HIGH, "ud hack":Risk.HIGH,
    "private cheat":Risk.HIGH, "private hack":Risk.HIGH,
    "paid cheat":Risk.MEDIUM, "premium cheat":Risk.MEDIUM,
    "lifetime cheat":Risk.MEDIUM, "lifetime sub":Risk.MEDIUM,
    "monthly sub":Risk.MEDIUM, "cheat key":Risk.MEDIUM,
    "hack key":Risk.MEDIUM, "loader key":Risk.MEDIUM,
    "keyauth":Risk.MEDIUM, "key auth":Risk.MEDIUM,
    "key system":Risk.MEDIUM, "license key":Risk.MEDIUM,
    "whitelist":Risk.MEDIUM, "whitelist system":Risk.MEDIUM,
    "hwid lock":Risk.HIGH, "hwid lock bypass":Risk.CRITICAL,
    "hwid reset":Risk.HIGH, "hwid unlocker":Risk.HIGH,
    "fingerprint bypass":Risk.CRITICAL, "device id bypass":Risk.CRITICAL,
    "pc id changer":Risk.HIGH, "machine guid":Risk.HIGH,
    "battleye":Risk.MEDIUM, "battleye bypass":Risk.CRITICAL,
    "eac":Risk.MEDIUM, "easyanticheat":Risk.MEDIUM,
    "vac":Risk.MEDIUM, "valve anticheat":Risk.MEDIUM,
    "faceit":Risk.MEDIUM, "faceit anticheat":Risk.HIGH,
    "esportal":Risk.MEDIUM, "fiveguard":Risk.MEDIUM,
    "punkbuster":Risk.MEDIUM, "pb bypass":Risk.HIGH,
    "ricochet":Risk.MEDIUM, "cod anticheat":Risk.MEDIUM,
    "dma cheat":Risk.CRITICAL, "dma hack":Risk.CRITICAL,
    "dma card":Risk.CRITICAL, "dma device":Risk.CRITICAL,
    "dma firmware":Risk.CRITICAL, "pcie cheat":Risk.CRITICAL,
    "pcie dma":Risk.CRITICAL, "fpga cheat":Risk.CRITICAL,
    "raspberry pi":Risk.CRITICAL, "rpi cheat":Risk.CRITICAL,
    "arduino cheat":Risk.HIGH, "teensy cheat":Risk.HIGH,
    "usb cheat":Risk.HIGH, "usb device":Risk.HIGH,
    "color detection":Risk.HIGH, "color sensor":Risk.HIGH,
    "color aimbot":Risk.CRITICAL, "color aimbot device":Risk.CRITICAL,
    "dma card":Risk.CRITICAL, "dma device":Risk.CRITICAL,
    
    # External/overlay related
    "external overlay":Risk.HIGH, "external hack":Risk.HIGH,
    "external cheat":Risk.HIGH, "overlay hack":Risk.HIGH,
    "overlay cheat":Risk.HIGH, "topmost overlay":Risk.HIGH,
    "transparent overlay":Risk.HIGH, "always on top":Risk.MEDIUM,
    "windowed mode":Risk.LOW, "fullscreen windowed":Risk.LOW,
    "borderless window":Risk.LOW, "borderless":Risk.LOW,
    
    # Console/controller cheats
    "ps4 cheat":Risk.HIGH, "ps5 cheat":Risk.HIGH,
    "xbox cheat":Risk.HIGH, "xbox series x cheat":Risk.HIGH,
    "console cheat":Risk.HIGH, "console hack":Risk.HIGH,
    "jtag":Risk.HIGH, "rgh":Risk.HIGH,
    "ps3 jailbreak":Risk.HIGH, "ps4 jailbreak":Risk.HIGH,
    "ps5 jailbreak":Risk.HIGH, "xbox rgh":Risk.HIGH,
    "xbox jtag":Risk.HIGH, "xbox360 rgh":Risk.HIGH,
    "save wizard":Risk.MEDIUM, "save editor":Risk.MEDIUM,
    "game save":Risk.LOW, "modded save":Risk.MEDIUM,
    
    # Mobile cheats
    "android cheat":Risk.HIGH, "android hack":Risk.HIGH,
    "ios cheat":Risk.HIGH, "ios hack":Risk.HIGH,
    "game guardian":Risk.CRITICAL, "gg cheat":Risk.CRITICAL,
    "gg hack":Risk.CRITICAL, "android mod":Risk.MEDIUM,
    "mod menu":Risk.MEDIUM, "mod apk":Risk.MEDIUM,
    "hack apk":Risk.MEDIUM, "il2cpp cheat":Risk.HIGH,
    "libil2cpp":Risk.MEDIUM, "libunity":Risk.MEDIUM,
    "android injector":Risk.HIGH, "ios injector":Risk.HIGH,
    "jailbreak cheat":Risk.HIGH, "cydia cheat":Risk.HIGH,
    "tweaked app":Risk.MEDIUM, "hacked app":Risk.MEDIUM,
    
    # Specific game cheats (popular games)
    "csgo cheat":Risk.CRITICAL, "csgo hack":Risk.CRITICAL,
    "cs2 cheat":Risk.CRITICAL, "cs2 hack":Risk.CRITICAL,
    "valorant cheat":Risk.CRITICAL, "valorant hack":Risk.CRITICAL,
    "val cheat":Risk.CRITICAL, "val hack":Risk.CRITICAL,
    "warzone cheat":Risk.CRITICAL, "warzone hack":Risk.CRITICAL,
    "mw3 cheat":Risk.CRITICAL, "mw3 hack":Risk.CRITICAL,
    "mw2 cheat":Risk.CRITICAL, "mw2 hack":Risk.CRITICAL,
    "apex cheat":Risk.CRITICAL, "apex hack":Risk.CRITICAL,
    "apex legends":Risk.HIGH, "apex legends cheat":Risk.CRITICAL,
    "fortnite cheat":Risk.CRITICAL, "fortnite hack":Risk.CRITICAL,
    "fn cheat":Risk.CRITICAL, "fn hack":Risk.CRITICAL,
    "pubg cheat":Risk.CRITICAL, "pubg hack":Risk.CRITICAL,
    "pubg pc":Risk.HIGH, "pubg mobile":Risk.HIGH,
    "rust cheat":Risk.CRITICAL, "rust hack":Risk.CRITICAL,
    "rust hack":Risk.CRITICAL, "ezfrags rust":Risk.CRITICAL,
    "dayz cheat":Risk.CRITICAL, "dayz hack":Risk.CRITICAL,
    "eft cheat":Risk.CRITICAL, "eft hack":Risk.CRITICAL,
    "escape from tarkov":Risk.CRITICAL, "tarkov cheat":Risk.CRITICAL,
    "tarkov hack":Risk.CRITICAL, "arena breakout":Risk.CRITICAL,
    "ab cheat":Risk.CRITICAL, "ab hack":Risk.CRITICAL,
    "fivem cheat":Risk.HIGH, "fivem hack":Risk.HIGH,
    "fivem mod":Risk.MEDIUM, "gta cheat":Risk.HIGH,
    "gta hack":Risk.HIGH, "gta online cheat":Risk.HIGH,
    "rdr2 cheat":Risk.HIGH, "rdr2 hack":Risk.HIGH,
    "red dead":Risk.MEDIUM, "overwatch cheat":Risk.CRITICAL,
    "overwatch hack":Risk.CRITICAL, "ow cheat":Risk.CRITICAL,
    "ow2 cheat":Risk.CRITICAL, "ow2 hack":Risk.CRITICAL,
    "rainbow six":Risk.CRITICAL, "r6 cheat":Risk.CRITICAL,
    "r6 hack":Risk.CRITICAL, "siege cheat":Risk.CRITICAL,
    "siege hack":Risk.CRITICAL, "battlebit cheat":Risk.CRITICAL,
    "battlebit hack":Risk.CRITICAL, "the finals cheat":Risk.CRITICAL,
    "the finals hack":Risk.CRITICAL, "xdefiant cheat":Risk.CRITICAL,
    "xdefiant hack":Risk.CRITICAL, "payday cheat":Risk.HIGH,
    "payday hack":Risk.HIGH, "payday 3 cheat":Risk.HIGH,
    "payday 3 hack":Risk.HIGH, "dead by daylight":Risk.HIGH,
    "dbd cheat":Risk.HIGH, "dbd hack":Risk.HIGH,
    "dbd perk":Risk.MEDIUM, "hunt showdown":Risk.HIGH,
    "hunt cheat":Risk.HIGH, "hunt hack":Risk.HIGH,
    "sea of thieves":Risk.HIGH, "soT cheat":Risk.HIGH,
    "soT hack":Risk.HIGH, "minecraft cheat":Risk.MEDIUM,
    "minecraft hack":Risk.MEDIUM, "mc cheat":Risk.MEDIUM,
    "mc hack":Risk.MEDIUM, "wurst client":Risk.HIGH,
    "impact client":Risk.HIGH, "meteor client":Risk.HIGH,
    "future client":Risk.HIGH, "rusherhack":Risk.HIGH,
    "among us cheat":Risk.MEDIUM, "among us hack":Risk.MEDIUM,
    "among us mod":Risk.LOW, "fall guys cheat":Risk.MEDIUM,
    "fall guys hack":Risk.MEDIUM, "rocket league":Risk.MEDIUM,
    "rocket league cheat":Risk.MEDIUM, "rl cheat":Risk.MEDIUM,
    "bakkesmod":Risk.LOW, "bakkesmod plugin":Risk.LOW,
    
    # Misc cheat terms
    "unlock tool":Risk.HIGH, "unlocker":Risk.HIGH,
    "premium unlocker":Risk.HIGH, "dlc unlocker":Risk.HIGH,
    "creamapi":Risk.HIGH, "cream api":Risk.HIGH,
    "greenluma":Risk.HIGH, "goldberg":Risk.MEDIUM,
    "goldberg emu":Risk.MEDIUM, "steam emu":Risk.MEDIUM,
    "emu":Risk.LOW, "emulator":Risk.LOW,
    "crack":Risk.MEDIUM, "crack only":Risk.MEDIUM,
    "no cd crack":Risk.MEDIUM, "no dvd":Risk.MEDIUM,
    "license bypass":Risk.HIGH, "license crack":Risk.HIGH,
    "activation bypass":Risk.HIGH, "activation fix":Risk.MEDIUM,
    "keygen":Risk.HIGH, "keygen crack":Risk.HIGH,
    "patch":Risk.LOW, "trainer":Risk.MEDIUM,
    "game trainer":Risk.MEDIUM, "cheat trainer":Risk.HIGH,
    "mrantifun":Risk.LOW, "fling trainer":Risk.LOW,
    "plitch":Risk.LOW, "we mod":Risk.LOW,
    "wemod":Risk.LOW, "cheat happens":Risk.LOW,
    "cheathappens":Risk.LOW, "ch trainer":Risk.LOW,
    
    # Anti-cheat bypass terms
    "manual map":Risk.CRITICAL, "manual mapping":Risk.CRITICAL,
    "mmap":Risk.CRITICAL, "mmapper":Risk.CRITICAL,
    "thread hijack":Risk.CRITICAL, "thread hijacking":Risk.CRITICAL,
    "apc injection":Risk.CRITICAL, "apc inject":Risk.CRITICAL,
    "atom bombing":Risk.HIGH, "atom bomb":Risk.HIGH,
    "early bird":Risk.HIGH, "earlybird":Risk.HIGH,
    "process hollowing":Risk.CRITICAL, "hollowing":Risk.CRITICAL,
    "runpe":Risk.CRITICAL, "run pe":Risk.CRITICAL,
    "reflective dll":Risk.CRITICAL, "reflective injection":Risk.CRITICAL,
    "reflective loader":Risk.CRITICAL, "reflectiveloade":Risk.CRITICAL,
    "process doppelganging":Risk.CRITICAL, "doppelganging":Risk.CRITICAL,
    "process ghosting":Risk.CRITICAL, "ghosting":Risk.CRITICAL,
    "herpaderping":Risk.CRITICAL, "herp derp":Risk.CRITICAL,
    "kernel callback":Risk.HIGH, "kernel exploit":Risk.CRITICAL,
    "eac bypass":Risk.CRITICAL, "be bypass":Risk.CRITICAL,
    "vac bypass":Risk.CRITICAL, "faceit bypass":Risk.CRITICAL,
    "esportal bypass":Risk.CRITICAL, "fiveguard bypass":Risk.CRITICAL,
    "frida bypass":Risk.HIGH, "frida anti-anti":Risk.HIGH,
    "x64dbg bypass":Risk.HIGH, "antidebug":Risk.HIGH,
    "antidump":Risk.HIGH, "antihook":Risk.HIGH,
    "antivm":Risk.HIGH, "anti vm":Risk.HIGH,
    "vbox detection":Risk.MEDIUM, "vmware detection":Risk.MEDIUM,
    "sandboxie detection":Risk.MEDIUM, "sandbox detection":Risk.MEDIUM,
    "sleep bypass":Risk.HIGH, "timing attack":Risk.HIGH,
    "rdtsc":Risk.MEDIUM, "rdtsc bypass":Risk.HIGH,
    "beep bypass":Risk.MEDIUM, "debugger detection":Risk.HIGH,
    
    # Leet speak variations
    "4im80t":Risk.CRITICAL, "41m80t":Risk.CRITICAL,
    "w4llh4x":Risk.CRITICAL, "w411h4x":Risk.CRITICAL,
    "7r1gg3r":Risk.HIGH, "7r1gg3r80t":Risk.CRITICAL,
    "5p33dh4x":Risk.CRITICAL, "5p33d h4x":Risk.CRITICAL,
    "35p":Risk.HIGH, "35p h4x":Risk.CRITICAL,
    "r4d4r":Risk.MEDIUM, "r4d4r h4x":Risk.HIGH,
    "gl0w":Risk.MEDIUM, "gl0w h4x":Risk.HIGH,
    "ch4m5":Risk.HIGH, "ch4m5 h4x":Risk.HIGH,
    "n0fl4sh":Risk.HIGH, "n0fl4sh h4x":Risk.HIGH,
    "n0sm0k3":Risk.HIGH, "n0sm0k3 h4x":Risk.HIGH,
    "n0r3c01l":Risk.HIGH, "n0r3c01l h4x":Risk.HIGH,
    "n0spr34d":Risk.HIGH, "n0spr34d h4x":Risk.HIGH,
    "51l3n7":Risk.HIGH, "51l3n7 41m":Risk.CRITICAL,
    "41m 4u70":Risk.HIGH, "41m4u70":Risk.HIGH,
    "4u70f1r3":Risk.HIGH, "4u70f1r3 h4x":Risk.HIGH,
    "r4p1df1r3":Risk.HIGH, "r4p1d f1r3":Risk.HIGH,
}

SUSPICIOUS_IMPORTS = {
    "ReadProcessMemory":          (Risk.HIGH,     "Reads another process memory"),
    "WriteProcessMemory":         (Risk.HIGH,     "Writes to another process memory"),
    "OpenProcess":                (Risk.MEDIUM,   "Opens handle to another process"),
    "VirtualAllocEx":             (Risk.HIGH,     "Allocates memory in remote process"),
    "VirtualProtectEx":           (Risk.HIGH,     "Changes memory protection remotely"),
    "CreateRemoteThread":         (Risk.CRITICAL, "Injects thread into another process"),
    "CreateRemoteThreadEx":       (Risk.CRITICAL, "Thread injection (extended)"),
    "NtWriteVirtualMemory":       (Risk.HIGH,     "Low-level memory write (ntdll)"),
    "NtCreateThreadEx":           (Risk.CRITICAL, "Low-level thread injection (ntdll)"),
    "OpenProcessToken":           (Risk.MEDIUM,   "Opens process access token"),
    "AdjustTokenPrivileges":      (Risk.HIGH,     "Privilege escalation via token"),
    "ImpersonateLoggedOnUser":    (Risk.HIGH,     "User impersonation"),
    "SetWindowsHookExW":          (Risk.HIGH,     "Global input hook (keylogger risk)"),
    "SetWindowsHookExA":          (Risk.HIGH,     "Global input hook"),
    "CallNextHookEx":             (Risk.MEDIUM,   "Part of hook chain"),
    "InternetOpenW":              (Risk.MEDIUM,   "Opens internet session"),
    "InternetOpenA":              (Risk.MEDIUM,   "Opens internet session"),
    "InternetOpenUrlA":           (Risk.MEDIUM,   "Opens URL (C2/update risk)"),
    "InternetOpenUrlW":           (Risk.MEDIUM,   "Opens URL (C2/update risk)"),
    "HttpSendRequestA":           (Risk.MEDIUM,   "Sends HTTP request"),
    "LoadLibraryA":               (Risk.MEDIUM,   "Dynamic DLL loading"),
    "LoadLibraryW":               (Risk.MEDIUM,   "Dynamic DLL loading"),
    "IsDebuggerPresent":          (Risk.MEDIUM,   "Anti-debug check"),
    "CheckRemoteDebuggerPresent": (Risk.MEDIUM,   "Remote debugger check"),
    "NtQueryInformationProcess":  (Risk.MEDIUM,   "Low-level process info"),
    "SuspendThread":              (Risk.MEDIUM,   "Thread suspension"),
    "NtCreateFile":               (Risk.LOW,      "Low-level file access"),
    "NtDeleteFile":               (Risk.MEDIUM,   "Low-level file delete (stealth)"),
}

DANGEROUS_COMBOS = [
    # Original entries (your provided ones)
    {"apis":{"ReadProcessMemory","WriteProcessMemory","OpenProcess"},
     "risk":Risk.CRITICAL,"title":"Memory R/W Triad",
     "detail":"Classic memory hacking: Open + Read + Write another process"},
    {"apis":{"OpenProcess","VirtualAllocEx","CreateRemoteThread"},
     "risk":Risk.CRITICAL,"title":"DLL Injection Pattern",
     "detail":"OpenProcess + VirtualAllocEx + CreateRemoteThread = DLL injection"},
    {"apis":{"SetWindowsHookExW","CallNextHookEx"},
     "risk":Risk.HIGH,"title":"Input Hook Chain",
     "detail":"Windows hook chain — intercepts keyboard/mouse input"},
    {"apis":{"OpenProcessToken","AdjustTokenPrivileges","OpenProcess"},
     "risk":Risk.HIGH,"title":"Privilege Escalation",
     "detail":"Token manipulation + process open = privilege escalation"},
    {"apis":{"InternetOpenUrlA","LoadLibraryA","CreateRemoteThread"},
     "risk":Risk.CRITICAL,"title":"Remote Cheat Loader",
     "detail":"Downloads from internet and injects — cheat loader pattern"},
    {"apis":{"NtCreateThreadEx","NtWriteVirtualMemory","OpenProcess"},
     "risk":Risk.CRITICAL,"title":"Stealth NT Injection",
     "detail":"Low-level ntdll injection — bypasses many security tools"},
    {"apis":{"CreateRemoteThread","WriteProcessMemory","VirtualProtectEx"},
     "risk":Risk.CRITICAL,"title":"Code Injection",
     "detail":"Write and execute shellcode in remote process with memory protection change"},
    {"apis":{"RegOpenKeyEx","RegSetValueEx","RegCreateKeyEx"},
     "risk":Risk.HIGH,"title":"Persistence via Registry",
     "detail":"Modifying registry keys for persistence (e.g., Run keys)"},
    {"apis":{"CreateService","StartService","OpenSCManager"},
     "risk":Risk.CRITICAL,"title":"Service Installation",
     "detail":"Creating and starting a new service — common for malware persistence"},
    {"apis":{"GetAsyncKeyState","SetWindowsHookEx","GetForegroundWindow"},
     "risk":Risk.HIGH,"title":"Keylogging Setup",
     "detail":"Hooks or polls keystrokes — potential keylogger"},
    {"apis":{"CreateFileMapping","MapViewOfFile","OpenFileMapping"},
     "risk":Risk.MEDIUM,"title":"Shared Memory Access",
     "detail":"May indicate inter-process communication via shared memory"},
    {"apis":{"socket","connect","send","recv"},
     "risk":Risk.HIGH,"title":"Network Communication",
     "detail":"Basic socket operations — C2 or data exfiltration"},
    {"apis":{"WinExec","system","CreateProcess"},
     "risk":Risk.HIGH,"title":"Command Execution",
     "detail":"Executes system commands or binaries"},
    {"apis":{"NtQuerySystemInformation","NtQueryInformationProcess","NtReadVirtualMemory"},
     "risk":Risk.MEDIUM,"title":"Process Enumeration",
     "detail":"Enumerating processes/threads for reconnaissance"},
    {"apis":{"CryptEncrypt","CryptDecrypt","CryptAcquireContext"},
     "risk":Risk.HIGH,"title":"Cryptographic Operations",
     "detail":"May indicate ransomware or protected communication"},
    {"apis":{"FindFirstFile","FindNextFile","GetFileAttributes"},
     "risk":Risk.MEDIUM,"title":"File System Recon",
     "detail":"Enumerating files/directories — potential data harvesting"},
    {"apis":{"DebugActiveProcess","DebugSetProcessKillOnExit","WaitForDebugEvent"},
     "risk":Risk.CRITICAL,"title":"Process Debugging",
     "detail":"Attaching as debugger — can be used for code injection or cracking"},
    {"apis":{"SetWindowsHookEx","GetMessage","PeekMessage"},
     "risk":Risk.HIGH,"title":"Global Message Hook",
     "detail":"Monitoring all window messages — keylogging or UI automation"},
    {"apis":{"CreateToolhelp32Snapshot","Process32First","Process32Next"},
     "risk":Risk.MEDIUM,"title":"Process Snapshot",
     "detail":"Taking snapshot of processes/threads — reconnaissance"},
    {"apis":{"URLDownloadToFile","ShellExecute","DeleteFile"},
     "risk":Risk.CRITICAL,"title":"Download & Execute",
     "detail":"Downloads a file, executes it, then deletes the evidence"},
    
    # Advanced Injection Techniques
    {"apis":{"NtCreateThreadEx","NtWriteVirtualMemory","NtOpenProcess"},
     "risk":Risk.CRITICAL,"title":"NT API Injection",
     "detail":"Native API injection — bypasses user-mode hooks"},
    {"apis":{"RtlCreateUserThread","NtWriteVirtualMemory","NtOpenProcess"},
     "risk":Risk.CRITICAL,"title":"RTL Thread Injection",
     "detail":"Undocumented RTL API injection — stealthy thread creation"},
    {"apis":{"QueueUserAPC","WriteProcessMemory","OpenProcess"},
     "risk":Risk.CRITICAL,"title":"APC Injection",
     "detail":"Asynchronous Procedure Call injection — hijacks existing threads"},
    {"apis":{"NtQueueApcThread","NtWriteVirtualMemory","NtOpenProcess"},
     "risk":Risk.CRITICAL,"title":"Native APC Injection",
     "detail":"NT level APC injection — even more stealthy"},
    {"apis":{"CreateProcess","NtUnmapViewOfSection","NtWriteVirtualMemory"},
     "risk":Risk.CRITICAL,"title":"Process Hollowing",
     "detail":"Creates process, unmaps original code, injects payload"},
    {"apis":{"CreateProcess","NtCreateSection","NtMapViewOfSection"},
     "risk":Risk.CRITICAL,"title":"Process Doppelgänging",
     "detail":"Uses transaction and section — advanced process hollowing variant"},
    {"apis":{"CreateProcess","SetThreadContext","NtResumeThread"},
     "risk":Risk.CRITICAL,"title":"Early Bird Injection",
     "detail":"Injects before process fully initializes — bypasses some monitors"},
    {"apis":{"NtCreateThreadEx","NtAllocateVirtualMemory","NtWriteVirtualMemory"},
     "risk":Risk.CRITICAL,"title":"Manual Mapping",
     "detail":"Manually maps DLL without using LoadLibrary — avoids module tracking"},
    
    # Kernel-Level Techniques
    {"apis":{"NtLoadDriver","NtOpenFile","NtSetSystemInformation"},
     "risk":Risk.CRITICAL,"title":"Driver Loading",
     "detail":"Loads kernel driver — highest privilege level"},
    {"apis":{"NtOpenProcess","NtReadVirtualMemory","NtWriteVirtualMemory"},
     "risk":Risk.CRITICAL,"title":"Kernel Memory Access",
     "detail":"Kernel-mode memory read/write — bypasses all user-mode hooks"},
    {"apis":{"MmMapIoSpace","ZwMapViewOfSection","ZwOpenSection"},
     "risk":Risk.CRITICAL,"title":"Physical Memory Access",
     "detail":"Direct physical memory access — ultimate stealth"},
    {"apis":{"IoCreateDevice","IoCreateSymbolicLink","ZwSetSecurityObject"},
     "risk":Risk.CRITICAL,"title":"Kernel Device Creation",
     "detail":"Creates kernel device for communication with user-mode cheat"},
    
    # Anti-Debug & Anti-Analysis
    {"apis":{"NtQueryInformationProcess","NtClose","NtRaiseHardError"},
     "risk":Risk.HIGH,"title":"Debugger Detection",
     "detail":"Checks for debugger presence using NT API"},
    {"apis":{"IsDebuggerPresent","CheckRemoteDebuggerPresent","NtSetInformationThread"},
     "risk":Risk.HIGH,"title":"Comprehensive Anti-Debug",
     "detail":"Multiple debugger checks combined"},
    {"apis":{"NtYieldExecution","GetTickCount","QueryPerformanceCounter"},
     "risk":Risk.MEDIUM,"title":"Timing-Based Detection",
     "detail":"Detects emulation via timing discrepancies"},
    {"apis":{"NtSetInformationThread","NtHideThreadFromDebugger","NtClose"},
     "risk":Risk.HIGH,"title":"Thread Hiding",
     "detail":"Hides threads from debuggers"},
    
    # Memory Protection & Manipulation
    {"apis":{"VirtualProtectEx","WriteProcessMemory","FlushInstructionCache"},
     "risk":Risk.CRITICAL,"title":"Runtime Code Modification",
     "detail":"Modifies executable code at runtime — self-modifying cheats"},
    {"apis":{"NtProtectVirtualMemory","NtWriteVirtualMemory","NtFlushInstructionCache"},
     "risk":Risk.CRITICAL,"title":"Native Memory Protection",
     "detail":"NT API memory protection bypass"},
    {"apis":{"VirtualAllocEx","VirtualProtectEx","CreateRemoteThread"},
     "risk":Risk.CRITICAL,"title":"Memory Allocation + Execution",
     "detail":"Allocates, changes protection, executes — classic injection"},
    
    # Process Manipulation
    {"apis":{"NtOpenProcess","NtSuspendProcess","NtResumeProcess"},
     "risk":Risk.HIGH,"title":"Process Suspension",
     "detail":"Suspends/resumes processes — can pause anti-cheat"},
    {"apis":{"NtOpenProcess","NtDuplicateObject","NtSetInformationProcess"},
     "risk":Risk.CRITICAL,"title":"Handle Duplication",
     "detail":"Duplicates process handles — privilege escalation"},
    
    # Token Manipulation
    {"apis":{"NtOpenProcessToken","NtAdjustPrivilegesToken","NtImpersonateThread"},
     "risk":Risk.CRITICAL,"title":"Advanced Token Manipulation",
     "detail":"NT API token privilege adjustment + impersonation"},
    {"apis":{"OpenProcessToken","DuplicateTokenEx","CreateProcessWithToken"},
     "risk":Risk.CRITICAL,"title":"Token-Based Process Creation",
     "detail":"Creates process with elevated privileges via token"},
    
    # Keylogging & Input Monitoring
    {"apis":{"SetWindowsHookEx","GetMessage","CallNextHookEx"},
     "risk":Risk.HIGH,"title":"Global Hook Chain",
     "detail":"Global Windows hook for input monitoring"},
    {"apis":{"GetAsyncKeyState","GetKeyState","GetForegroundWindow"},
     "risk":Risk.HIGH,"title":"Poll-Based Keylogger",
     "detail":"Polls key states periodically — stealthier than hooks"},
    {"apis":{"RegisterRawInputDevices","GetRawInputData","GetMessage"},
     "risk":Risk.HIGH,"title":"Raw Input Monitoring",
     "detail":"Captures raw input data — bypasses some hook detections"},
    
    # Network Communication
    {"apis":{"WSAStartup","socket","connect","send","recv"},
     "risk":Risk.HIGH,"title":"Socket Communication",
     "detail":"Basic network communication for C2"},
    {"apis":{"InternetOpen","InternetConnect","HttpOpenRequest","HttpSendRequest"},
     "risk":Risk.HIGH,"title":"HTTP Communication",
     "detail":"HTTP-based C2 communication"},
    {"apis":{"URLDownloadToFile","WinExec","DeleteFile"},
     "risk":Risk.CRITICAL,"title":"Download & Execute & Clean",
     "detail":"Downloads, runs, removes evidence"},
    
    # Persistence Techniques
    {"apis":{"RegCreateKeyEx","RegSetValueEx","RegCloseKey"},
     "risk":Risk.HIGH,"title":"Registry Persistence",
     "detail":"Creates registry run keys for persistence"},
    {"apis":{"CreateService","StartService","OpenService"},
     "risk":Risk.CRITICAL,"title":"Service Persistence",
     "detail":"Installs as Windows service"},
    {"apis":{"CopyFile","MoveFileEx","DeleteFile"},
     "risk":Risk.MEDIUM,"title":"File Operations",
     "detail":"File manipulation for persistence"},
    {"apis":{"CreateDirectory","SetCurrentDirectory","GetModuleFileName"},
     "risk":Risk.MEDIUM,"title":"Directory Operations",
     "detail":"Directory manipulation for cheat files"},
    
    # Anti-Sandbox & VM Detection
    {"apis":{"NtQuerySystemInformation","NtQueryVolumeInformationFile","NtQueryInformationProcess"},
     "risk":Risk.HIGH,"title":"Comprehensive System Enumeration",
     "detail":"Detects VMs/sandboxes via system info"},
    {"apis":{"GetModuleHandle","GetProcAddress","LoadLibrary"},
     "risk":Risk.MEDIUM,"title":"Module Detection",
     "detail":"Checks for presence of sandbox modules"},
    {"apis":{"NtOpenKey","NtQueryValueKey","NtClose"},
     "risk":Risk.HIGH,"title":"Registry VM Detection",
     "detail":"Checks registry for VM artifacts"},
    
    # HWID Spoofing & Anti-Ban
    {"apis":{"NtOpenKey","NtSetValueKey","NtDeleteKey"},
     "risk":Risk.CRITICAL,"title":"Registry Manipulation for HWID",
     "detail":"Modifies registry to spoof HWID"},
    {"apis":{"DeviceIoControl","CreateFile","CloseHandle"},
     "risk":Risk.CRITICAL,"title":"Device Control for Spoofing",
     "detail":"Direct device communication for hardware spoofing"},
    {"apis":{"GetVolumeInformation","SetVolumeLabel","CreateFile"},
     "risk":Risk.HIGH,"title":"Volume Information Manipulation",
     "detail":"Volume serial spoofing"},
    {"apis":{"GetAdaptersInfo","GetAdaptersAddresses","CreateIpForwardEntry"},
     "risk":Risk.HIGH,"title":"Network Adapter Manipulation",
     "detail":"MAC address spoofing"},
    
    # Code Integrity Bypass
    {"apis":{"NtCreateThreadEx","NtSetContextThread","NtGetContextThread"},
     "risk":Risk.CRITICAL,"title":"Thread Context Manipulation",
     "detail":"Modifies thread context for code execution"},
    {"apis":{"NtContinue","NtRaiseException","NtSetInformationThread"},
     "risk":Risk.HIGH,"title":"Exception Handling for Code Flow",
     "detail":"Uses exceptions to control code flow — anti-analysis"},
    {"apis":{"NtCreateSection","NtMapViewOfSection","NtUnmapViewOfSection"},
     "risk":Risk.CRITICAL,"title":"Section Mapping",
     "detail":"Memory sections for code sharing/mapping"},
    
    # AMSI & ETW Bypass
    {"apis":{"AmsiScanBuffer","AmsiScanString","AmsiInitialize"},
     "risk":Risk.CRITICAL,"title":"AMSI Patch Pattern",
     "detail":"Patching AMSI to disable script scanning"},
    {"apis":{"EtwEventWrite","EtwEventRegister","EtwEventUnregister"},
     "risk":Risk.CRITICAL,"title":"ETW Bypass Pattern",
     "detail":"Disables Event Tracing for Windows"},
    
    # Direct Syscall Techniques
    {"apis":{"NtAllocateVirtualMemory","NtProtectVirtualMemory","NtCreateThreadEx"},
     "risk":Risk.CRITICAL,"title":"Direct Syscall Injection",
     "detail":"Bypasses user-mode hooks with direct syscalls"},
    {"apis":{"NtOpenProcess","NtReadVirtualMemory","NtWriteVirtualMemory"},
     "risk":Risk.CRITICAL,"title":"Direct Syscall Memory Ops",
     "detail":"All memory operations via direct syscalls"},
    
    # External/Overlay Cheats
    {"apis":{"CreateWindowEx","SetWindowLong","SetLayeredWindowAttributes"},
     "risk":Risk.HIGH,"title":"Layered Window Overlay",
     "detail":"Creates transparent overlay for ESP/aimbot"},
    {"apis":{"Direct3DCreate9","IDirect3DDevice9::Present","IDirect3DDevice9::DrawIndexedPrimitive"},
     "risk":Risk.HIGH,"title":"D3D Hooking",
     "detail":"Hooks Direct3D for rendering cheats"},
    {"apis":{"wglSwapBuffers","glBegin","glEnd","glDrawElements"},
     "risk":Risk.HIGH,"title":"OpenGL Hooking",
     "detail":"Hooks OpenGL for rendering cheats"},
    
    # DMA & Hardware-Based
    {"apis":{"MmMapIoSpace","MmUnmapIoSpace","READ_PORT_UCHAR"},
     "risk":Risk.CRITICAL,"title":"Physical Memory DMA",
     "detail":"Direct physical memory access via DMA"},
    {"apis":{"ZwOpenSection","ZwMapViewOfSection","ZwClose"},
     "risk":Risk.CRITICAL,"title":"Physical Memory Section",
     "detail":"Maps physical memory sections"},
    
    # Anti-Cheat Specific Bypasses
    {"apis":{"NtOpenFile","NtCreateFile","NtDeviceIoControlFile"},
     "risk":Risk.CRITICAL,"title":"Anti-Cheat Driver Communication",
     "detail":"Direct communication with anti-cheat drivers"},
    {"apis":{"NtQuerySystemInformation","NtSetSystemInformation","NtPowerInformation"},
     "risk":Risk.HIGH,"title":"System State Manipulation",
     "detail":"Modifies system state to fool anti-cheat"},
    
    # Self-Protection
    {"apis":{"NtSetInformationProcess","NtProtectVirtualMemory","NtClose"},
     "risk":Risk.HIGH,"title":"Process Protection",
     "detail":"Protects own process from termination/debugging"},
    {"apis":{"NtOpenKey","NtDeleteKey","NtRenameKey"},
     "risk":Risk.HIGH,"title":"Registry Trace Cleanup",
     "detail":"Deletes registry traces after execution"},
    
    # Fileless Techniques
    {"apis":{"NtCreateSection","NtMapViewOfSection","NtCreateThreadEx"},
     "risk":Risk.CRITICAL,"title":"Fileless Execution",
     "detail":"Executes code without writing to disk"},
    {"apis":{"NtCreateUserProcess","NtWriteVirtualMemory","NtResumeThread"},
     "risk":Risk.CRITICAL,"title":"Fileless Process Creation",
     "detail":"Creates process without executable file"},
    
    # Anti-Memory Scanning
    {"apis":{"NtFreeVirtualMemory","NtAllocateVirtualMemory","NtProtectVirtualMemory"},
     "risk":Risk.HIGH,"title":"Memory Garbage Collection",
     "detail":"Frees/allocates memory to evade scanning"},
    {"apis":{"VirtualProtect","VirtualAlloc","VirtualFree"},
     "risk":Risk.HIGH,"title":"Dynamic Memory Management",
     "detail":"Constantly changes memory to evade detection"},
    
    # Code Caves & Trampolines
    {"apis":{"VirtualProtectEx","WriteProcessMemory","ReadProcessMemory"},
     "risk":Risk.CRITICAL,"title":"Code Cave Injection",
     "detail":"Finds code caves in target process for injection"},
    
    # Mutex/Event Operations
    {"apis":{"CreateMutex","OpenMutex","ReleaseMutex"},
     "risk":Risk.LOW,"title":"Mutex Operations",
     "detail":"Mutex for single instance or synchronization"},
    {"apis":{"CreateEvent","OpenEvent","SetEvent","ResetEvent"},
     "risk":Risk.LOW,"title":"Event Operations",
     "detail":"Event signaling between processes"},
    
    # Named Pipe Communication
    {"apis":{"CreateNamedPipe","ConnectNamedPipe","DisconnectNamedPipe","CallNamedPipe"},
     "risk":Risk.MEDIUM,"title":"Named Pipe IPC",
     "detail":"Inter-process communication via named pipes"},
    
    # Windows Hooks for Various Purposes
    {"apis":{"SetWindowsHookEx","UnhookWindowsHookEx","CallNextHookEx"},
     "risk":Risk.HIGH,"title":"Windows Hook Management",
     "detail":"Installs/uninstalls various Windows hooks"},
    
    # Code Integrity & Signing
    {"apis":{"CryptQueryObject","CryptSignMessage","CryptVerifyMessageSignature"},
     "risk":Risk.MEDIUM,"title":"Code Signing Operations",
     "detail":"Signing or verifying signatures — can be used for fake signatures"},
    
    # Process Injection Variations
    {"apis":{"NtCreateThreadEx","RtlCreateUserThread","CreateRemoteThread"},
     "risk":Risk.CRITICAL,"title":"Multiple Thread Creation",
     "detail":"Uses multiple thread creation APIs for redundancy"},
    {"apis":{"WriteProcessMemory","NtWriteVirtualMemory","ZwWriteVirtualMemory"},
     "risk":Risk.CRITICAL,"title":"Multiple Memory Write APIs",
     "detail":"Uses different memory write APIs to avoid hooks"},
    
    # Anti-Dump Techniques
    {"apis":{"NtSetInformationProcess","NtProtectVirtualMemory","NtFlushInstructionCache"},
     "risk":Risk.HIGH,"title":"Process Hollowing Prevention",
     "detail":"Prevents process dumping via hollowing protection"},
    {"apis":{"VirtualProtect","VirtualProtectEx","WriteProcessMemory"},
     "risk":Risk.HIGH,"title":"Code Obfuscation at Runtime",
     "detail":"Obfuscates code in memory to prevent dumping"},
    
    # DLL Unlinking
    {"apis":{"NtQueryInformationProcess","NtReadVirtualMemory","NtWriteVirtualMemory"},
     "risk":Risk.CRITICAL,"title":"PEB Manipulation",
     "detail":"Modifies PEB to unlink DLLs from module list"},
    
    # Import Table Manipulation
    {"apis":{"NtQueryInformationProcess","NtReadVirtualMemory","NtProtectVirtualMemory"},
     "risk":Risk.CRITICAL,"title":"Import Table Wiping",
     "detail":"Wipes import table after resolution to evade detection"},
    
    # TLS Callbacks
    {"apis":{"NtSetInformationThread","NtQueueApcThread","NtAlertThread"},
     "risk":Risk.HIGH,"title":"TLS Callback Manipulation",
     "detail":"Uses TLS callbacks for early code execution"},
    
    # Exception Handling for Anti-Debug
    {"apis":{"AddVectoredExceptionHandler","RemoveVectoredExceptionHandler","RaiseException"},
     "risk":Risk.HIGH,"title":"VEH Anti-Debug",
     "detail":"Uses vectored exception handling to detect debuggers"},
    
    # Hardware Breakpoint Detection
    {"apis":{"NtGetContextThread","NtSetContextThread","NtContinue"},
     "risk":Risk.HIGH,"title":"Hardware Breakpoint Detection",
     "detail":"Checks thread context for hardware breakpoints"},
    
    # Sandbox Evasion via Environment
    {"apis":{"GetComputerName","GetUserName","GetEnvironmentVariable"},
     "risk":Risk.MEDIUM,"title":"Environment Checks",
     "detail":"Checks computer/user names for sandbox indicators"},
    
    # Mouse/Keyboard Simulation
    {"apis":{"mouse_event","keybd_event","SendInput"},
     "risk":Risk.MEDIUM,"title":"Input Simulation",
     "detail":"Simulates mouse/keyboard input for automation"},
    
    # Screenshot/Capture
    {"apis":{"BitBlt","GetDC","CreateCompatibleDC","CreateCompatibleBitmap"},
     "risk":Risk.HIGH,"title":"Screen Capture",
     "detail":"Captures screen content — potential wallhack/radar"},
    
    # Anti-Cheat Module Enumeration
    {"apis":{"CreateToolhelp32Snapshot","Module32First","Module32Next"},
     "risk":Risk.HIGH,"title":"Anti-Cheat Module Detection",
     "detail":"Enumerates modules to detect anti-cheat presence"},
    
    # Process Memory Scanning
    {"apis":{"ReadProcessMemory","VirtualQueryEx","WriteProcessMemory"},
     "risk":Risk.HIGH,"title":"Memory Scanning Pattern",
     "detail":"Scans process memory for values — cheat engine pattern"},
    
    # System Call Hooking Detection
    {"apis":{"NtQuerySystemInformation","NtSetSystemInformation","NtRaiseHardError"},
     "risk":Risk.HIGH,"title":"System Call Integrity Check",
     "detail":"Checks if system calls are hooked"},
    
    # Anti-AntiCheat Measures
    {"apis":{"NtOpenProcess","NtOpenThread","NtDuplicateObject"},
     "risk":Risk.CRITICAL,"title":"AntiCheat Process Manipulation",
     "detail":"Opens and manipulates anti-cheat processes"},
    
    # Firmware Level
    {"apis":{"NtOpenFirmwareTable","NtEnumerateFirmwareTables","NtSetFirmwareTable"},
     "risk":Risk.CRITICAL,"title":"Firmware Manipulation",
     "detail":"Accesses/modifies firmware tables — UEFI level persistence"},
    
    # Boot Configuration
    {"apis":{"NtOpenKey","NtSetValueKey","NtDeleteKey"},
     "risk":Risk.CRITICAL,"title":"BCD Manipulation",
     "detail":"Modifies boot configuration — bootkit patterns"},
    
    # Driver Communication
    {"apis":{"CreateFile","DeviceIoControl","CloseHandle"},
     "risk":Risk.CRITICAL,"title":"Driver Communication",
     "detail":"Communicates with kernel driver for cheat operations"},
    
    # Memory Descriptor List Manipulation
    {"apis":{"NtAllocateVirtualMemory","NtFreeVirtualMemory","NtLockVirtualMemory"},
     "risk":Risk.CRITICAL,"title":"MDL Manipulation",
     "detail":"Manipulates Memory Descriptor Lists for kernel access"},
    
    # Interrupt Descriptor Table
    {"apis":{"NtSetInformationKernel","NtQuerySystemInformation","NtRaiseHardError"},
     "risk":Risk.CRITICAL,"title":"IDT Manipulation",
     "detail":"Potential IDT hooking for kernel-level stealth"},
    
    # System Service Descriptor Table
    {"apis":{"NtSetSystemInformation","NtQuerySystemInformation","NtRaiseHardError"},
     "risk":Risk.CRITICAL,"title":"SSDT Hooking Pattern",
     "detail":"Pattern indicating SSDT hooking for kernel control"},
    
    # Cache Control
    {"apis":{"NtFlushInstructionCache","NtFlushWriteBuffer","NtSetInformationProcess"},
     "risk":Risk.HIGH,"title":"Cache Manipulation",
     "detail":"Flushes caches — often after code modification"},
    
    # Power Management
    {"apis":{"NtPowerInformation","NtSetThreadExecutionState","NtRaiseHardError"},
     "risk":Risk.MEDIUM,"title":"Power State Checks",
     "detail":"Checks power state — VM detection"},
    
    # Time Manipulation
    {"apis":{"NtQuerySystemTime","NtSetSystemTime","NtQueryPerformanceCounter"},
     "risk":Risk.HIGH,"title":"Time Manipulation",
     "detail":"Modifies system time — anti-timing checks"},
    
    # Security Descriptor
    {"apis":{"NtQuerySecurityObject","NtSetSecurityObject","NtOpenKey"},
     "risk":Risk.HIGH,"title":"Security Descriptor Manipulation",
     "detail":"Modifies security descriptors for access"},
    
    # Memory Barriers
    {"apis":{"NtReadVirtualMemory","NtWriteVirtualMemory","NtFlushVirtualMemory"},
     "risk":Risk.HIGH,"title":"Memory Barrier Operations",
     "detail":"Memory barriers for synchronization in multi-threaded cheats"},
    
    # Atomic Operations
    {"apis":{"InterlockedIncrement","InterlockedDecrement","InterlockedExchange"},
     "risk":Risk.LOW,"title":"Atomic Operations",
     "detail":"Atomic operations for thread-safe cheat state"},
    
    # Critical Sections
    {"apis":{"InitializeCriticalSection","EnterCriticalSection","LeaveCriticalSection","DeleteCriticalSection"},
     "risk":Risk.LOW,"title":"Critical Section Usage",
     "detail":"Thread synchronization in cheat code"},
    
    # Resource Enumeration
    {"apis":{"EnumResourceNames","FindResource","LoadResource","LockResource"},
     "risk":Risk.MEDIUM,"title":"Resource Enumeration",
     "detail":"Enumerates resources — potential payload extraction"},
    
    # Version Information
    {"apis":{"GetFileVersionInfo","GetFileVersionInfoSize","VerQueryValue"},
     "risk":Risk.LOW,"title":"Version Information Checks",
     "detail":"Checks file versions — target identification"},
    
    # Dynamic-Link Library Search Order
    {"apis":{"SetDllDirectory","AddDllDirectory","RemoveDllDirectory"},
     "risk":Risk.HIGH,"title":"DLL Directory Manipulation",
     "detail":"Changes DLL search order — DLL hijacking potential"},
    
    # KnownDLLs Bypass
    {"apis":{"NtOpenKey","NtSetValueKey","NtDeleteKey"},
     "risk":Risk.CRITICAL,"title":"KnownDLLs Manipulation",
     "detail":"Modifies KnownDLLs registry key for hijacking"},
    
    # AppInit_DLLs
    {"apis":{"RegSetValueEx","RegCreateKeyEx","RegOpenKeyEx"},
     "risk":Risk.HIGH,"title":"AppInit_DLLs Persistence",
     "detail":"Sets AppInit_DLLs registry for global DLL loading"},
    
    # Winlogon Notify
    {"apis":{"RegSetValueEx","RegCreateKeyEx","RegOpenKeyEx"},
     "risk":Risk.HIGH,"title":"Winlogon Notify Persistence",
     "detail":"Winlogon notification package persistence"},
    
    # Image File Execution Options
    {"apis":{"RegSetValueEx","RegCreateKeyEx","RegOpenKeyEx"},
     "risk":Risk.HIGH,"title":"IFEO Hijacking",
     "detail":"Image File Execution Options debugger key hijacking"},
    
    # Shim Database
    {"apis":{"sdbOpenDatabase","sdbReadEntry","sdbWriteEntry"},
     "risk":Risk.CRITICAL,"title":"Application Shim Manipulation",
     "detail":"Application compatibility shim database modification"},
    
    # Windows Filtering Platform
    {"apis":{"FwpmEngineOpen","FwpmFilterAdd","FwpmFilterDelete"},
     "risk":Risk.HIGH,"title":"WFP Manipulation",
     "detail":"Windows Filtering Platform — network filtering/redirection"},
    
    # Windows Sockets SPI
    {"apis":{"WSCInstallProvider","WSCDeinstallProvider","WSCWriteProviderOrder"},
     "risk":Risk.CRITICAL,"title":"LSP Hijacking",
     "detail":"Layered Service Provider installation — network traffic interception"},
    
    # Windows Hooks (Various Types)
    {"apis":{"SetWindowsHookEx","CallNextHookEx","UnhookWindowsHookEx"},
     "risk":Risk.HIGH,"title":"Windows Hook System",
     "detail":"Various hook types (WH_KEYBOARD, WH_MOUSE, WH_CBT, etc.)"},
    
    # CBT Hooks
    {"apis":{"SetWindowsHookEx","CallNextHookEx","UnhookWindowsHookEx"},
     "risk":Risk.HIGH,"title":"Computer-Based Training Hooks",
     "detail":"CBT hooks monitor window creation/activation/destruction"},
    
    # Journal Hooks
    {"apis":{"SetWindowsHookEx","CallNextHookEx","UnhookWindowsHookEx"},
     "risk":Risk.HIGH,"title":"Journal Record/Playback Hooks",
     "detail":"Journal hooks record/playback input events"},
    
    # Message Filters
    {"apis":{"SetMessageExtraInfo","GetMessageExtraInfo","GetQueueStatus"},
     "risk":Risk.MEDIUM,"title":"Message Queue Manipulation",
     "detail":"Message queue filtering and monitoring"},
    
    # Timer Operations
    {"apis":{"SetTimer","KillTimer","SetWaitableTimer"},
     "risk":Risk.MEDIUM,"title":"Timer Operations",
     "detail":"Timers for periodic cheat operations"},
    
    # Wait Operations
    {"apis":{"WaitForSingleObject","WaitForMultipleObjects","MsgWaitForMultipleObjects"},
     "risk":Risk.MEDIUM,"title":"Wait Operations",
     "detail":"Synchronization waits in cheat code"},
    
    # High-Resolution Timers
    {"apis":{"QueryPerformanceCounter","QueryPerformanceFrequency","timeGetTime"},
     "risk":Risk.MEDIUM,"title":"High-Resolution Timing",
     "detail":"Precise timing for aimbot/speedhack"},
    
    # Multimedia Timers
    {"apis":{"timeSetEvent","timeKillEvent","timeBeginPeriod","timeEndPeriod"},
     "risk":Risk.MEDIUM,"title":"Multimedia Timers",
     "detail":"High-precision multimedia timers"},
    
    # Console Operations
    {"apis":{"AllocConsole","FreeConsole","AttachConsole","GetConsoleWindow"},
     "risk":Risk.LOW,"title":"Console Operations",
     "detail":"Console management for cheat UI"},
    
    # Window Station/Desktop
    {"apis":{"OpenWindowStation","CreateWindowStation","OpenDesktop","CreateDesktop"},
     "risk":Risk.HIGH,"title":"Window Station/Desktop Manipulation",
     "detail":"Creates isolated desktops for cheat windows"},
    
    # Clipboard
    {"apis":{"OpenClipboard","GetClipboardData","SetClipboardData","CloseClipboard"},
     "risk":Risk.MEDIUM,"title":"Clipboard Operations",
     "detail":"Clipboard monitoring/manipulation"},
    
    # Data Copy
    {"apis":{"WM_COPYDATA","SendMessage","PostMessage"},
     "risk":Risk.MEDIUM,"title":"WM_COPYDATA Communication",
     "detail":"Window message-based IPC"},
    
    # Dynamic Data Exchange
    {"apis":{"DdeInitialize","DdeConnect","DdeClientTransaction","DdeUninitialize"},
     "risk":Risk.MEDIUM,"title":"DDE Communication",
     "detail":"Legacy DDE protocol for IPC"},
    
    # OLE/COM
    {"apis":{"CoInitialize","CoCreateInstance","CoUninitialize","CoGetClassObject"},
     "risk":Risk.HIGH,"title":"COM Operations",
     "detail":"COM object creation — automation/persistence"},
    
    # BSTR Operations
    {"apis":{"SysAllocString","SysFreeString","SysReAllocString","SysStringLen"},
     "risk":Risk.LOW,"title":"BSTR Operations",
     "detail":"COM string manipulation"},
    
    # Variant Operations
    {"apis":{"VariantInit","VariantClear","VariantCopy","VariantChangeType"},
     "risk":Risk.LOW,"title":"Variant Operations",
     "detail":"COM variant manipulation"},
    
    # SafeArray Operations
    {"apis":{"SafeArrayCreate","SafeArrayDestroy","SafeArrayAccessData","SafeArrayUnaccessData"},
     "risk":Risk.LOW,"title":"SafeArray Operations",
     "detail":"COM array manipulation"},
    
    # Type Library
    {"apis":{"LoadTypeLib","LoadRegTypeLib","QueryPathOfRegTypeLib"},
     "risk":Risk.MEDIUM,"title":"Type Library Operations",
     "detail":"Type library loading — COM automation"},
    
    # ActiveX
    {"apis":{"CoCreateInstance","CoGetClassObject","CoRegisterClassObject","CoRevokeClassObject"},
     "risk":Risk.HIGH,"title":"ActiveX Operations",
     "detail":"ActiveX control registration/creation"},
    
    # Internet Explorer COM
    {"apis":{"CoCreateInstance","IWebBrowser2::Navigate","IWebBrowser2::get_Document"},
     "risk":Risk.HIGH,"title":"IE COM Automation",
     "detail":"Internet Explorer automation for web-based cheats"},
    
    # XMLHTTP
    {"apis":{"CoCreateInstance","IXMLHTTPRequest::open","IXMLHTTPRequest::send"},
     "risk":Risk.HIGH,"title":"XMLHTTP Requests",
     "detail":"AJAX requests for cheat C2"},
    
    # WinHTTP
    {"apis":{"WinHttpOpen","WinHttpConnect","WinHttpOpenRequest","WinHttpSendRequest","WinHttpReceiveResponse"},
     "risk":Risk.HIGH,"title":"WinHTTP Communication",
     "detail":"HTTP communication via WinHTTP API"},
    
    # WinINet
    {"apis":{"InternetOpen","InternetConnect","HttpOpenRequest","HttpSendRequest","InternetReadFile"},
     "risk":Risk.HIGH,"title":"WinINet Communication",
     "detail":"HTTP communication via WinINet API"},
    
    # WebSocket
    {"apis":{"WebSocketCreateClientHandle","WebSocketSend","WebSocketReceive","WebSocketAbortHandle"},
     "risk":Risk.HIGH,"title":"WebSocket Communication",
     "detail":"WebSocket for real-time cheat C2"},
    
    # FTP
    {"apis":{"InternetOpen","InternetConnect","FtpGetFile","FtpPutFile","FtpDeleteFile"},
     "risk":Risk.HIGH,"title":"FTP Operations",
     "detail":"FTP for file transfer"},
    
    # DNS
    {"apis":{"getaddrinfo","getnameinfo","DnsQuery","DnsRecordSetFree"},
     "risk":Risk.MEDIUM,"title":"DNS Operations",
     "detail":"DNS queries — potential DNS tunneling"},
    
    # ICMP
    {"apis":{"IcmpCreateFile","IcmpSendEcho","IcmpCloseHandle"},
     "risk":Risk.MEDIUM,"title":"ICMP Operations",
     "detail":"ICMP for C2 communication"},
    
    # Raw Sockets
    {"apis":{"socket","setsockopt","bind","recvfrom","sendto"},
     "risk":Risk.HIGH,"title":"Raw Socket Operations",
     "detail":"Raw sockets for packet crafting"},
    
    # Packet Filtering
    {"apis":{"WSALookupService","WSAEnumProtocols","WSASetService"},
     "risk":Risk.MEDIUM,"title":"Network Service Operations",
     "detail":"Network service discovery"},
    
    # IP Helper,
]

HASH_BLACKLIST: dict = {}  # sha256 → name

SUBSYSTEMS = {
    0:"Unknown",1:"Native",2:"Windows GUI",3:"Windows CUI",
    9:"Windows CE",10:"EFI App",
}

# ══════════════════════════════════════════════════════════════
# PE PARSER
# ══════════════════════════════════════════════════════════════
class PEParser:
    def __init__(self, data:bytes):
        self.data=data; self.valid=False; self.is_64=False
        self.is_dll=False; self.machine=0; self.subsystem=0
        self.timestamp=0; self.imports=[]; self.sections=[]
        self._parse()

    def _u16(self,o): return struct.unpack_from("<H",self.data,o)[0]
    def _u32(self,o): return struct.unpack_from("<I",self.data,o)[0]
    def _u64(self,o): return struct.unpack_from("<Q",self.data,o)[0]

    def _parse(self):
        d=self.data
        if len(d)<64 or d[:2]!=b"MZ": return
        pe_off=self._u32(0x3C)
        if pe_off+24>len(d) or d[pe_off:pe_off+4]!=b"PE\x00\x00": return
        self.valid=True
        self.machine=self._u16(pe_off+4)
        num_sec=self._u16(pe_off+6)
        self.timestamp=self._u32(pe_off+8)
        chars=self._u16(pe_off+22)
        self.is_dll=bool(chars&0x2000)
        self.is_64=(self.machine==0x8664)
        opt_size=self._u16(pe_off+20)
        opt_off=pe_off+24
        sub_off=opt_off+68
        if sub_off+2<=len(d): self.subsystem=self._u16(sub_off)
        dd_base=opt_off+(112 if self.is_64 else 96)
        sec_off=opt_off+opt_size
        for i in range(num_sec):
            so=sec_off+i*40
            if so+40>len(d): break
            name=d[so:so+8].rstrip(b"\x00").decode("latin-1","replace")
            self.sections.append({
                "name":name,"vaddr":self._u32(so+12),
                "vsize":self._u32(so+16),"rawoff":self._u32(so+20),
                "rawsize":self._u32(so+24),"chars":self._u32(so+36),"entropy":0.0})

        def rva2off(rva):
            for s in self.sections:
                if s["vaddr"]<=rva<s["vaddr"]+max(s["vsize"],s["rawsize"],1):
                    return s["rawoff"]+(rva-s["vaddr"])
            return rva

        if dd_base+16<=len(d):
            imp_rva=self._u32(dd_base+8)
            if imp_rva:
                try:
                    idx=rva2off(imp_rva)
                    while idx+20<=len(d):
                        name_rva=self._u32(idx+12)
                        oft=self._u32(idx); ft=self._u32(idx+16)
                        if name_rva==0: break
                        thunk_off=rva2off(oft or ft)
                        ps=8 if self.is_64 else 4; ti=thunk_off
                        while ti+ps<=len(d):
                            val=self._u64(ti) if self.is_64 else self._u32(ti)
                            ti+=ps
                            if val==0: break
                            hb=(1<<63) if self.is_64 else 0x80000000
                            if val&hb: continue
                            ho=rva2off(val&0x7FFFFFFF)+2
                            end=d.find(b"\x00",ho,ho+256)
                            if end==-1: continue
                            fn=d[ho:end].decode("latin-1","replace")
                            if fn: self.imports.append(fn)
                        idx+=20
                except: pass

# ══════════════════════════════════════════════════════════════
# ANALYZE ONE FILE
# ══════════════════════════════════════════════════════════════
def _entropy(data:bytes)->float:
    if not data: return 0.0
    c=[0]*256
    for b in data: c[b]+=1
    n=len(data); e=0.0
    for x in c:
        if x:
            p=x/n; e-=p*math.log2(p)
    return e

def analyze_file(path:str)->FileResult:
    t0=time.time()
    try:
        fsize = os.path.getsize(path)
        with open(path,"rb") as f:
            # Read full file but cap string scan data at 10MB
            data = f.read()
    except Exception as e:
        return FileResult(path=path,size=0,sha256="",md5="",
            file_type="?",arch="?",compile_time="?",is_packed=False,
            overall_risk=Risk.CLEAN,error=str(e))
    # For very large files only scan first+last 5MB for strings
    scan_data = data if len(data) <= 10*1024*1024 else data[:5*1024*1024] + data[-5*1024*1024:]

    sha256=hashlib.sha256(data).hexdigest()
    md5   =hashlib.md5(data).hexdigest()
    pe    =PEParser(data)
    findings=[]

    # File type
    if pe.valid:
        arch=  "x64" if pe.is_64 else "x86"
        kind=  "DLL" if pe.is_dll else "EXE"
        ftype= f"PE {kind} ({arch})"
        mmap = {0x14c:"i386",0x8664:"AMD64",0x1c0:"ARM",0xaa64:"ARM64"}
        arch_s=mmap.get(pe.machine,f"0x{pe.machine:04x}")
        try:
            ct=datetime.utcfromtimestamp(pe.timestamp).strftime("%Y-%m-%d %H:%M UTC")
        except: ct="?"
    else:
        ftype="Non-PE / Unknown"; arch_s="?"; ct="?"

    # Hash blacklist
    if sha256 in HASH_BLACKLIST:
        findings.append(Finding("HashBlacklist",Risk.CRITICAL,
            f"Known cheat: {HASH_BLACKLIST[sha256]}",
            "SHA-256 matches blacklisted tool",[f"Hash: {sha256[:32]}…"]))

    # String scan
    ascii_s  = re.findall(rb"[\x20-\x7e]{5,}",scan_data)
    uni_s    = re.findall(rb"(?:[\x20-\x7e]\x00){5,}",scan_data)
    decoded  = [s.decode("ascii","replace").lower() for s in ascii_s]
    for us in uni_s:
        try: decoded.append(us.decode("utf-16-le","replace").lower())
        except: pass

    hits={r:[] for r in Risk}; seen=set()
    for text in decoded:
        for kw,risk in CHEAT_STRINGS.items():
            if kw in text and kw not in seen:
                seen.add(kw); hits[risk].append(kw)

    for risk in [Risk.CRITICAL,Risk.HIGH,Risk.MEDIUM,Risk.LOW]:
        h=hits[risk]
        if h:
            findings.append(Finding("StringScan",risk,
                f"{len(h)} {risk.label} string(s)",
                "Suspicious strings in binary",h[:12]))

    # Entropy
    ov_ent=_entropy(data); packed=(ov_ent>7.2)
    if ov_ent>7.2:
        findings.append(Finding("Entropy",Risk.HIGH,
            f"High entropy {ov_ent:.3f} — packed/encrypted",
            "Binary likely packed (UPX/VMProtect/Themida)",
            [f"Entropy: {ov_ent:.4f}"]))
    elif ov_ent>6.8:
        findings.append(Finding("Entropy",Risk.MEDIUM,
            f"Elevated entropy {ov_ent:.3f}",
            "Possibly compressed or obfuscated",
            [f"Entropy: {ov_ent:.4f}"]))

    for s in pe.sections:
        ro=s["rawoff"]; rs=s["rawsize"]
        if rs<512: continue
        e=_entropy(data[ro:ro+rs]); s["entropy"]=e
        is_exec=bool(s["chars"]&0x20000000)
        if e>7.2 and is_exec:
            findings.append(Finding("Entropy",Risk.HIGH,
                f"Section '{s['name']}' entropy {e:.3f} (exec+packed)",
                "Packed executable section",
                [f"Section:{s['name']} Entropy:{e:.4f}"]))

    # Import table
    if pe.valid and pe.imports:
        imp_set=set(pe.imports)
        single={r:[] for r in Risk}
        for api in imp_set:
            if api in SUSPICIOUS_IMPORTS:
                r2,desc=SUSPICIOUS_IMPORTS[api]; single[r2].append((api,desc))
        for risk in [Risk.CRITICAL,Risk.HIGH,Risk.MEDIUM,Risk.LOW]:
            h2=single[risk]
            if h2:
                findings.append(Finding("ImportTable",risk,
                    f"{len(h2)} {risk.label} import(s)",
                    "Suspicious Windows API imports",
                    [f"{a}  —  {d}" for a,d in h2[:10]]))
        imp_lower={i.lower() for i in imp_set}
        for combo in DANGEROUS_COMBOS:
            req={a.lower() for a in combo["apis"]}
            if req.issubset(imp_lower):
                matched=sorted(a for a in imp_set if a.lower() in req)
                findings.append(Finding("ImportCombo",combo["risk"],
                    combo["title"],combo["detail"],
                    [f"APIs: {', '.join(matched)}"]))

    if not pe.valid and len(data)>2:
        findings.append(Finding("Structure",Risk.MEDIUM,
            "Not a valid PE","No MZ/PE header — packed/shellcode?",
            [f"First bytes: {data[:8].hex()}"]))

    overall=max((f.risk for f in findings),key=lambda r:r.score,
                default=Risk.CLEAN)
    ms=(time.time()-t0)*1000
    return FileResult(
        path=path,size=len(data),sha256=sha256,md5=md5,
        file_type=ftype,arch=arch_s,compile_time=ct,
        is_packed=packed,overall_risk=overall,
        findings=sorted(findings,key=lambda f:-f.risk.score),
        imports=pe.imports,sections=pe.sections,
        strings_found=list(seen),scan_time_ms=ms)

# ══════════════════════════════════════════════════════════════
# FOLDER WALKER
# ══════════════════════════════════════════════════════════════
def collect_files(root_path:str, exts=SCAN_EXTENSIONS)->list:
    files=[]
    try:
        for dirpath,_,filenames in os.walk(root_path):
            for fn in filenames:
                if os.path.splitext(fn)[1].lower() in exts:
                    files.append(os.path.join(dirpath,fn))
    except Exception:
        pass
    return files

# ══════════════════════════════════════════════════════════════
# REPORT GENERATORS
# ══════════════════════════════════════════════════════════════
def gen_txt(results:list, scan_path:str, elapsed:float)->str:
    sep ="═"*72; sep2="─"*72
    lines=[sep,
        "  ANTI-CHEAT FOLDER SCANNER — FULL REPORT",
        f"  Scan Path : {scan_path}",
        f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Duration  : {elapsed:.1f}s",
        f"  Files     : {len(results)} scanned",
        sep,""]

    # Summary
    by_risk={r.label:[] for r in Risk}
    for res in results: by_risk[res.overall_risk.label].append(res)
    lines+=["  SUMMARY",sep2]
    for label in ["CRITICAL","HIGH","MEDIUM","LOW","CLEAN"]:
        n=len(by_risk[label])
        if n: lines.append(f"  {label:<10}: {n} file(s)")
    lines+=[""]

    # Only suspicious
    suspicious=[r for r in results if r.overall_risk.score>=2]
    suspicious.sort(key=lambda r:-r.overall_risk.score)

    lines+=[f"  SUSPICIOUS FILES ({len(suspicious)})",sep2,""]
    for i,res in enumerate(suspicious,1):
        lines+=[
            f"  [{i:03}] {res.overall_risk.icon} {res.overall_risk.label}  "
            f"{os.path.basename(res.path)}",
            f"         Path    : {res.path}",
            f"         Type    : {res.file_type}  |  "
            f"Size: {res.size/1024:.1f} KB  |  Packed: {'YES' if res.is_packed else 'No'}",
            f"         SHA-256 : {res.sha256}",
            f"         MD5     : {res.md5}",
            f"         Findings: {len(res.findings)}",
        ]
        for f in res.findings:
            lines.append(f"           {f.risk.icon} [{f.risk.label}][{f.category}] {f.title}")
            lines.append(f"              {f.detail}")
            for ev in f.evidence[:5]:
                lines.append(f"              • {ev}")
        lines.append("")
    lines+=[sep,"  END OF REPORT",sep]
    return "\n".join(lines)

def gen_html(results:list, scan_path:str, elapsed:float)->str:
    rc={"CLEAN":"#3fb950","LOW":"#58a6ff","MEDIUM":"#e3b341",
        "HIGH":"#d29922","CRITICAL":"#f85149"}
    icons={"CLEAN":"✅","LOW":"ℹ","MEDIUM":"⚠","HIGH":"🔶","CRITICAL":"🚨"}

    by_risk={r.label:[] for r in Risk}
    for res in results: by_risk[res.overall_risk.label].append(res)
    suspicious=[r for r in results if r.overall_risk.score>=2]
    suspicious.sort(key=lambda r:-r.overall_risk.score)

    cards=""
    for res in suspicious:
        rlabel=res.overall_risk.label
        color =rc[rlabel]
        finds_html=""
        for f in res.findings:
            fc=rc[f.risk.label]
            evs="".join(f'<li style="color:#8b949e;font-size:12px">{e}</li>'
                        for e in f.evidence[:6])
            finds_html+=f"""
            <div style="border-left:3px solid {fc};padding:6px 10px;
                 margin:5px 0;background:#0d1117;border-radius:3px">
              <span style="color:{fc};font-weight:bold;font-size:12px">
                {f.risk.icon} [{f.risk.label}][{f.category}]</span>
              <span style="color:#e6edf3;margin-left:6px;font-size:12px">{f.title}</span>
              <p style="color:#8b949e;margin:3px 0;font-size:11px">{f.detail}</p>
              <ul style="margin:2px 0 2px 14px">{evs}</ul>
            </div>"""

        cards+=f"""
        <div style="background:#161b22;border:1px solid #30363d;
             border-radius:8px;margin:12px 0;padding:16px;
             border-top:3px solid {color}">
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:10px">
            <span style="background:{color};color:#0d1117;padding:3px 10px;
                  border-radius:12px;font-weight:bold;font-size:12px">
              {res.overall_risk.icon} {rlabel}</span>
            <span style="color:#e6edf3;font-weight:bold;font-size:14px">
              {os.path.basename(res.path)}</span>
            <span style="color:#8b949e;font-size:12px;margin-left:auto">
              {len(res.findings)} findings</span>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;
               gap:4px 20px;font-size:12px;color:#8b949e;margin-bottom:10px">
            <div><b style="color:#58a6ff">Path</b>: {res.path}</div>
            <div><b style="color:#58a6ff">Type</b>: {res.file_type}</div>
            <div><b style="color:#58a6ff">Size</b>: {res.size/1024:.1f} KB</div>
            <div><b style="color:#58a6ff">Packed</b>:
              {'<span style="color:#f85149">YES ⚠</span>' if res.is_packed
               else '<span style="color:#3fb950">No</span>'}</div>
            <div style="grid-column:1/-1">
              <b style="color:#58a6ff">SHA-256</b>:
              <span style="font-family:Consolas;color:#3fb950;font-size:11px">
                {res.sha256}</span></div>
            <div style="grid-column:1/-1">
              <b style="color:#58a6ff">MD5</b>:
              <span style="font-family:Consolas;color:#3fb950;font-size:11px">
                {res.md5}</span></div>
          </div>
          {finds_html}
        </div>"""

    # Summary bar
    sumbar=""
    for label in ["CRITICAL","HIGH","MEDIUM","LOW","CLEAN"]:
        n=len(by_risk[label])
        if n:
            sumbar+=f"""<div style="text-align:center;padding:8px 16px;
              background:#161b22;border-radius:6px;border-top:3px solid {rc[label]}">
              <div style="color:{rc[label]};font-size:22px;font-weight:bold">{n}</div>
              <div style="color:#8b949e;font-size:11px">{icons[label]} {label}</div>
            </div>"""

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Folder Scan Report</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0d1117;color:#e6edf3;font-family:'Segoe UI',sans-serif;
       padding:24px;max-width:1100px;margin:0 auto}}
  h1{{color:#58a6ff;font-size:22px;margin-bottom:4px}}
  h2{{color:#58a6ff;font-size:15px;margin:24px 0 8px;
      border-left:3px solid #58a6ff;padding-left:10px}}
  .meta{{color:#8b949e;font-size:13px;margin-bottom:20px}}
  .sumgrid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));
            gap:10px;margin:16px 0 24px}}
</style></head><body>
<h1>🛡 Anti-Cheat Folder Scanner — Report</h1>
<div class="meta">
  📁 {scan_path} &nbsp;|&nbsp;
  🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
  ⚡ {elapsed:.1f}s &nbsp;|&nbsp;
  📄 {len(results)} files scanned
</div>

<h2>Summary</h2>
<div class="sumgrid">{sumbar}</div>

<h2>Suspicious Files ({len(suspicious)})</h2>
{cards if cards else '<p style="color:#3fb950">✅ No suspicious files found.</p>'}

<p style="color:#30363d;font-size:11px;margin-top:40px;text-align:center">
Anti-Cheat Scanner • {datetime.now().year}</p>
</body></html>"""

def gen_json(results:list, scan_path:str, elapsed:float)->str:
    data={
        "scan_path":scan_path,
        "generated":datetime.now().isoformat(),
        "duration_s":round(elapsed,2),
        "total_files":len(results),
        "summary":{r.label:sum(1 for x in results
                               if x.overall_risk.label==r.label)
                   for r in Risk},
        "suspicious":[{
            "path":r.path,"sha256":r.sha256,"md5":r.md5,
            "type":r.file_type,"size":r.size,
            "risk":r.overall_risk.label,"packed":r.is_packed,
            "findings":[{"category":f.category,"risk":f.risk.label,
                         "title":f.title,"detail":f.detail,
                         "evidence":f.evidence}
                        for f in r.findings],
            "suspicious_strings":r.strings_found,
        } for r in results if r.overall_risk.score>=2],
    }
    return json.dumps(data,indent=2,ensure_ascii=False)

# ══════════════════════════════════════════════════════════════
# MAIN GUI
# ══════════════════════════════════════════════════════════════
class ScannerGUI:
    def __init__(self, root:tk.Tk):
        self.root=root
        self._results:list[FileResult]=[]
        self._scan_q:queue.Queue=queue.Queue()
        self._running=False
        self._start_t=0.0
        self._total=0
        self._done=0
        self._executor:Optional[ThreadPoolExecutor]=None
        self._build()
        self._poll()

    # ── BUILD ─────────────────────────────────────────────────
    def _build(self):
        self.root.title("Anti-Cheat Folder Scanner")
        self.root.geometry("1160x780")
        self.root.minsize(960,640)
        self.root.configure(bg=BG)
        self._header()
        self._path_bar()
        self._stat_bar()
        self._body()
        self._footer()

    def _header(self):
        h=tk.Frame(self.root,bg=PANEL,height=54)
        h.pack(fill="x"); h.pack_propagate(False)
        tk.Label(h,text="🔍  ANTI-CHEAT FOLDER SCANNER",
                 font=("Segoe UI",13,"bold"),
                 bg=PANEL,fg=BLUE).pack(side="left",padx=18,pady=10)
        tk.Label(h,text="EXE · DLL · SYS · DRV · OCX — Recursive Scan",
                 font=UI,bg=PANEL,fg=DIM).pack(side="left")

    def _path_bar(self):
        bar=tk.Frame(self.root,bg=PANEL2,
                     highlightthickness=1,highlightbackground=BORDER)
        bar.pack(fill="x",padx=10,pady=(8,0))

        tk.Label(bar,text="📁 Scan Path:",
                 font=UI_B,bg=PANEL2,fg=FG).pack(side="left",padx=(10,6),pady=8)

        self.path_var=tk.StringVar(value="C:\\")
        path_entry=tk.Entry(bar,textvariable=self.path_var,
                            font=("Consolas",10),bg=BG,fg=GREEN,
                            insertbackground=FG,relief="flat",width=55)
        path_entry.pack(side="left",ipady=4,pady=8)

        tk.Button(bar,text="📂 Browse",font=UI,
                  bg="#21262d",fg=BLUE,relief="flat",cursor="hand2",padx=10,
                  command=self._browse_folder).pack(side="left",padx=6,pady=8)

        # Quick paths
        tk.Label(bar,text="Quick:",font=UI,bg=PANEL2,fg=DIM).pack(side="left",padx=(10,4))
        for label,path in [("C:\\","C:\\"),("Program Files","C:\\Program Files"),
                            ("AppData",os.path.expanduser("~\\AppData")),
                            ("Downloads",os.path.expanduser("~\\Downloads"))]:
            tk.Button(bar,text=label,font=("Segoe UI",8),
                      bg="#21262d",fg=DIM,relief="flat",cursor="hand2",padx=6,
                      command=lambda p=path:self._set_path(p)
                      ).pack(side="left",padx=2,pady=8)

        # Scan button
        self.scan_btn=tk.Button(bar,text="▶  START SCAN",
                                font=("Segoe UI",9,"bold"),
                                bg=GREEN,fg=BG,relief="flat",
                                cursor="hand2",padx=16,
                                command=self._start_scan)
        self.scan_btn.pack(side="right",padx=10,pady=8)

        self.stop_btn=tk.Button(bar,text="⏹ Stop",font=UI,
                                bg="#21262d",fg=RED,relief="flat",
                                cursor="hand2",padx=10,state="disabled",
                                command=self._stop_scan)
        self.stop_btn.pack(side="right",padx=4,pady=8)

        # Filter
        tk.Label(bar,text="Show:",font=UI,bg=PANEL2,fg=DIM).pack(side="right",padx=(10,2))
        self.filter_var=tk.StringVar(value="ALL")
        for opt in ["ALL","CRITICAL","HIGH","MEDIUM","LOW"]:
            tk.Radiobutton(bar,text=opt,variable=self.filter_var,value=opt,
                           font=("Segoe UI",8),bg=PANEL2,fg=FG,
                           selectcolor=BG,activebackground=PANEL2,
                           relief="flat",cursor="hand2",
                           command=self._apply_filter
                           ).pack(side="right",padx=3)

    def _stat_bar(self):
        sb=tk.Frame(self.root,bg=PANEL,height=40,
                    highlightthickness=1,highlightbackground=BORDER)
        sb.pack(fill="x",padx=10,pady=4)
        sb.pack_propagate(False)
        defs=[("SCANNED","0","s_scanned",DIM),
              ("SUSPICIOUS","0","s_sus",ORANGE),
              ("CRITICAL","0","s_crit",RED),
              ("HIGH","0","s_high",ORANGE),
              ("MEDIUM","0","s_med",YELLOW),
              ("LOW","0","s_low",BLUE),
              ("CLEAN","0","s_clean",GREEN),
              ("SPEED","—","s_speed",DIM),
              ("ETA","—","s_eta",DIM)]
        for title,init,attr,color in defs:
            cell=tk.Frame(sb,bg=PANEL); cell.pack(side="left",expand=True)
            tk.Label(cell,text=title,font=("Segoe UI",7),bg=PANEL,fg=DIM).pack()
            lbl=tk.Label(cell,text=init,font=("Segoe UI",10,"bold"),bg=PANEL,fg=color)
            lbl.pack(); setattr(self,attr,lbl)

    def _body(self):
        pane=tk.PanedWindow(self.root,orient="horizontal",
                            bg=BG,sashwidth=6)
        pane.pack(fill="both",expand=True,padx=10,pady=(0,4))

        # ── Left: result list ─────────────────────────────────
        left=tk.Frame(pane,bg=PANEL,
                      highlightthickness=1,highlightbackground=BORDER)
        pane.add(left,minsize=560)

        hdr=tk.Frame(left,bg=PANEL)
        hdr.pack(fill="x",padx=8,pady=(6,2))
        tk.Label(hdr,text="Scan Results",font=UI_B,
                 bg=PANEL,fg=DIM).pack(side="left")
        self.count_lbl=tk.Label(hdr,text="",font=UI,bg=PANEL,fg=DIM)
        self.count_lbl.pack(side="right")

        cols=("risk","filename","type","size","findings","path")
        self.tree=ttk.Treeview(left,columns=cols,show="headings",height=30)
        sty=ttk.Style(); sty.theme_use("clam")
        sty.configure("Treeview",background=BG,fieldbackground=BG,
                      foreground=FG,font=MONO,rowheight=21,borderwidth=0)
        sty.configure("Treeview.Heading",background=PANEL,foreground=DIM,
                      font=("Segoe UI",8,"bold"))
        sty.map("Treeview",background=[("selected","#264f78")],
                foreground=[("selected",FG)])

        self.tree.heading("risk",    text="Risk")
        self.tree.heading("filename",text="File Name")
        self.tree.heading("type",    text="Type")
        self.tree.heading("size",    text="Size")
        self.tree.heading("findings",text="Hits")
        self.tree.heading("path",    text="Full Path")
        self.tree.column("risk",    width=90, anchor="center")
        self.tree.column("filename",width=170)
        self.tree.column("type",    width=90)
        self.tree.column("size",    width=70, anchor="e")
        self.tree.column("findings",width=40, anchor="center")
        self.tree.column("path",    width=300)

        ts=ttk.Scrollbar(left,command=self.tree.yview)
        self.tree.configure(yscrollcommand=ts.set)
        ts.pack(side="right",fill="y")
        self.tree.pack(fill="both",expand=True,padx=(6,0),pady=(0,6))
        self.tree.bind("<<TreeviewSelect>>",self._on_select)

        # ── Right: detail ─────────────────────────────────────
        right=tk.Frame(pane,bg=PANEL,
                       highlightthickness=1,highlightbackground=BORDER)
        pane.add(right,minsize=460)

        nb=ttk.Notebook(right)
        sty.configure("TNotebook",background=PANEL,borderwidth=0)
        sty.configure("TNotebook.Tab",background=BG,foreground=DIM,
                      padding=[10,4],font=UI)
        sty.map("TNotebook.Tab",
                background=[("selected",PANEL)],
                foreground=[("selected",BLUE)])
        nb.pack(fill="both",expand=True,padx=4,pady=4)

        t1=tk.Frame(nb,bg=PANEL); nb.add(t1,text="  📋 Detail  ")
        self.detail_txt=self._make_text(t1)
        t2=tk.Frame(nb,bg=PANEL); nb.add(t2,text="  📥 Imports  ")
        self.imp_txt=self._make_text(t2)
        t3=tk.Frame(nb,bg=PANEL); nb.add(t3,text="  📦 Sections  ")
        self.sec_txt=self._make_text(t3)
        t4=tk.Frame(nb,bg=PANEL); nb.add(t4,text="  🔤 Strings  ")
        self.str_txt=self._make_text(t4)

    def _make_text(self,parent)->tk.Text:
        f=tk.Frame(parent,bg=PANEL); f.pack(fill="both",expand=True,padx=4,pady=4)
        t=tk.Text(f,bg=BG,fg=FG,font=MONO,relief="flat",
                  wrap="word",state="disabled",cursor="arrow",
                  selectbackground="#264f78")
        sb2=ttk.Scrollbar(f,command=t.yview)
        t.configure(yscrollcommand=sb2.set)
        for r,c in [("CLEAN",GREEN),("LOW",BLUE),("MEDIUM",YELLOW),
                    ("HIGH",ORANGE),("CRITICAL",RED)]:
            t.tag_config(r,foreground=c)
        t.tag_config("HEAD",foreground=BLUE,font=("Consolas",10,"bold"))
        t.tag_config("DIM",foreground=DIM)
        t.tag_config("BOLD",font=MONO_B)
        t.tag_config("GREEN",foreground=GREEN)
        sb2.pack(side="right",fill="y"); t.pack(fill="both",expand=True)
        return t

    def _footer(self):
        f=tk.Frame(self.root,bg=PANEL,height=30,
                   highlightthickness=1,highlightbackground=BORDER)
        f.pack(fill="x",side="bottom"); f.pack_propagate(False)

        # Export buttons
        for label,fmt,color in [("💾 TXT","txt",GREEN),
                                 ("🌐 HTML","html",ORANGE),
                                 ("📋 JSON","json",PURPLE)]:
            tk.Button(f,text=label,font=("Segoe UI",8),
                      bg="#21262d",fg=color,relief="flat",cursor="hand2",padx=8,
                      command=lambda fm=fmt:self._save(fm)
                      ).pack(side="right",padx=3,pady=4)
        tk.Label(f,text="Export:",font=UI,bg=PANEL,fg=DIM).pack(side="right",padx=4)

        self.status=tk.Label(f,text="Enter a folder path and press START SCAN.",
                             font=UI,bg=PANEL,fg=DIM,anchor="w")
        self.status.pack(side="left",padx=10)
        self.prog=ttk.Progressbar(f,length=180,mode="determinate")

    # ── ACTIONS ───────────────────────────────────────────────
    def _browse_folder(self):
        d=filedialog.askdirectory(title="Select folder to scan")
        if d: self.path_var.set(d)

    def _set_path(self,p:str): self.path_var.set(p)

    def _start_scan(self):
        if self._running: return
        path=self.path_var.get().strip()
        if not os.path.isdir(path):
            messagebox.showerror("Error",f"Not a valid folder:\n{path}")
            return

        # Clear previous
        self._results.clear()
        for item in self.tree.get_children(): self.tree.delete(item)
        for t in [self.detail_txt,self.imp_txt,self.sec_txt,self.str_txt]:
            self._wipe(t)

        self._running=True
        self._start_t=time.time()
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status.config(text=f"Collecting files in {path}…")

        def worker():
            files=collect_files(path)
            self._total=len(files)
            self._done=0
            if self._total==0:
                self._scan_q.put(("done",None))
                return

            self.root.after(0,lambda:self.prog.configure(maximum=self._total))
            self.root.after(0,self.prog.pack,{"side":"right","padx":6,"pady":5})

            # Skip files > 50MB to prevent hang
            files = [f for f in files if os.path.getsize(f) < 50*1024*1024]
            self._total = len(files)

            with ThreadPoolExecutor(max_workers=4) as ex:
                self._executor=ex
                futs={ex.submit(analyze_file,fp):fp for fp in files}
                for fut in as_completed(futs):
                    if not self._running: break
                    try:
                        result=fut.result()
                        self._scan_q.put(("result",result))
                    except Exception as e:
                        pass
            self._scan_q.put(("done",None))

        threading.Thread(target=worker,daemon=True).start()

    def _stop_scan(self):
        self._running=False
        self.status.config(text="Stopping…")

    def _poll(self):
        # Batch: max 25 items per cycle — prevents GUI freeze
        processed = 0
        scan_done = False
        while processed < 25:
            try:
                msg, data = self._scan_q.get_nowait()
            except queue.Empty:
                break
            if msg == "result":
                self._done += 1
                self._results.append(data)
                processed += 1
            elif msg == "done":
                scan_done = True
                break

        # Update UI once per cycle (not per file)
        if processed > 0:
            elapsed = time.time() - self._start_t
            rate    = self._done / elapsed if elapsed > 0 else 0
            eta     = (self._total - self._done) / rate if rate > 0 else 0
            by = {r.label: 0 for r in Risk}
            for res in self._results:
                by[res.overall_risk.label] += 1
            sus = sum(by[l] for l in ["CRITICAL","HIGH","MEDIUM"])
            self.s_scanned.config(text=str(len(self._results)))
            self.s_sus.config(text=str(sus))
            self.s_crit.config(text=str(by["CRITICAL"]))
            self.s_high.config(text=str(by["HIGH"]))
            self.s_med.config( text=str(by["MEDIUM"]))
            self.s_low.config( text=str(by["LOW"]))
            self.s_clean.config(text=str(by["CLEAN"]))
            self.s_speed.config(text=f"{rate:.0f}/s")
            self.s_eta.config(text=f"{int(eta)}s" if 0 < eta < 3600 else "...")
            if self._total > 0:
                self.prog["value"] = self._done
            self.status.config(
                text=f"Scanning {self._done}/{self._total}  "
                     f"| CRITICAL:{by['CRITICAL']}  HIGH:{by['HIGH']}  MED:{by['MEDIUM']}")
            # Add new suspicious rows to tree
            for res in self._results[-processed:]:
                if res.overall_risk.score >= 1:
                    self._add_row(res)
            # Cap tree at 1500 rows to keep GUI fast
            ch = self.tree.get_children()
            if len(ch) > 1500:
                for old_item in ch[:len(ch)-1500]:
                    self.tree.delete(old_item)
            self.count_lbl.config(text=f"Showing {len(self.tree.get_children())} rows")

        if scan_done:
            self._scan_done()
        else:
            interval = 60 if processed >= 20 else 200
            self.root.after(interval, self._poll)

    def _scan_done(self):
        self._running=False
        elapsed=time.time()-self._start_t
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.prog.pack_forget()
        sus=sum(1 for r in self._results if r.overall_risk.score>=2)
        self.status.config(
            text=f"✅ Done — {self._done} files in {elapsed:.1f}s  |  "
                 f"🚨 {sus} suspicious")
        self._update_stats()
        self._apply_filter()

    def _update_stats(self):
        by={r.label:0 for r in Risk}
        for res in self._results: by[res.overall_risk.label]+=1
        self.s_scanned.config(text=str(len(self._results)))
        sus=sum(by[l] for l in ["CRITICAL","HIGH","MEDIUM"])
        self.s_sus.config(text=str(sus))
        self.s_crit.config(text=str(by["CRITICAL"]))
        self.s_high.config(text=str(by["HIGH"]))
        self.s_med.config( text=str(by["MEDIUM"]))
        self.s_low.config( text=str(by["LOW"]))
        self.s_clean.config(text=str(by["CLEAN"]))
        self.count_lbl.config(
            text=f"Showing {len(self.tree.get_children())} rows")

    def _add_row(self,res:FileResult):
        rl=res.overall_risk.label
        filt=self.filter_var.get()
        if filt!="ALL" and filt!=rl: return
        icon=res.overall_risk.icon
        fname=os.path.basename(res.path)
        size=f"{res.size/1024:.1f}KB"
        self.tree.insert("","end",
            values=(f"{icon} {rl}",fname,res.file_type,
                    size,len(res.findings),res.path),
            tags=(rl,))
        self.tree.tag_configure(rl,foreground=res.overall_risk.color)
        self.tree.see(self.tree.get_children()[-1])

    def _apply_filter(self):
        for item in self.tree.get_children(): self.tree.delete(item)
        filt=self.filter_var.get()
        for res in sorted(self._results,key=lambda r:-r.overall_risk.score):
            if res.overall_risk==Risk.CLEAN and filt=="ALL": continue
            if filt!="ALL" and res.overall_risk.label!=filt: continue
            self._add_row(res)
        self.count_lbl.config(
            text=f"Showing {len(self.tree.get_children())} rows")

    def _on_select(self,_=None):
        sel=self.tree.selection()
        if not sel: return
        vals=self.tree.item(sel[0],"values")
        path=vals[5] if len(vals)>5 else ""
        res=next((r for r in self._results if r.path==path),None)
        if res: self._show_detail(res)

    def _show_detail(self,res:FileResult):
        self._fill_detail(res)
        self._fill_imports(res)
        self._fill_sections(res)
        self._fill_strings(res)

    def _fill_detail(self,res:FileResult):
        t=self.detail_txt; self._wipe(t); t.config(state="normal")
        def w(tx,tag=""): t.insert("end",tx,tag)
        rl=res.overall_risk.label
        w(f"{res.overall_risk.icon} {rl} — {os.path.basename(res.path)}\n","HEAD")
        w("─"*60+"\n","DIM")
        for k,v in [("Path",res.path),("Size",f"{res.size:,} bytes ({res.size/1024:.2f} KB)"),
                    ("Type",res.file_type),("Arch",res.arch),
                    ("Compiled",res.compile_time),
                    ("Packed","YES ⚠" if res.is_packed else "No"),
                    ("Scan time",f"{res.scan_time_ms:.1f} ms")]:
            w(f"  {k:<12}: ","DIM"); w(v+"\n","")
        w("\n  SHA-256 : ","DIM"); w(res.sha256+"\n","GREEN")
        w("  MD5     : ","DIM");   w(res.md5+"\n","GREEN")
        w(f"\n  Findings: {len(res.findings)}\n\n","DIM")
        if not res.findings:
            w("  ✅ No suspicious findings.\n","CLEAN")
        else:
            for i,f in enumerate(res.findings,1):
                w(f"\n  [{i:02}] {f.risk.icon} ","DIM")
                w(f"[{f.risk.label}]",f.risk.label)
                w(f" [{f.category}] ","DIM"); w(f.title+"\n","BOLD")
                w(f"       {f.detail}\n","DIM")
                for ev in f.evidence:
                    w(f"       • {ev}\n",f.risk.label)
        t.config(state="disabled")

    def _fill_imports(self,res:FileResult):
        t=self.imp_txt; self._wipe(t); t.config(state="normal")
        def w(tx,tag=""): t.insert("end",tx,tag)
        if not res.imports:
            w("  No imports found.\n","DIM"); t.config(state="disabled"); return
        sus=[i for i in res.imports if i in SUSPICIOUS_IMPORTS]
        norm=[i for i in res.imports if i not in SUSPICIOUS_IMPORTS]
        w(f"  Total: {len(res.imports)}  |  Suspicious: {len(sus)}\n\n","HEAD")
        if sus:
            w(f"  ⚠ SUSPICIOUS ({len(sus)})\n","HEAD"); w("─"*58+"\n","DIM")
            for api in sus:
                risk,desc=SUSPICIOUS_IMPORTS[api]
                w(f"  {risk.icon} ",""); w(f"{api:<40}",risk.label)
                w(f"  {desc}\n","DIM")
            w("\n","")
        if norm:
            w(f"  NORMAL ({len(norm)})\n","HEAD"); w("─"*58+"\n","DIM")
            for i,api in enumerate(sorted(norm)):
                w(f"  {api:<36}","DIM")
                if i%2==1: w("\n","")
        t.config(state="disabled")

    def _fill_sections(self,res:FileResult):
        t=self.sec_txt; self._wipe(t); t.config(state="normal")
        def w(tx,tag=""): t.insert("end",tx,tag)
        if not res.sections:
            w("  No sections.\n","DIM"); t.config(state="disabled"); return
        w(f"  {'Name':<12}{'VAddr':>10}{'Size':>12}{'Entropy':>10}  Flags\n","HEAD")
        w("─"*62+"\n","DIM")
        for s in res.sections:
            e=s.get("entropy",0)
            et="CRITICAL" if e>7.2 else "HIGH" if e>6.8 else "DIM"
            fl=[]
            c=s.get("chars",0)
            if c&0x20000000:fl.append("EXEC")
            if c&0x40000000:fl.append("READ")
            if c&0x80000000:fl.append("WRITE")
            w(f"  {s['name']:<12}{s['vaddr']:>10x}{s['rawsize']:>12,}","DIM")
            w(f"{e:>10.4f}","BOLD")
            w(f"  {' | '.join(fl)}","DIM")
            if e>7.2: w("  ← PACKED","CRITICAL")
            elif e>6.8: w("  ← elevated","HIGH")
            w("\n","")
        t.config(state="disabled")

    def _fill_strings(self,res:FileResult):
        t=self.str_txt; self._wipe(t); t.config(state="normal")
        def w(tx,tag=""): t.insert("end",tx,tag)
        if not res.strings_found:
            w("  ✅ No cheat strings found.\n","GREEN")
        else:
            w(f"  {len(res.strings_found)} suspicious string(s)\n\n","HEAD")
            for kw in sorted(res.strings_found):
                risk=CHEAT_STRINGS.get(kw,Risk.LOW)
                w(f"  {risk.icon} ",""); w(f"{kw}\n",risk.label)
        t.config(state="disabled")

    def _wipe(self,t:tk.Text):
        t.config(state="normal"); t.delete("1.0","end")
        t.config(state="disabled")

    # ── SAVE ──────────────────────────────────────────────────
    def _save(self,fmt:str):
        if not self._results:
            messagebox.showinfo("Save","No results yet."); return
        ts=datetime.now().strftime("%Y%m%d_%H%M%S")
        path=filedialog.asksaveasfilename(
            initialfile=f"scan_report_{ts}",
            defaultextension=f".{fmt}",
            filetypes=[(fmt.upper(),f"*.{fmt}"),("All","*.*")])
        if not path: return
        elapsed=time.time()-self._start_t
        try:
            if   fmt=="txt":  content=gen_txt(self._results,self.path_var.get(),elapsed)
            elif fmt=="html": content=gen_html(self._results,self.path_var.get(),elapsed)
            elif fmt=="json": content=gen_json(self._results,self.path_var.get(),elapsed)
            with open(path,"w",encoding="utf-8") as f: f.write(content)
            self.status.config(text=f"Saved → {path}")
            messagebox.showinfo("Saved",f"Report:\n{path}")
        except Exception as e:
            messagebox.showerror("Error",str(e))

# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════
def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()!=0
    except: return False

def main():
    if not is_admin():
        try:
            import subprocess
            subprocess.run(["powershell","Start-Process",sys.executable,
                f'"{os.path.abspath(__file__)}"',"-Verb","RunAs"],check=False)
        except: pass
        sys.exit(0)

    root=tk.Tk()
    ScannerGUI(root)
    root.mainloop()

if __name__=="__main__":
    main()





exe converter bat : 


@echo off
title Folder Scanner Builder
color 0A
echo.
echo  ╔═══════════════════════════════════════════╗
echo  ║  Anti-Cheat Folder Scanner — Builder     ║
echo  ╚═══════════════════════════════════════════╝
echo.

cd /d "%~dp0"
echo [INFO] Directory: %CD%
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found!
    pause & exit /b 1
)

echo [1/3] Installing PyInstaller...
python -m pip install pyinstaller --quiet
echo        Done.

echo [2/3] Building FolderScanner.exe...
python -m PyInstaller ^
  --onefile ^
  --noconsole ^
  --name "FolderScanner" ^
  --hidden-import tkinter ^
  --hidden-import tkinter.ttk ^
  --hidden-import tkinter.filedialog ^
  --hidden-import tkinter.messagebox ^
  --hidden-import concurrent.futures ^
  --hidden-import queue ^
  --hidden-import threading ^
  --hidden-import json ^
  --hidden-import hashlib ^
  folder_scanner.py

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed!
    pause & exit /b 1
)

echo.
echo  ╔═══════════════════════════════════════════╗
echo  ║  ✅  dist\FolderScanner.exe ready!        ║
echo  ╚═══════════════════════════════════════════╝
echo.
explorer "%~dp0dist"
pause



