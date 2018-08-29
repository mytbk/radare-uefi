# Copyright (C)  2018 Iru Cai <mytbk920423@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later

from efiobj import EfiObj, regMap, efiAddrMap
from uefi_tables import rt_svc_name, boot_svc_name
from smmbase import smmbaseobj

def doLocateProtocol(r2):
    if regMap.get("rcx").get("value") is not None and regMap.get("r8").get("value") is not None:
        f = r2.cmdj("fdj {}".format(regMap["rcx"]["value"]))
        if f.get("name") is not None:
            guidname = f["name"]
            staddr = regMap["r8"]["value"]
            if len(guidname) > 16 and guidname[0:4] == "gEfi" and guidname[-12:] == "ProtocolGuid":
                guidname = guidname[4:-12]
                r2.cmd("f {} @ {}".format(guidname, staddr))
                if guidname == "SmmBase":
                    efiAddrMap[staddr] = smmbaseobj

def doInstallProtocolInterface(r2):
    if regMap.get("r9").get("value") is not None:
        r2.cmd("\"CC protocol interface\" @ {}".format(regMap.get("r9")["insn"]["offset"]))

def gBSact(r2, insn):
    fname = boot_svc_name(insn["ptr"])
    if fname is not None:
        r2.cmd("CC \"gBS->{}\" @ {}".format(fname, insn["offset"]))
    if fname == "LocateProtocol":
        doLocateProtocol(r2)
    elif fname == "InstallProtocolInterface":
        doInstallProtocolInterface(r2)
    elif fname == "CreateEvent" or fname == "CreateEventEx":
        if regMap.get("r8").get("value") is not None:
            r2.cmd("af {}".format(regMap["r8"]["value"]))

def gRTact(r2, insn):
    fname = rt_svc_name(insn["ptr"])
    if (fname is not None):
        r2.cmd("CC \"gRT->{}\" @ {}".format(fname, insn["offset"]))

gbsobj = EfiObj(gBSact)
grtobj = EfiObj(gRTact)
