# Copyright (C)  2018 Iru Cai <mytbk920423@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later

from efiobj import EfiObj, regMap, efiAddrMap
from uefi_tables import rt_svc_name, boot_svc_name
from smmbase import smmbaseobj

def doLocateProtocol(r2):
    if regMap.get("rcx") is not None and regMap.get("r8") is not None:
        f = r2.cmdj("fdj {}".format(regMap["rcx"]))
        if f.get("name") is not None:
            guidname = f["name"]
            staddr = regMap["r8"]
            if len(guidname) > 16 and guidname[0:4] == "gEfi" and guidname[-12:] == "ProtocolGuid":
                guidname = guidname[4:-12]
                r2.cmd("f {} @ {}".format(guidname, staddr))
                if guidname == "SmmBase":
                    efiAddrMap[staddr] = smmbaseobj


def gBSact(r2, insn):
    fname = boot_svc_name(insn["ptr"])
    if fname is not None:
        r2.cmd("CC \"gBS->{}\" @ {}".format(fname, insn["offset"]))
    if fname == "LocateProtocol":
        doLocateProtocol(r2)

def gRTact(r2, insn):
    fname = rt_svc_name(insn["ptr"])
    if (fname is not None):
        r2.cmd("CC \"gRT->{}\" @ {}".format(fname, insn["offset"]))

gbsobj = EfiObj(gBSact)
grtobj = EfiObj(gRTact)
