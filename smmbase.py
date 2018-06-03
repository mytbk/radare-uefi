# Copyright (C)  2018 Iru Cai <mytbk920423@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later

from efiobj import EfiObj

smmbase = [ "Register", "UnRegister", "Communicate", "RegisterCallback",
        "InSmm", "SmmAllocatePool", "SmmFreePool", "GetSmstLocation" ]

def smm_method(addr):
    if (addr >= len(smmbase)*8):
        return None
    return smmbase[addr//8]

def smmbase_act(r2, insn):
    fname = smm_method(insn["ptr"])
    if fname is not None:
        r2.cmd("CC \"SmmBase->{}\" @ {}".format(fname, insn["offset"]))

smmbaseobj = EfiObj(smmbase_act)
