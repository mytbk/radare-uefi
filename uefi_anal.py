#!/usr/bin/env python
# 
# find_tables.py: find where gST, gBS, gRT are stored in the program
# Copyright (C) 2018  Iru Cai <mytbk920423@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import r2pipe
from uefi_tables import rt_svc_name, boot_svc_name
from flag_guids import flagAllGuids

r2 = r2pipe.open()

def find_tables(addr):
    res = {}
    rBS = "x"
    rRT = "x"
    cmdline = "pdj @ {}".format(addr)
    ops = r2.cmdj(cmdline)
    for insn in ops:
        if (res.get("gST") is None and insn["type"] == "call"):
            return find_tables(insn["jump"])

        if (insn["type"] == "mov"):
            es = insn["esil"].split(',')
            if (es[0] == "rdx" and es[-1] == "=[8]"):
                res["gST"] = insn["ptr"]

            if ('qword [rdx + 0x60]' in insn['disasm']):
                rBS = es[4]

            if ('qword [rdx + 0x58]' in insn['disasm']):
                rRT = es[4]

            if (res.get("gBS") is None and es[0] == rBS and es[-1] == "=[8]"):
                res["gBS"] = insn["ptr"]

            if (res.get("gRT") is None and es[0] == rRT and es[-1] == "=[8]"):
                res["gRT"] = insn["ptr"]

    return res

def find_functions(g, ops):
    gBS = g["gBS"]
    gRT = g["gRT"]
    regRT = ""
    regBS = ""
    for insn in ops:
        if insn["type"] == "invalid": # there may be error
            return
        es = insn["esil"].split(',')
        if (insn["type"] == "mov"):
            if (es[-1] == "=" and es[-3] == "[8]"):
                if (insn["ptr"] == gBS):
                    regBS = es[-2]
                if (insn["ptr"] == gRT):
                    regRT = es[-2]
        if (insn["type"] == "ucall"):
            if (es[1] == regBS):
                fname = boot_svc_name(insn["ptr"])
                if (fname is not None):
                    r2.cmd("CC \"gBS->{}\" @ {}".format(fname, insn["offset"]))
            if (es[1] == regRT):
                fname = rt_svc_name(insn["ptr"])
                if (fname is not None):
                    r2.cmd("CC \"gRT->{}\" @ {}".format(fname, insn["offset"]))
#        if (insn["type"] == "call"):
#            subf_ops = r2.cmdj("pdfj @ {}".format(insn["jump"]))["ops"]
#            find_functions(g, subf_ops, depth+1)


g = find_tables("$$")
print(g)
for s in ["gST", "gBS", "gRT"]:
    if (g.get(s) is not None):
        r2.cmd("f {}@{}".format(s, g[s]))

r2.cmd("aa")
ops = r2.cmdj("pdfj")["ops"]
find_functions(g, ops)
analyzed = [ ops[0]["offset"] ]
all_fcns = list(filter(lambda x: "fcn." in x["name"], r2.cmdj("fj")))
for f in all_fcns:
    ops = r2.cmdj("pdfj @ {}".format(f["offset"]))["ops"]
    find_functions(g, ops)

flagAllGuids(r2)
r2.cmd("f-hit*")
