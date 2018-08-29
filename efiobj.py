# Copyright (C)  2018 Iru Cai <mytbk920423@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later

# register and address mappings
# regMap: reg->{value, defined insn}
regMap = {}
# efiAddrMap: addr->efiobj
efiAddrMap = {}

class EfiObj:
    def __init__(self, cb):
        self.action = cb

