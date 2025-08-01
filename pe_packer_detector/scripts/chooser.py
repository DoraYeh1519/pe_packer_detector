# chooser.py
import idaapi
import ida_kernwin
import idc

class JmpChooser(ida_kernwin.Choose):
    def __init__(self, jmps, dist_threshold):
        cols = [
            ["Address",     12 | ida_kernwin.CHCOL_EA],
            ["Target Addr", 12 | ida_kernwin.CHCOL_EA],
            ["Distance",    12 | ida_kernwin.CHCOL_EA],
            ["Disassembly", 36 | ida_kernwin.CHCOL_PLAIN],
        ]
        super(JmpChooser, self).__init__(
            "JMP Instruction List",
            cols,
            flags=ida_kernwin.CH_ATTRS    # 支持 OnGetLineAttr
        )
        self.threshold = dist_threshold
        # 距离从大到小
        self.items = sorted(
            jmps,
            key=lambda jt: abs(jt[1] - jt[0]) if jt[1] else 0,
            reverse=True
        )

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, idx):
        ea, target = self.items[idx]
        disasm = idaapi.generate_disasm_line(ea, 0)
        dist = abs(target - ea) if target else 0
        dist_str = f"0x{dist:X}" if target else ""
        return [f"0x{ea:X}", f"0x{target:X}" if target else "", dist_str, disasm]

    def OnGetLineAttr(self, idx):
        ea, target = self.items[idx]
        if not target:
            return None
        dist = abs(target - ea)
        seg_ea = idaapi.getseg(ea)
        seg_t  = idaapi.getseg(target)
        # 跨段：蓝色
        if seg_ea and seg_t and seg_ea.start_ea != seg_t.start_ea:
            return [0xCCCCFF, 0]
        mid = self.threshold // 2
        # 远/中/近 三色
        if dist > self.threshold:
            return [0xFFCCCC, 0]
        elif dist > mid:
            return [0xFFFFCC, 0]
        else:
            return [0xCCFFCC, 0]

    def OnSelectLine(self, idx):
        ea, target = self.items[idx]
        idaapi.jumpto(target or ea)
        return False
