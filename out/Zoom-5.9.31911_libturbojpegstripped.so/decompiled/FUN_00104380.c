1: 
2: void FUN_00104380(long param_1,int param_2)
3: 
4: {
5: code **ppcVar1;
6: int iVar2;
7: int iVar3;
8: undefined4 uVar4;
9: undefined4 uVar5;
10: code **ppcVar6;
11: code *pcVar7;
12: long lVar8;
13: uint uVar9;
14: long lVar10;
15: int iVar11;
16: 
17: ppcVar6 = (code **)(***(code ***)(param_1 + 8))(param_1,1,0xc0);
18: *(code ***)(param_1 + 0x1c8) = ppcVar6;
19: *ppcVar6 = FUN_00104290;
20: if (param_2 == 0) {
21: pcVar7 = (code *)(**(code **)(*(long *)(param_1 + 8) + 8))(param_1,1,0x500);
22: lVar8 = (long)ppcVar6 << 0x3c;
23: if (-1 < lVar8) {
24: iVar11 = 10;
25: }
26: else {
27: ppcVar6[4] = pcVar7;
28: iVar11 = 9;
29: }
30: uVar9 = (uint)(-1 >= lVar8);
31: ppcVar1 = ppcVar6 + (4 - (lVar8 >> 0x3f));
32: ppcVar1[2] = pcVar7 + (ulong)(uVar9 + 2) * 0x80;
33: ppcVar1[3] = pcVar7 + (ulong)(uVar9 + 3) * 0x80;
34: ppcVar1[4] = pcVar7 + (ulong)(uVar9 + 4) * 0x80;
35: ppcVar1[5] = pcVar7 + (ulong)(uVar9 + 5) * 0x80;
36: *ppcVar1 = pcVar7 + (ulong)uVar9 * 0x80;
37: ppcVar1[1] = pcVar7 + (ulong)(uVar9 + 1) * 0x80;
38: ppcVar1[6] = pcVar7 + (ulong)(uVar9 + 6) * 0x80;
39: ppcVar1[7] = pcVar7 + (ulong)(uVar9 + 7) * 0x80;
40: ppcVar6[(long)(int)(uVar9 + 8) + 4] = pcVar7 + (long)(int)(uVar9 + 8) * 0x80;
41: if (iVar11 != 9) {
42: ppcVar6[(long)(int)(uVar9 + 9) + 4] = pcVar7 + (long)(int)(uVar9 + 9) * 0x80;
43: }
44: ppcVar6[0xe] = (code *)0x0;
45: return;
46: }
47: iVar11 = 0;
48: lVar8 = *(long *)(param_1 + 0x58);
49: if (0 < *(int *)(param_1 + 0x4c)) {
50: do {
51: iVar2 = *(int *)(lVar8 + 0xc);
52: pcVar7 = *(code **)(*(long *)(param_1 + 8) + 0x28);
53: uVar4 = FUN_0013be30(*(undefined4 *)(lVar8 + 0x20),(long)iVar2);
54: uVar5 = FUN_0013be30(*(undefined4 *)(lVar8 + 0x1c),(long)*(int *)(lVar8 + 8));
55: pcVar7 = (code *)(*pcVar7)(param_1,1,0,uVar5,uVar4,iVar2);
56: lVar10 = (long)iVar11;
57: iVar11 = iVar11 + 1;
58: iVar2 = *(int *)(param_1 + 0x4c);
59: iVar3 = *(int *)(param_1 + 0x4c);
60: ppcVar6[lVar10 + 0xe] = pcVar7;
61: lVar8 = lVar8 + 0x60;
62: } while (iVar3 != iVar11 && iVar11 <= iVar2);
63: }
64: return;
65: }
66: 
