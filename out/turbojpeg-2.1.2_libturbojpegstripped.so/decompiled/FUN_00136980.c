1: 
2: void FUN_00136980(long param_1)
3: 
4: {
5: code **ppcVar1;
6: undefined (*pauVar2) [16];
7: ulong uVar3;
8: code **ppcVar4;
9: uint uVar5;
10: int iVar6;
11: uint uVar7;
12: int iVar8;
13: bool bVar9;
14: 
15: ppcVar4 = (code **)(***(code ***)(param_1 + 8))(param_1,0,0x108);
16: *(code ***)(param_1 + 0x248) = ppcVar4;
17: *(undefined4 *)(ppcVar4 + 0x16) = 0;
18: ppcVar4[1] = FUN_001352b0;
19: *ppcVar4 = FUN_00134ba0;
20: uVar3 = ((ulong)ppcVar4 & 0xffffffff) >> 3;
21: uVar5 = (uint)uVar3 & 1;
22: bVar9 = (uVar3 & 1) == 0;
23: ppcVar4[2] = FUN_00136470;
24: ppcVar4[5] = FUN_00134990;
25: if (bVar9) {
26: iVar8 = 0x10;
27: }
28: else {
29: ppcVar4[6] = FUN_00134990;
30: *(undefined4 *)((long)ppcVar4 + 0xb4) = 0;
31: iVar8 = 0xf;
32: }
33: uVar7 = 0x10 - uVar5;
34: ppcVar1 = ppcVar4 + (ulong)uVar5 + 6;
35: pauVar2 = (undefined (*) [16])((long)ppcVar4 + ((ulong)uVar5 + 0x2d) * 4);
36: *ppcVar1 = FUN_00134990;
37: ppcVar1[1] = FUN_00134990;
38: ppcVar1[2] = FUN_00134990;
39: ppcVar1[3] = FUN_00134990;
40: *pauVar2 = (undefined  [16])0x0;
41: ppcVar1[4] = FUN_00134990;
42: ppcVar1[5] = FUN_00134990;
43: ppcVar1[6] = FUN_00134990;
44: ppcVar1[7] = FUN_00134990;
45: pauVar2[1] = (undefined  [16])0x0;
46: ppcVar1[8] = FUN_00134990;
47: ppcVar1[9] = FUN_00134990;
48: ppcVar1[10] = FUN_00134990;
49: ppcVar1[0xb] = FUN_00134990;
50: pauVar2[2] = (undefined  [16])0x0;
51: if (uVar7 >> 2 == 4) {
52: ppcVar1[0xc] = FUN_00134990;
53: ppcVar1[0xd] = FUN_00134990;
54: ppcVar1[0xe] = FUN_00134990;
55: ppcVar1[0xf] = FUN_00134990;
56: pauVar2[3] = (undefined  [16])0x0;
57: }
58: uVar5 = uVar7 & 0xfffffffc;
59: iVar6 = !bVar9 + uVar5;
60: if (uVar7 != uVar5) {
61: ppcVar4[(long)iVar6 + 6] = FUN_00134990;
62: *(undefined4 *)((long)ppcVar4 + (long)iVar6 * 4 + 0xb4) = 0;
63: if (iVar8 - uVar5 != 1) {
64: ppcVar4[(long)(iVar6 + 1) + 6] = FUN_00134990;
65: *(undefined4 *)((long)ppcVar4 + (long)(iVar6 + 1) * 4 + 0xb4) = 0;
66: if (iVar8 - uVar5 != 2) {
67: ppcVar4[(long)(iVar6 + 2) + 6] = FUN_00134990;
68: *(undefined4 *)((long)ppcVar4 + (long)(iVar6 + 2) * 4 + 0xb4) = 0;
69: }
70: }
71: }
72: ppcVar4[6] = FUN_00136200;
73: ppcVar4[0x14] = FUN_00136200;
74: *(undefined8 *)(param_1 + 0x130) = 0;
75: *(undefined4 *)(param_1 + 0xac) = 0;
76: *(undefined4 *)(param_1 + 0x21c) = 0;
77: ppcVar4[3] = (code *)0x0;
78: *(undefined4 *)((long)ppcVar4 + 0x24) = 0;
79: ppcVar4[0x1f] = (code *)0x0;
80: return;
81: }
82: 
