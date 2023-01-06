1: 
2: void FUN_0012bb00(long param_1)
3: 
4: {
5: code **ppcVar1;
6: ulong uVar2;
7: undefined8 *puVar3;
8: undefined8 *puVar4;
9: int iVar5;
10: uint uVar6;
11: bool bVar8;
12: byte bVar9;
13: ulong uVar7;
14: 
15: bVar9 = 0;
16: ppcVar1 = (code **)(***(code ***)(param_1 + 8))(param_1,0,0x108);
17: *(code ***)(param_1 + 0x248) = ppcVar1;
18: puVar3 = (undefined8 *)((long)ppcVar1 + 0xb4);
19: *(undefined4 *)(ppcVar1 + 0x16) = 0;
20: uVar7 = 0x40;
21: iVar5 = 0x40;
22: *ppcVar1 = FUN_00129c70;
23: bVar8 = ((ulong)puVar3 & 1) != 0;
24: ppcVar1[1] = FUN_0012a1d0;
25: ppcVar1[2] = FUN_0012b6a0;
26: ppcVar1[5] = FUN_00129a10;
27: ppcVar1[6] = FUN_00129a10;
28: ppcVar1[7] = FUN_00129a10;
29: ppcVar1[8] = FUN_00129a10;
30: ppcVar1[9] = FUN_00129a10;
31: ppcVar1[10] = FUN_00129a10;
32: ppcVar1[0xb] = FUN_00129a10;
33: ppcVar1[0xc] = FUN_00129a10;
34: ppcVar1[0xd] = FUN_00129a10;
35: ppcVar1[0xe] = FUN_00129a10;
36: ppcVar1[0xf] = FUN_00129a10;
37: ppcVar1[0x10] = FUN_00129a10;
38: ppcVar1[0x11] = FUN_00129a10;
39: ppcVar1[0x12] = FUN_00129a10;
40: ppcVar1[0x13] = FUN_00129a10;
41: ppcVar1[0x14] = FUN_00129a10;
42: ppcVar1[0x15] = FUN_00129a10;
43: if (bVar8) {
44: puVar3 = (undefined8 *)((long)ppcVar1 + 0xb5);
45: *(undefined *)((long)ppcVar1 + 0xb4) = 0;
46: uVar7 = 0x3f;
47: iVar5 = 0x3f;
48: }
49: if (((ulong)puVar3 & 2) == 0) {
50: uVar6 = (uint)uVar7;
51: }
52: else {
53: uVar6 = iVar5 - 2;
54: uVar7 = (ulong)uVar6;
55: *(undefined2 *)puVar3 = 0;
56: puVar3 = (undefined8 *)((long)puVar3 + 2);
57: }
58: if (((ulong)puVar3 & 4) != 0) {
59: *(undefined4 *)puVar3 = 0;
60: uVar7 = (ulong)(uVar6 - 4);
61: puVar3 = (undefined8 *)((long)puVar3 + 4);
62: }
63: uVar2 = uVar7 >> 3;
64: while (uVar2 != 0) {
65: uVar2 = uVar2 - 1;
66: *puVar3 = 0;
67: puVar3 = puVar3 + (ulong)bVar9 * -2 + 1;
68: }
69: if ((uVar7 & 4) != 0) {
70: *(undefined4 *)puVar3 = 0;
71: puVar3 = (undefined8 *)((long)puVar3 + 4);
72: }
73: puVar4 = puVar3;
74: if ((uVar7 & 2) != 0) {
75: puVar4 = (undefined8 *)((long)puVar3 + 2);
76: *(undefined2 *)puVar3 = 0;
77: }
78: if (bVar8) {
79: *(undefined *)puVar4 = 0;
80: }
81: ppcVar1[6] = FUN_0012b740;
82: ppcVar1[0x14] = FUN_0012b740;
83: *(undefined8 *)(param_1 + 0x130) = 0;
84: *(undefined4 *)(param_1 + 0xac) = 0;
85: *(undefined4 *)(param_1 + 0x21c) = 0;
86: *(undefined4 *)(ppcVar1 + 3) = 0;
87: *(undefined4 *)((long)ppcVar1 + 0x1c) = 0;
88: *(undefined4 *)((long)ppcVar1 + 0x24) = 0;
89: ppcVar1[0x1f] = (code *)0x0;
90: return;
91: }
92: 
