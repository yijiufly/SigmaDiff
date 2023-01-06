1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: long FUN_001498a0(code **param_1,uint param_2,uint param_3,uint param_4)
5: 
6: {
7: code *pcVar1;
8: code **ppcVar2;
9: undefined8 uVar3;
10: ulong uVar4;
11: long lVar5;
12: undefined8 *puVar6;
13: uint uVar7;
14: uint uVar8;
15: ulong uVar9;
16: 
17: uVar4 = SUB168((ZEXT816(0) << 0x40 | ZEXT816(0x3b9ac9e8)) / (ZEXT416(param_3) << 7),0);
18: pcVar1 = param_1[1];
19: if (uVar4 == 0) {
20: ppcVar2 = (code **)*param_1;
21: *(undefined4 *)(ppcVar2 + 5) = 0x46;
22: (**ppcVar2)();
23: }
24: if (param_4 <= uVar4) {
25: uVar4 = (ulong)param_4;
26: }
27: *(int *)(pcVar1 + 0xa0) = (int)uVar4;
28: lVar5 = FUN_00148a90(param_1,param_2,(ulong)param_4 << 3);
29: if (param_4 != 0) {
30: uVar7 = 0;
31: do {
32: if (param_4 - uVar7 < (uint)uVar4) {
33: uVar4 = (ulong)(param_4 - uVar7);
34: }
35: pcVar1 = param_1[1];
36: uVar9 = uVar4 * (ulong)param_3 * 0x80;
37: if (1000000000 < uVar9) {
38: ppcVar2 = (code **)*param_1;
39: ppcVar2[5] = (code *)0x800000036;
40: (**ppcVar2)();
41: }
42: if (1000000000 < uVar9 + 0x37) {
43: ppcVar2 = (code **)*param_1;
44: ppcVar2[5] = (code *)0x300000036;
45: (**ppcVar2)();
46: }
47: if (1 < param_2) {
48: ppcVar2 = (code **)*param_1;
49: *(uint *)((long)ppcVar2 + 0x2c) = param_2;
50: *(undefined4 *)(ppcVar2 + 5) = 0xe;
51: (**ppcVar2)(param_1);
52: }
53: puVar6 = (undefined8 *)FUN_0014a5c0(param_1,uVar9 + 0x37);
54: if (puVar6 == (undefined8 *)0x0) {
55: ppcVar2 = (code **)*param_1;
56: ppcVar2[5] = (code *)0x400000036;
57: (**ppcVar2)();
58: *(ulong *)(pcVar1 + 0x98) = uVar9 + 0x37 + *(long *)(pcVar1 + 0x98);
59: _TURBOJPEG_1.4 = *(undefined8 *)(pcVar1 + (long)(int)param_2 * 8 + 0x78);
60: _DAT_00000010 = 0;
61: _DAT_00000008 = uVar9;
62: *(undefined8 *)(pcVar1 + (long)(int)param_2 * 8 + 0x78) = 0;
63: uVar9 = 0x18;
64: puVar6 = (undefined8 *)0x18;
65: LAB_00149a2b:
66: puVar6 = (undefined8 *)((long)puVar6 + (0x20 - uVar9));
67: }
68: else {
69: *(ulong *)(pcVar1 + 0x98) = uVar9 + 0x37 + *(long *)(pcVar1 + 0x98);
70: uVar3 = *(undefined8 *)(pcVar1 + (long)(int)param_2 * 8 + 0x78);
71: puVar6[1] = uVar9;
72: puVar6[2] = 0;
73: *puVar6 = uVar3;
74: *(undefined8 **)(pcVar1 + (long)(int)param_2 * 8 + 0x78) = puVar6;
75: puVar6 = puVar6 + 3;
76: uVar9 = (ulong)((uint)puVar6 & 0x1f);
77: if (((ulong)puVar6 & 0x1f) != 0) goto LAB_00149a2b;
78: }
79: if ((int)uVar4 != 0) {
80: uVar8 = (int)uVar4 + uVar7;
81: do {
82: uVar9 = (ulong)uVar7;
83: uVar7 = uVar7 + 1;
84: *(undefined8 **)(lVar5 + uVar9 * 8) = puVar6;
85: puVar6 = puVar6 + (ulong)param_3 * 0x10;
86: } while (uVar7 != uVar8);
87: }
88: } while (uVar7 < param_4);
89: }
90: return lVar5;
91: }
92: 
