1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: long FUN_00149ac0(code **param_1,uint param_2,uint param_3,uint param_4)
5: 
6: {
7: code *pcVar1;
8: code **ppcVar2;
9: undefined8 uVar3;
10: ulong uVar4;
11: ulong uVar5;
12: long lVar6;
13: undefined8 *puVar7;
14: uint uVar8;
15: uint uVar9;
16: ulong uVar10;
17: 
18: pcVar1 = param_1[1];
19: if (1000000000 < param_3) {
20: ppcVar2 = (code **)*param_1;
21: ppcVar2[5] = (code *)0x900000036;
22: (**ppcVar2)(param_1);
23: }
24: uVar4 = (ulong)(param_3 + 0x3f & 0xffffffc0);
25: uVar5 = SUB168((ZEXT816(0) << 0x40 | ZEXT816(0x3b9ac9e8)) / ZEXT816(uVar4),0);
26: if (uVar5 == 0) {
27: ppcVar2 = (code **)*param_1;
28: *(undefined4 *)(ppcVar2 + 5) = 0x46;
29: (**ppcVar2)(param_1);
30: }
31: if (param_4 <= uVar5) {
32: uVar5 = (ulong)param_4;
33: }
34: *(int *)(pcVar1 + 0xa0) = (int)uVar5;
35: lVar6 = FUN_00148a90(param_1,param_2,(ulong)param_4 << 3);
36: if (param_4 != 0) {
37: uVar8 = 0;
38: do {
39: if (param_4 - uVar8 < (uint)uVar5) {
40: uVar5 = (ulong)(param_4 - uVar8);
41: }
42: pcVar1 = param_1[1];
43: uVar10 = uVar5 * uVar4;
44: if (1000000000 < uVar10) {
45: ppcVar2 = (code **)*param_1;
46: ppcVar2[5] = (code *)0x800000036;
47: (**ppcVar2)();
48: }
49: if (1000000000 < uVar10 + 0x37) {
50: ppcVar2 = (code **)*param_1;
51: ppcVar2[5] = (code *)0x300000036;
52: (**ppcVar2)();
53: }
54: if (1 < param_2) {
55: ppcVar2 = (code **)*param_1;
56: *(uint *)((long)ppcVar2 + 0x2c) = param_2;
57: *(undefined4 *)(ppcVar2 + 5) = 0xe;
58: (**ppcVar2)(param_1);
59: }
60: puVar7 = (undefined8 *)FUN_0014a5c0(param_1,uVar10 + 0x37);
61: if (puVar7 == (undefined8 *)0x0) {
62: ppcVar2 = (code **)*param_1;
63: ppcVar2[5] = (code *)0x400000036;
64: (**ppcVar2)();
65: *(ulong *)(pcVar1 + 0x98) = uVar10 + 0x37 + *(long *)(pcVar1 + 0x98);
66: _TURBOJPEG_1.4 = *(undefined8 *)(pcVar1 + (long)(int)param_2 * 8 + 0x78);
67: _DAT_00000010 = 0;
68: _DAT_00000008 = uVar10;
69: *(undefined8 *)(pcVar1 + (long)(int)param_2 * 8 + 0x78) = 0;
70: uVar10 = 0x18;
71: puVar7 = (undefined8 *)0x18;
72: LAB_00149c6b:
73: puVar7 = (undefined8 *)((long)puVar7 + (0x20 - uVar10));
74: }
75: else {
76: *(ulong *)(pcVar1 + 0x98) = uVar10 + 0x37 + *(long *)(pcVar1 + 0x98);
77: uVar3 = *(undefined8 *)(pcVar1 + (long)(int)param_2 * 8 + 0x78);
78: puVar7[1] = uVar10;
79: puVar7[2] = 0;
80: *puVar7 = uVar3;
81: *(undefined8 **)(pcVar1 + (long)(int)param_2 * 8 + 0x78) = puVar7;
82: puVar7 = puVar7 + 3;
83: uVar10 = (ulong)((uint)puVar7 & 0x1f);
84: if (((ulong)puVar7 & 0x1f) != 0) goto LAB_00149c6b;
85: }
86: if ((int)uVar5 != 0) {
87: uVar9 = (int)uVar5 + uVar8;
88: do {
89: uVar10 = (ulong)uVar8;
90: uVar8 = uVar8 + 1;
91: *(undefined8 **)(lVar6 + uVar10 * 8) = puVar7;
92: puVar7 = (undefined8 *)((long)puVar7 + uVar4);
93: } while (uVar8 != uVar9);
94: }
95: } while (uVar8 < param_4);
96: }
97: return lVar6;
98: }
99: 
