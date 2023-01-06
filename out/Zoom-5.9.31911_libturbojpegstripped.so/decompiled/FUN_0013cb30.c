1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: long FUN_0013cb30(code **param_1,ulong param_2,uint param_3,uint param_4)
5: 
6: {
7: code *pcVar1;
8: code *pcVar2;
9: undefined8 uVar3;
10: code **ppcVar4;
11: ulong uVar5;
12: long lVar6;
13: ulong uVar7;
14: undefined8 *puVar8;
15: uint uVar9;
16: undefined8 *puVar10;
17: ulong uVar11;
18: uint uVar12;
19: uint uVar13;
20: 
21: uVar5 = SUB168((ZEXT416(0) << 0x40 | ZEXT816(0x3b9ac9e8)) / (ZEXT416(param_3) << 7),0);
22: pcVar1 = param_1[1];
23: uVar12 = (uint)param_2;
24: if (uVar5 == 0) {
25: ppcVar4 = (code **)*param_1;
26: *(undefined4 *)(ppcVar4 + 5) = 0x46;
27: (**ppcVar4)();
28: param_2 = param_2 & 0xffffffff;
29: }
30: if (param_4 <= uVar5) {
31: uVar5 = (ulong)param_4;
32: }
33: *(int *)(pcVar1 + 0xa0) = (int)uVar5;
34: uVar11 = 0;
35: lVar6 = FUN_0013bee0(param_1,param_2,(ulong)param_4 << 3);
36: if (param_4 == 0) {
37: return lVar6;
38: }
39: do {
40: pcVar1 = param_1[1];
41: uVar9 = (uint)uVar11;
42: if (param_4 - uVar9 < (uint)uVar5) {
43: uVar5 = (ulong)(param_4 - uVar9);
44: }
45: uVar7 = uVar5 * (ulong)param_3 * 0x80;
46: if (1000000000 < uVar7) {
47: pcVar2 = *param_1;
48: *(undefined4 *)(pcVar2 + 0x28) = 0x36;
49: *(undefined4 *)(pcVar2 + 0x2c) = 8;
50: (**(code **)*param_1)();
51: }
52: if (1000000000 < uVar7 + 0x37) {
53: pcVar2 = *param_1;
54: *(undefined4 *)(pcVar2 + 0x28) = 0x36;
55: *(undefined4 *)(pcVar2 + 0x2c) = 3;
56: (**(code **)*param_1)();
57: }
58: if (1 < uVar12) {
59: pcVar2 = *param_1;
60: *(uint *)(pcVar2 + 0x2c) = uVar12;
61: *(undefined4 *)(pcVar2 + 0x28) = 0xe;
62: (**(code **)*param_1)(param_1);
63: }
64: puVar8 = (undefined8 *)FUN_0013d900(param_1,uVar7 + 0x37);
65: if (puVar8 == (undefined8 *)0x0) {
66: pcVar2 = *param_1;
67: *(undefined4 *)(pcVar2 + 0x28) = 0x36;
68: *(undefined4 *)(pcVar2 + 0x2c) = 4;
69: (**(code **)*param_1)();
70: *(ulong *)(pcVar1 + 0x98) = uVar7 + 0x37 + *(long *)(pcVar1 + 0x98);
71: _TURBOJPEG_1.4 = *(undefined8 *)(pcVar1 + (long)(int)uVar12 * 8 + 0x78);
72: puVar10 = (undefined8 *)0x18;
73: _DAT_00000010 = 0;
74: _DAT_00000008 = uVar7;
75: *(undefined8 *)(pcVar1 + (long)(int)uVar12 * 8 + 0x78) = 0;
76: uVar7 = 0x18;
77: LAB_0013cc69:
78: puVar10 = (undefined8 *)((long)puVar10 + (0x20 - uVar7));
79: }
80: else {
81: *(ulong *)(pcVar1 + 0x98) = uVar7 + 0x37 + *(long *)(pcVar1 + 0x98);
82: uVar3 = *(undefined8 *)(pcVar1 + (long)(int)uVar12 * 8 + 0x78);
83: puVar8[1] = uVar7;
84: puVar10 = puVar8 + 3;
85: puVar8[2] = 0;
86: *puVar8 = uVar3;
87: *(undefined8 **)(pcVar1 + (long)(int)uVar12 * 8 + 0x78) = puVar8;
88: uVar7 = (ulong)((uint)puVar10 & 0x1f);
89: if (((ulong)puVar10 & 0x1f) != 0) goto LAB_0013cc69;
90: }
91: if ((int)uVar5 != 0) {
92: uVar9 = (int)uVar5 + uVar9;
93: do {
94: uVar13 = (int)uVar11 + 1;
95: *(undefined8 **)(lVar6 + uVar11 * 8) = puVar10;
96: puVar10 = puVar10 + (ulong)param_3 * 0x10;
97: uVar11 = (ulong)uVar13;
98: } while (uVar13 != uVar9);
99: }
100: if (param_4 <= uVar9) {
101: return lVar6;
102: }
103: uVar11 = (ulong)uVar9;
104: } while( true );
105: }
106: 
