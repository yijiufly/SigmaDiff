1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: long FUN_0013cdb0(code **param_1,uint param_2,uint param_3,uint param_4)
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
19: ulong uVar13;
20: 
21: pcVar1 = param_1[1];
22: if (1000000000 < param_3) {
23: pcVar2 = *param_1;
24: *(undefined4 *)(pcVar2 + 0x28) = 0x36;
25: *(undefined4 *)(pcVar2 + 0x2c) = 9;
26: (**(code **)*param_1)();
27: }
28: uVar13 = (ulong)(param_3 + 0x3f & 0xffffffc0);
29: uVar5 = SUB168((ZEXT816(0) << 0x40 | ZEXT816(0x3b9ac9e8)) / ZEXT816(uVar13),0);
30: if (uVar5 == 0) {
31: ppcVar4 = (code **)*param_1;
32: *(undefined4 *)(ppcVar4 + 5) = 0x46;
33: (**ppcVar4)(param_1);
34: }
35: if (param_4 <= uVar5) {
36: uVar5 = (ulong)param_4;
37: }
38: *(int *)(pcVar1 + 0xa0) = (int)uVar5;
39: uVar11 = 0;
40: lVar6 = FUN_0013bee0(param_1,param_2,(ulong)param_4 << 3);
41: if (param_4 == 0) {
42: return lVar6;
43: }
44: do {
45: pcVar1 = param_1[1];
46: uVar9 = (uint)uVar11;
47: if (param_4 - uVar9 < (uint)uVar5) {
48: uVar5 = (ulong)(param_4 - uVar9);
49: }
50: uVar7 = uVar5 * uVar13;
51: if (1000000000 < uVar7) {
52: pcVar2 = *param_1;
53: *(undefined4 *)(pcVar2 + 0x28) = 0x36;
54: *(undefined4 *)(pcVar2 + 0x2c) = 8;
55: (**(code **)*param_1)();
56: }
57: if (1000000000 < uVar7 + 0x37) {
58: pcVar2 = *param_1;
59: *(undefined4 *)(pcVar2 + 0x28) = 0x36;
60: *(undefined4 *)(pcVar2 + 0x2c) = 3;
61: (**(code **)*param_1)();
62: }
63: if (1 < param_2) {
64: pcVar2 = *param_1;
65: *(uint *)(pcVar2 + 0x2c) = param_2;
66: *(undefined4 *)(pcVar2 + 0x28) = 0xe;
67: (**(code **)*param_1)(param_1);
68: }
69: puVar8 = (undefined8 *)FUN_0013d900(param_1,uVar7 + 0x37);
70: if (puVar8 == (undefined8 *)0x0) {
71: pcVar2 = *param_1;
72: *(undefined4 *)(pcVar2 + 0x28) = 0x36;
73: *(undefined4 *)(pcVar2 + 0x2c) = 4;
74: (**(code **)*param_1)();
75: *(ulong *)(pcVar1 + 0x98) = uVar7 + 0x37 + *(long *)(pcVar1 + 0x98);
76: _TURBOJPEG_1.4 = *(undefined8 *)(pcVar1 + (long)(int)param_2 * 8 + 0x78);
77: puVar10 = (undefined8 *)0x18;
78: _DAT_00000010 = 0;
79: _DAT_00000008 = uVar7;
80: *(undefined8 *)(pcVar1 + (long)(int)param_2 * 8 + 0x78) = 0;
81: uVar7 = 0x18;
82: LAB_0013cf01:
83: puVar10 = (undefined8 *)((long)puVar10 + (0x20 - uVar7));
84: }
85: else {
86: *(ulong *)(pcVar1 + 0x98) = uVar7 + 0x37 + *(long *)(pcVar1 + 0x98);
87: uVar3 = *(undefined8 *)(pcVar1 + (long)(int)param_2 * 8 + 0x78);
88: puVar8[1] = uVar7;
89: puVar10 = puVar8 + 3;
90: puVar8[2] = 0;
91: *puVar8 = uVar3;
92: *(undefined8 **)(pcVar1 + (long)(int)param_2 * 8 + 0x78) = puVar8;
93: uVar7 = (ulong)((uint)puVar10 & 0x1f);
94: if (((ulong)puVar10 & 0x1f) != 0) goto LAB_0013cf01;
95: }
96: if ((int)uVar5 != 0) {
97: uVar9 = (int)uVar5 + uVar9;
98: do {
99: uVar12 = (int)uVar11 + 1;
100: *(undefined8 **)(lVar6 + uVar11 * 8) = puVar10;
101: puVar10 = (undefined8 *)((long)puVar10 + uVar13);
102: uVar11 = (ulong)uVar12;
103: } while (uVar12 != uVar9);
104: }
105: if (param_4 <= uVar9) {
106: return lVar6;
107: }
108: uVar11 = (ulong)uVar9;
109: } while( true );
110: }
111: 
