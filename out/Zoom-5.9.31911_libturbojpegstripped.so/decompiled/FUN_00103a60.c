1: 
2: void FUN_00103a60(long param_1,undefined8 *param_2)
3: 
4: {
5: undefined2 uVar1;
6: uint uVar2;
7: long lVar3;
8: long *plVar4;
9: uint uVar5;
10: uint uVar6;
11: long *plVar7;
12: long lVar8;
13: long lVar9;
14: uint uVar10;
15: uint uVar11;
16: undefined2 *puVar12;
17: undefined2 *puVar13;
18: uint uVar14;
19: undefined8 *puStack136;
20: int iStack92;
21: 
22: lVar3 = *(long *)(param_1 + 0x1c8);
23: lVar9 = *(long *)(param_1 + 0x58);
24: iStack92 = 0;
25: uVar6 = *(int *)(param_1 + 0x140) - 1;
26: puStack136 = param_2;
27: if (0 < *(int *)(param_1 + 0x4c)) {
28: do {
29: plVar4 = (long *)(**(code **)(*(long *)(param_1 + 8) + 0x40))
30: (param_1,*(undefined8 *)(lVar3 + 0x70 + (long)iStack92 * 8),
31: *(int *)(lVar3 + 0x10) * *(int *)(lVar9 + 0xc));
32: uVar11 = *(uint *)(lVar3 + 0x10);
33: uVar10 = *(uint *)(lVar9 + 0xc);
34: uVar14 = uVar10;
35: if ((uVar6 <= uVar11) && (uVar14 = *(uint *)(lVar9 + 0x20) % uVar10, uVar14 == 0)) {
36: uVar14 = uVar10;
37: }
38: uVar10 = *(uint *)(lVar9 + 0x1c);
39: uVar2 = *(uint *)(lVar9 + 8);
40: uVar5 = uVar10 % uVar2;
41: if (0 < (int)uVar5) {
42: uVar5 = uVar2 - uVar5;
43: }
44: if (0 < (int)uVar14) {
45: plVar7 = plVar4;
46: do {
47: lVar8 = *plVar7;
48: (**(code **)(*(long *)(param_1 + 0x1e8) + 8))
49: (param_1,lVar9,*puStack136,lVar8,(int)plVar7 - (int)plVar4,0,uVar10);
50: if (0 < (int)uVar5) {
51: puVar12 = (undefined2 *)(lVar8 + (ulong)uVar10 * 0x80);
52: FUN_0013bed0(puVar12,(long)(int)uVar5 << 7);
53: uVar1 = puVar12[-0x40];
54: puVar13 = puVar12 + (ulong)(uVar5 - 1) * 0x40 + 0x40;
55: do {
56: *puVar12 = uVar1;
57: puVar12 = puVar12 + 0x40;
58: } while (puVar12 != puVar13);
59: }
60: plVar7 = plVar7 + 1;
61: } while (plVar7 != plVar4 + (ulong)(uVar14 - 1) + 1);
62: uVar11 = *(uint *)(lVar3 + 0x10);
63: }
64: if ((uVar6 == uVar11) &&
65: (uVar11 = (uVar5 + uVar10) / uVar2, (int)uVar14 < *(int *)(lVar9 + 0xc))) {
66: plVar4 = plVar4 + (long)(int)uVar14 + -1;
67: do {
68: puVar13 = (undefined2 *)plVar4[1];
69: lVar8 = *plVar4;
70: FUN_0013bed0();
71: uVar10 = 0;
72: if (uVar11 != 0) {
73: do {
74: lVar8 = lVar8 + (long)(int)uVar2 * 0x80;
75: uVar1 = *(undefined2 *)(lVar8 + -0x80);
76: puVar12 = puVar13;
77: if (0 < (int)uVar2) {
78: do {
79: *puVar12 = uVar1;
80: puVar12 = puVar12 + 0x40;
81: } while (puVar12 != puVar13 + (ulong)(uVar2 - 1) * 0x40 + 0x40);
82: }
83: uVar10 = uVar10 + 1;
84: puVar13 = puVar13 + (long)(int)uVar2 * 0x40;
85: } while (uVar10 != uVar11);
86: }
87: uVar14 = uVar14 + 1;
88: plVar4 = plVar4 + 1;
89: } while (*(uint *)(lVar9 + 0xc) != uVar14 && (int)uVar14 <= (int)*(uint *)(lVar9 + 0xc));
90: }
91: iStack92 = iStack92 + 1;
92: lVar9 = lVar9 + 0x60;
93: puStack136 = puStack136 + 1;
94: } while (*(int *)(param_1 + 0x4c) != iStack92 && iStack92 <= *(int *)(param_1 + 0x4c));
95: }
96: FUN_00103480(param_1,param_2);
97: return;
98: }
99: 
