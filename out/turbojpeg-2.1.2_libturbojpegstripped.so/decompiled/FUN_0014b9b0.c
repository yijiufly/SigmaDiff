1: 
2: undefined8 FUN_0014b9b0(long param_1,long param_2)
3: 
4: {
5: long lVar1;
6: long lVar2;
7: long lVar3;
8: uint uVar4;
9: int iVar5;
10: int iVar6;
11: long lVar7;
12: long lVar8;
13: int iVar9;
14: long lVar10;
15: uint uVar11;
16: int iStack88;
17: 
18: lVar3 = *(long *)(param_1 + 0x1f0);
19: if (*(int *)(param_1 + 0x118) != 0) {
20: iVar5 = *(int *)(lVar3 + 0x60);
21: if (iVar5 == 0) {
22: FUN_0014b810();
23: iVar5 = *(int *)(param_1 + 0x118);
24: *(uint *)(lVar3 + 100) = *(int *)(lVar3 + 100) + 1U & 7;
25: }
26: *(int *)(lVar3 + 0x60) = iVar5 + -1;
27: }
28: if (0 < *(int *)(param_1 + 0x170)) {
29: lVar8 = 1;
30: do {
31: while( true ) {
32: lVar7 = (long)*(int *)(param_1 + 0x170 + lVar8 * 4);
33: lVar1 = lVar3 + lVar7 * 4;
34: lVar10 = (long)*(int *)(*(long *)(param_1 + 0x148 + lVar7 * 8) + 0x14);
35: iVar6 = (int)**(short **)(param_2 + -8 + lVar8 * 8) >>
36: ((byte)*(undefined4 *)(param_1 + 0x1a8) & 0x1f);
37: lVar2 = lVar3 + lVar10 * 8;
38: lVar7 = (long)*(int *)(lVar1 + 0x50) + *(long *)(lVar2 + 0x68);
39: iVar9 = iVar6 - *(int *)(lVar1 + 0x40);
40: iVar5 = (int)lVar8;
41: if (iVar9 != 0) break;
42: FUN_0014a8b0(param_1,lVar7);
43: *(undefined4 *)(lVar1 + 0x50) = 0;
44: LAB_0014ba23:
45: lVar8 = lVar8 + 1;
46: if (*(int *)(param_1 + 0x170) == iVar5 || *(int *)(param_1 + 0x170) < iVar5) {
47: return 1;
48: }
49: }
50: *(int *)(lVar1 + 0x40) = iVar6;
51: FUN_0014ac60(param_1,lVar7);
52: if (iVar9 < 1) {
53: iVar9 = -iVar9;
54: FUN_0014ac60(param_1,lVar7 + 1);
55: lVar7 = lVar7 + 3;
56: *(undefined4 *)(lVar1 + 0x50) = 8;
57: }
58: else {
59: FUN_0014a8b0(param_1);
60: lVar7 = lVar7 + 2;
61: *(undefined4 *)(lVar1 + 0x50) = 4;
62: }
63: uVar4 = iVar9 - 1;
64: uVar11 = 0;
65: iStack88 = 0;
66: if (uVar4 != 0) {
67: FUN_0014ac60(param_1,lVar7);
68: iVar6 = 1;
69: iStack88 = 1;
70: lVar7 = *(long *)(lVar2 + 0x68) + 0x14;
71: uVar11 = (int)uVar4 >> 1;
72: if (uVar11 != 0) {
73: do {
74: FUN_0014ac60(param_1,lVar7);
75: iStack88 = iVar6 << 1;
76: lVar7 = lVar7 + 1;
77: uVar11 = (int)uVar11 >> 1;
78: iVar6 = iStack88;
79: } while (uVar11 != 0);
80: uVar11 = iStack88 >> 1;
81: }
82: }
83: FUN_0014a8b0(param_1,lVar7);
84: if (iStack88 < (int)((1 << (*(byte *)(param_1 + 0xc0 + lVar10) & 0x3f)) >> 1)) {
85: *(undefined4 *)(lVar1 + 0x50) = 0;
86: }
87: else {
88: if ((int)((1 << (*(byte *)(param_1 + 0xd0 + lVar10) & 0x3f)) >> 1) < iStack88) {
89: *(int *)(lVar1 + 0x50) = *(int *)(lVar1 + 0x50) + 8;
90: }
91: }
92: if (uVar11 == 0) goto LAB_0014ba23;
93: do {
94: FUN_0014b010(param_1,lVar7 + 0xe,(uVar11 & uVar4) != 0);
95: uVar11 = (int)uVar11 >> 1;
96: } while (uVar11 != 0);
97: lVar8 = lVar8 + 1;
98: } while (*(int *)(param_1 + 0x170) != iVar5 && iVar5 <= *(int *)(param_1 + 0x170));
99: }
100: return 1;
101: }
102: 
