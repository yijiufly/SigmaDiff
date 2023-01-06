1: 
2: undefined8 FUN_0013fd50(long param_1,long param_2)
3: 
4: {
5: long lVar1;
6: long lVar2;
7: int iVar3;
8: long lVar4;
9: long lVar5;
10: long extraout_RDX;
11: int iVar6;
12: uint uVar7;
13: long lVar8;
14: long lVar9;
15: long lVar10;
16: uint uVar11;
17: int iStack92;
18: 
19: lVar2 = *(long *)(param_1 + 0x1f0);
20: if (*(int *)(param_1 + 0x118) != 0) {
21: iVar3 = *(int *)(lVar2 + 0x60);
22: if (iVar3 == 0) {
23: FUN_0013ef30(param_1,*(undefined4 *)(lVar2 + 100));
24: iVar3 = *(int *)(param_1 + 0x118);
25: *(uint *)(lVar2 + 100) = *(int *)(lVar2 + 100) + 1U & 7;
26: }
27: *(int *)(lVar2 + 0x60) = iVar3 + -1;
28: }
29: lVar8 = 0;
30: if (0 < *(int *)(param_1 + 0x170)) {
31: do {
32: while( true ) {
33: lVar5 = (long)*(int *)(param_1 + 0x174 + lVar8 * 4);
34: lVar1 = lVar2 + lVar5 * 4;
35: iVar3 = (int)**(short **)(param_2 + lVar8 * 8) >>
36: ((byte)*(undefined4 *)(param_1 + 0x1a8) & 0x1f);
37: lVar4 = (long)*(int *)(*(long *)(param_1 + 0x148 + lVar5 * 8) + 0x14);
38: lVar5 = lVar2 + lVar4 * 8;
39: lVar9 = (long)*(int *)(lVar1 + 0x50) + *(long *)(lVar5 + 0x68);
40: iVar6 = iVar3 - *(int *)(lVar1 + 0x40);
41: if (iVar6 != 0) break;
42: FUN_0013e1a0(param_1,lVar9);
43: *(undefined4 *)(lVar1 + 0x50) = 0;
44: LAB_0013fdba:
45: iVar3 = (int)lVar8 + 1;
46: lVar8 = lVar8 + 1;
47: if (*(int *)(param_1 + 0x170) == iVar3 || *(int *)(param_1 + 0x170) < iVar3) {
48: return 1;
49: }
50: }
51: *(int *)(lVar1 + 0x40) = iVar3;
52: FUN_0013dd70(param_1,lVar9);
53: if (iVar6 < 1) {
54: iVar6 = -iVar6;
55: lVar10 = lVar9 + 3;
56: FUN_0013dd70(param_1,lVar9 + 1);
57: *(undefined4 *)(lVar1 + 0x50) = 8;
58: }
59: else {
60: lVar10 = lVar9 + 2;
61: FUN_0013e1a0(param_1,lVar9 + 1);
62: *(undefined4 *)(lVar1 + 0x50) = 4;
63: }
64: uVar11 = 0;
65: uVar7 = iVar6 - 1;
66: iStack92 = 0;
67: if (uVar7 != 0) {
68: FUN_0013dd70(param_1,lVar10);
69: iVar3 = (int)uVar7 >> 1;
70: lVar5 = *(long *)(lVar5 + 0x68);
71: lVar10 = lVar5 + 0x14;
72: if (iVar3 == 0) {
73: uVar11 = 0;
74: iStack92 = 1;
75: }
76: else {
77: iStack92 = 1;
78: lVar9 = lVar10;
79: do {
80: lVar10 = lVar9 + 1;
81: FUN_0013dd70(param_1,lVar9,lVar5);
82: iStack92 = iStack92 << 1;
83: iVar3 = iVar3 >> 1;
84: lVar5 = extraout_RDX;
85: lVar9 = lVar10;
86: } while (iVar3 != 0);
87: uVar11 = iStack92 >> 1;
88: }
89: }
90: FUN_0013e1a0(param_1,lVar10);
91: if (iStack92 < (int)((1 << (*(byte *)(param_1 + 0xc0 + lVar4) & 0x3f)) >> 1)) {
92: *(undefined4 *)(lVar1 + 0x50) = 0;
93: }
94: else {
95: if ((int)((1 << (*(byte *)(param_1 + 0xd0 + lVar4) & 0x3f)) >> 1) < iStack92) {
96: *(int *)(lVar1 + 0x50) = *(int *)(lVar1 + 0x50) + 8;
97: }
98: }
99: if (uVar11 == 0) goto LAB_0013fdba;
100: do {
101: FUN_0013e5d0(param_1,lVar10 + 0xe,(uVar11 & uVar7) != 0);
102: uVar11 = (int)uVar11 >> 1;
103: } while (uVar11 != 0);
104: iVar3 = (int)lVar8 + 1;
105: lVar8 = lVar8 + 1;
106: } while (*(int *)(param_1 + 0x170) != iVar3 && iVar3 <= *(int *)(param_1 + 0x170));
107: }
108: return 1;
109: }
110: 
