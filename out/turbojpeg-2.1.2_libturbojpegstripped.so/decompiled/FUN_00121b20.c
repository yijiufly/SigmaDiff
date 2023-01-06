1: 
2: undefined8 FUN_00121b20(long param_1,long param_2)
3: 
4: {
5: long *plVar1;
6: undefined4 uVar2;
7: long lVar3;
8: undefined8 uVar4;
9: undefined8 *puVar5;
10: code **ppcVar6;
11: int iVar7;
12: int iVar8;
13: undefined *puVar9;
14: ulong uVar10;
15: long lVar11;
16: uint uVar12;
17: uint uVar13;
18: uint uVar14;
19: ulong uVar15;
20: byte bStack76;
21: 
22: uVar2 = *(undefined4 *)(param_1 + 0x1a8);
23: iVar8 = *(int *)(param_1 + 0x118);
24: lVar3 = *(long *)(param_1 + 0x1f0);
25: puVar9 = (undefined *)**(undefined8 **)(param_1 + 0x28);
26: uVar4 = (*(undefined8 **)(param_1 + 0x28))[1];
27: *(undefined **)(lVar3 + 0x30) = puVar9;
28: *(undefined8 *)(lVar3 + 0x38) = uVar4;
29: if ((iVar8 != 0) && (*(int *)(lVar3 + 0x80) == 0)) {
30: FUN_00120fe0(lVar3,*(undefined4 *)(lVar3 + 0x84));
31: puVar9 = *(undefined **)(lVar3 + 0x30);
32: }
33: iVar8 = *(int *)(param_1 + 0x170);
34: if (0 < iVar8) {
35: uVar12 = *(uint *)(lVar3 + 0x48);
36: lVar11 = 1;
37: do {
38: if (*(int *)(lVar3 + 0x28) == 0) {
39: uVar14 = uVar12 + 1;
40: bStack76 = (byte)uVar2;
41: uVar10 = *(ulong *)(lVar3 + 0x40) |
42: (ulong)((int)**(short **)(param_2 + -8 + lVar11 * 8) >> (bStack76 & 0x1f) & 1) <<
43: (0x18U - (char)uVar14 & 0x3f);
44: if (7 < (int)uVar14) {
45: uVar13 = uVar12 - 7 & 7;
46: do {
47: while( true ) {
48: uVar15 = uVar10;
49: *(undefined **)(lVar3 + 0x30) = puVar9 + 1;
50: *puVar9 = (char)(uVar15 >> 0x10);
51: plVar1 = (long *)(lVar3 + 0x38);
52: *plVar1 = *plVar1 + -1;
53: if (*plVar1 == 0) {
54: puVar5 = *(undefined8 **)(*(long *)(lVar3 + 0x50) + 0x28);
55: iVar8 = (*(code *)puVar5[3])();
56: if (iVar8 == 0) {
57: ppcVar6 = (code **)**(code ***)(lVar3 + 0x50);
58: *(undefined4 *)(ppcVar6 + 5) = 0x18;
59: (**ppcVar6)();
60: }
61: puVar9 = (undefined *)*puVar5;
62: uVar4 = puVar5[1];
63: *(undefined **)(lVar3 + 0x30) = puVar9;
64: *(undefined8 *)(lVar3 + 0x38) = uVar4;
65: }
66: else {
67: puVar9 = *(undefined **)(lVar3 + 0x30);
68: }
69: if (((uint)(uVar15 >> 0x10) & 0xff) == 0xff) break;
70: LAB_00121bf0:
71: uVar14 = uVar14 - 8;
72: uVar10 = uVar15 << 8;
73: if (uVar14 == uVar13) goto LAB_00121c55;
74: }
75: *(undefined **)(lVar3 + 0x30) = puVar9 + 1;
76: *puVar9 = 0;
77: plVar1 = (long *)(lVar3 + 0x38);
78: *plVar1 = *plVar1 + -1;
79: if (*plVar1 == 0) {
80: puVar5 = *(undefined8 **)(*(long *)(lVar3 + 0x50) + 0x28);
81: iVar8 = (*(code *)puVar5[3])();
82: if (iVar8 == 0) {
83: ppcVar6 = (code **)**(code ***)(lVar3 + 0x50);
84: *(undefined4 *)(ppcVar6 + 5) = 0x18;
85: (**ppcVar6)();
86: }
87: puVar9 = (undefined *)*puVar5;
88: uVar4 = puVar5[1];
89: *(undefined **)(lVar3 + 0x30) = puVar9;
90: *(undefined8 *)(lVar3 + 0x38) = uVar4;
91: goto LAB_00121bf0;
92: }
93: uVar14 = uVar14 - 8;
94: puVar9 = *(undefined **)(lVar3 + 0x30);
95: uVar10 = uVar15 << 8;
96: } while (uVar14 != uVar13);
97: LAB_00121c55:
98: uVar10 = uVar15 << 8;
99: iVar8 = *(int *)(param_1 + 0x170);
100: uVar14 = uVar12 - 7 & 7;
101: }
102: uVar12 = uVar14;
103: *(ulong *)(lVar3 + 0x40) = uVar10;
104: *(uint *)(lVar3 + 0x48) = uVar12;
105: }
106: iVar7 = (int)lVar11;
107: lVar11 = lVar11 + 1;
108: } while (iVar7 < iVar8);
109: }
110: puVar5 = *(undefined8 **)(param_1 + 0x28);
111: *puVar5 = puVar9;
112: puVar5[1] = *(undefined8 *)(lVar3 + 0x38);
113: iVar8 = *(int *)(param_1 + 0x118);
114: if (iVar8 != 0) {
115: iVar7 = *(int *)(lVar3 + 0x80);
116: if (*(int *)(lVar3 + 0x80) == 0) {
117: *(uint *)(lVar3 + 0x84) = *(int *)(lVar3 + 0x84) + 1U & 7;
118: iVar7 = iVar8;
119: }
120: *(int *)(lVar3 + 0x80) = iVar7 + -1;
121: }
122: return 1;
123: }
124: 
