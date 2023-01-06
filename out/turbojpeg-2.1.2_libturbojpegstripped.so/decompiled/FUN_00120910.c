1: 
2: void FUN_00120910(long param_1)
3: 
4: {
5: long *plVar1;
6: byte *pbVar2;
7: code **ppcVar3;
8: long lVar4;
9: undefined *puVar5;
10: undefined8 *puVar6;
11: int iVar7;
12: uint uVar8;
13: ulong uVar9;
14: int iVar10;
15: byte *pbVar11;
16: uint uVar12;
17: uint uVar13;
18: ulong uVar14;
19: 
20: if (*(int *)(param_1 + 0x6c) == 0) {
21: return;
22: }
23: iVar10 = (byte)(&DAT_0017cd40)[*(int *)(param_1 + 0x6c)] - 1;
24: if (0xe < iVar10) {
25: ppcVar3 = (code **)**(code ***)(param_1 + 0x50);
26: *(undefined4 *)(ppcVar3 + 5) = 0x28;
27: (**ppcVar3)();
28: }
29: iVar7 = iVar10 * 0x10;
30: if (*(int *)(param_1 + 0x28) == 0) {
31: lVar4 = *(long *)(param_1 + 0x88 + (long)*(int *)(param_1 + 0x68) * 8);
32: FUN_001207a0(param_1,*(undefined4 *)(lVar4 + (long)iVar7 * 4),
33: (int)*(char *)(lVar4 + 0x400 + (long)iVar7));
34: }
35: else {
36: plVar1 = (long *)(*(long *)(param_1 + 0xa8 + (long)*(int *)(param_1 + 0x68) * 8) +
37: (long)iVar7 * 8);
38: *plVar1 = *plVar1 + 1;
39: }
40: if (iVar10 == 0) {
41: iVar10 = *(int *)(param_1 + 0x28);
42: *(undefined4 *)(param_1 + 0x6c) = 0;
43: }
44: else {
45: FUN_001207a0(param_1,*(undefined4 *)(param_1 + 0x6c),iVar10);
46: iVar10 = *(int *)(param_1 + 0x28);
47: *(undefined4 *)(param_1 + 0x6c) = 0;
48: }
49: if ((iVar10 == 0) && (*(int *)(param_1 + 0x70) != 0)) {
50: pbVar11 = *(byte **)(param_1 + 0x78);
51: uVar12 = *(uint *)(param_1 + 0x48);
52: pbVar2 = pbVar11 + (ulong)(*(int *)(param_1 + 0x70) - 1) + 1;
53: do {
54: if (iVar10 == 0) {
55: uVar13 = uVar12 + 1;
56: uVar9 = (ulong)(*pbVar11 & 1) << (0x18U - (char)uVar13 & 0x3f) | *(ulong *)(param_1 + 0x40);
57: if (7 < (int)uVar13) {
58: uVar8 = uVar12 - 7 & 7;
59: do {
60: while( true ) {
61: uVar14 = uVar9;
62: puVar5 = *(undefined **)(param_1 + 0x30);
63: *(undefined **)(param_1 + 0x30) = puVar5 + 1;
64: *puVar5 = (char)(uVar14 >> 0x10);
65: plVar1 = (long *)(param_1 + 0x38);
66: *plVar1 = *plVar1 + -1;
67: if (*plVar1 == 0) {
68: puVar6 = *(undefined8 **)(*(long *)(param_1 + 0x50) + 0x28);
69: iVar10 = (*(code *)puVar6[3])();
70: if (iVar10 == 0) {
71: ppcVar3 = (code **)**(code ***)(param_1 + 0x50);
72: *(undefined4 *)(ppcVar3 + 5) = 0x18;
73: (**ppcVar3)();
74: }
75: *(undefined8 *)(param_1 + 0x30) = *puVar6;
76: *(undefined8 *)(param_1 + 0x38) = puVar6[1];
77: }
78: if (((uint)(uVar14 >> 0x10) & 0xff) == 0xff) break;
79: LAB_00120a48:
80: uVar13 = uVar13 - 8;
81: uVar9 = uVar14 << 8;
82: if (uVar13 == uVar8) goto LAB_00120af0;
83: }
84: puVar5 = *(undefined **)(param_1 + 0x30);
85: *(undefined **)(param_1 + 0x30) = puVar5 + 1;
86: *puVar5 = 0;
87: plVar1 = (long *)(param_1 + 0x38);
88: *plVar1 = *plVar1 + -1;
89: if (*plVar1 != 0) goto LAB_00120a48;
90: puVar6 = *(undefined8 **)(*(long *)(param_1 + 0x50) + 0x28);
91: iVar10 = (*(code *)puVar6[3])();
92: if (iVar10 == 0) {
93: ppcVar3 = (code **)**(code ***)(param_1 + 0x50);
94: *(undefined4 *)(ppcVar3 + 5) = 0x18;
95: (**ppcVar3)();
96: }
97: uVar13 = uVar13 - 8;
98: *(undefined8 *)(param_1 + 0x30) = *puVar6;
99: *(undefined8 *)(param_1 + 0x38) = puVar6[1];
100: uVar9 = uVar14 << 8;
101: } while (uVar13 != uVar8);
102: LAB_00120af0:
103: uVar9 = uVar14 << 8;
104: uVar13 = uVar12 - 7 & 7;
105: }
106: uVar12 = uVar13;
107: *(ulong *)(param_1 + 0x40) = uVar9;
108: *(uint *)(param_1 + 0x48) = uVar12;
109: }
110: pbVar11 = pbVar11 + 1;
111: if (pbVar11 == pbVar2) break;
112: iVar10 = *(int *)(param_1 + 0x28);
113: } while( true );
114: }
115: *(undefined4 *)(param_1 + 0x70) = 0;
116: return;
117: }
118: 
