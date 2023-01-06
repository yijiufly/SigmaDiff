1: 
2: undefined8 FUN_00120010(long param_1,long param_2)
3: 
4: {
5: uint *puVar1;
6: uint uVar2;
7: int iVar3;
8: int iVar4;
9: long lVar5;
10: long lVar6;
11: code *pcVar7;
12: uint uVar8;
13: int iVar9;
14: undefined8 uVar10;
15: int iVar11;
16: int iVar12;
17: long lVar13;
18: int iVar14;
19: int iVar15;
20: int iStack112;
21: uint uStack104;
22: int iStack100;
23: int iStack92;
24: long lStack88;
25: int iStack80;
26: 
27: uVar2 = *(uint *)(param_1 + 0x1a4);
28: lVar5 = *(long *)(param_1 + 0x230);
29: uVar8 = *(int *)(param_1 + 0x1d8) - 1;
30: iStack92 = *(int *)(lVar5 + 0x2c);
31: iVar9 = *(int *)(lVar5 + 0x30);
32: if (iStack92 < iVar9) {
33: uStack104 = *(uint *)(lVar5 + 0x28);
34: if (uVar8 < uStack104) goto LAB_00120140;
35: while( true ) {
36: do {
37: FUN_0013bed0(*(undefined8 *)(lVar5 + 0x38),(long)*(int *)(param_1 + 0x1e0) << 7);
38: uVar10 = (**(code **)(*(long *)(param_1 + 0x250) + 8))(param_1);
39: if ((int)uVar10 == 0) {
40: *(int *)(lVar5 + 0x2c) = iStack92;
41: *(uint *)(lVar5 + 0x28) = uStack104;
42: return uVar10;
43: }
44: puVar1 = (uint *)(*(long *)(param_1 + 0x220) + 0x14);
45: if (((*puVar1 < uStack104 || *puVar1 == uStack104) &&
46: (uStack104 <= *(uint *)(*(long *)(param_1 + 0x220) + 0x18))) &&
47: (iVar9 = *(int *)(param_1 + 0x1b0), 0 < iVar9)) {
48: iStack80 = 0;
49: iStack112 = 0;
50: lStack88 = param_1;
51: do {
52: lVar6 = *(long *)(lStack88 + 0x1b8);
53: if (*(int *)(lVar6 + 0x30) == 0) {
54: iStack112 = iStack112 + *(int *)(lVar6 + 0x3c);
55: }
56: else {
57: pcVar7 = *(code **)(*(long *)(param_1 + 600) + 8 + (long)*(int *)(lVar6 + 4) * 8);
58: if (uStack104 < uVar8) {
59: iStack100 = *(int *)(lVar6 + 0x34);
60: }
61: else {
62: iStack100 = *(int *)(lVar6 + 0x44);
63: }
64: iVar12 = *(int *)(lVar6 + 0x24);
65: lVar13 = *(long *)(param_2 + (long)*(int *)(lVar6 + 4) * 8) +
66: (long)(iStack92 * iVar12) * 8;
67: iVar3 = *(int *)(*(long *)(param_1 + 0x220) + 0x14);
68: iVar11 = *(int *)(lVar6 + 0x38);
69: iVar4 = *(int *)(lVar6 + 0x40);
70: if (0 < iVar11) {
71: iVar9 = 0;
72: do {
73: if (((*(uint *)(param_1 + 0xb0) <= uVar2 - 1 &&
74: uVar2 - 1 != *(uint *)(param_1 + 0xb0)) ||
75: (*(int *)(lVar6 + 0x48) != iStack92 + iVar9 &&
76: iStack92 + iVar9 <= *(int *)(lVar6 + 0x48))) &&
77: (iVar15 = iStack112, iVar14 = (uStack104 - iVar3) * iVar4, 0 < iStack100)) {
78: do {
79: (*pcVar7)(param_1,lVar6,*(undefined8 *)(lVar5 + 0x38 + (long)iVar15 * 8),
80: lVar13,iVar14);
81: iVar12 = *(int *)(lVar6 + 0x24);
82: iVar15 = iVar15 + 1;
83: iVar14 = iVar14 + iVar12;
84: } while (iVar15 != iStack112 + iStack100);
85: iVar11 = *(int *)(lVar6 + 0x38);
86: }
87: iStack112 = iStack112 + *(int *)(lVar6 + 0x34);
88: lVar13 = lVar13 + (long)iVar12 * 8;
89: iVar15 = iVar9 + 1;
90: iVar9 = iVar9 + 1;
91: } while (iVar15 < iVar11);
92: iVar9 = *(int *)(param_1 + 0x1b0);
93: }
94: }
95: iStack80 = iStack80 + 1;
96: lStack88 = lStack88 + 8;
97: } while (iStack80 < iVar9);
98: }
99: uStack104 = uStack104 + 1;
100: } while (uStack104 <= uVar8);
101: iVar9 = *(int *)(lVar5 + 0x30);
102: LAB_00120140:
103: iStack92 = iStack92 + 1;
104: *(undefined4 *)(lVar5 + 0x28) = 0;
105: if (iVar9 <= iStack92) break;
106: uStack104 = 0;
107: }
108: uVar2 = *(uint *)(param_1 + 0x1a4);
109: }
110: *(int *)(param_1 + 0xb8) = *(int *)(param_1 + 0xb8) + 1;
111: uVar8 = *(int *)(param_1 + 0xb0) + 1;
112: *(uint *)(param_1 + 0xb0) = uVar8;
113: if (uVar2 <= uVar8) {
114: (**(code **)(*(long *)(param_1 + 0x240) + 0x18))(param_1);
115: return 4;
116: }
117: lVar5 = *(long *)(param_1 + 0x230);
118: if (*(int *)(param_1 + 0x1b0) < 2) {
119: if (uVar8 < uVar2 - 1) {
120: *(undefined4 *)(lVar5 + 0x30) = *(undefined4 *)(*(long *)(param_1 + 0x1b8) + 0xc);
121: }
122: else {
123: *(undefined4 *)(lVar5 + 0x30) = *(undefined4 *)(*(long *)(param_1 + 0x1b8) + 0x48);
124: }
125: }
126: else {
127: *(undefined4 *)(lVar5 + 0x30) = 1;
128: }
129: *(undefined4 *)(lVar5 + 0x28) = 0;
130: *(undefined4 *)(lVar5 + 0x2c) = 0;
131: return 3;
132: }
133: 
