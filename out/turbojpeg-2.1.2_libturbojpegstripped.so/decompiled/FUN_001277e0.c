1: 
2: undefined8 FUN_001277e0(long param_1,long param_2)
3: 
4: {
5: uint *puVar1;
6: undefined8 *puVar2;
7: int iVar3;
8: int iVar4;
9: long lVar5;
10: long lVar6;
11: code *pcVar7;
12: int iVar8;
13: uint uVar9;
14: int iVar10;
15: int iVar11;
16: uint uVar12;
17: long lVar13;
18: long lVar14;
19: int iStack140;
20: uint uStack128;
21: int iStack124;
22: long lStack112;
23: int iStack100;
24: int iStack96;
25: 
26: uVar12 = *(uint *)(param_1 + 0x1a4);
27: lVar5 = *(long *)(param_1 + 0x230);
28: iStack100 = *(int *)(lVar5 + 0x2c);
29: uVar9 = *(int *)(param_1 + 0x1d8) - 1;
30: iVar8 = *(int *)(lVar5 + 0x30);
31: if (iStack100 < iVar8) {
32: uStack128 = *(uint *)(lVar5 + 0x28);
33: if (uStack128 <= uVar9) goto LAB_0012786b;
34: while( true ) {
35: iStack100 = iStack100 + 1;
36: uStack128 = 0;
37: *(undefined4 *)(lVar5 + 0x28) = 0;
38: if (iVar8 <= iStack100) break;
39: LAB_0012786b:
40: do {
41: FUN_00148a80(*(undefined8 *)(lVar5 + 0x38),(long)*(int *)(param_1 + 0x1e0) << 7);
42: lVar6 = *(long *)(param_1 + 0x250);
43: if (*(int *)(lVar6 + 0x10) == 0) {
44: *(undefined4 *)(*(long *)(param_1 + 0x220) + 0x70) = *(undefined4 *)(param_1 + 0xb0);
45: }
46: iVar8 = (**(code **)(lVar6 + 8))();
47: if (iVar8 == 0) {
48: *(int *)(lVar5 + 0x2c) = iStack100;
49: *(uint *)(lVar5 + 0x28) = uStack128;
50: return 0;
51: }
52: puVar1 = (uint *)(*(long *)(param_1 + 0x220) + 0x14);
53: if (((*puVar1 < uStack128 || *puVar1 == uStack128) &&
54: (uStack128 <= *(uint *)(*(long *)(param_1 + 0x220) + 0x18))) &&
55: (iVar8 = *(int *)(param_1 + 0x1b0), 0 < iVar8)) {
56: lStack112 = 1;
57: iStack124 = 0;
58: do {
59: lVar6 = *(long *)(param_1 + 0x1b0 + lStack112 * 8);
60: if (*(int *)(lVar6 + 0x30) == 0) {
61: iStack124 = iStack124 + *(int *)(lVar6 + 0x3c);
62: }
63: else {
64: pcVar7 = *(code **)(*(long *)(param_1 + 600) + 8 + (long)*(int *)(lVar6 + 4) * 8);
65: if (uStack128 < uVar9) {
66: iStack96 = *(int *)(lVar6 + 0x34);
67: }
68: else {
69: iStack96 = *(int *)(lVar6 + 0x44);
70: }
71: iVar11 = *(int *)(lVar6 + 0x24);
72: lVar13 = *(long *)(param_2 + (long)*(int *)(lVar6 + 4) * 8) +
73: (long)(iStack100 * iVar11) * 8;
74: iVar3 = *(int *)(*(long *)(param_1 + 0x220) + 0x14);
75: iVar4 = *(int *)(lVar6 + 0x40);
76: iVar10 = *(int *)(lVar6 + 0x38);
77: if (0 < iVar10) {
78: iStack140 = 0;
79: do {
80: if (((*(uint *)(param_1 + 0xb0) < uVar12 - 1) ||
81: (*(int *)(lVar6 + 0x48) != iStack100 + iStack140 &&
82: iStack100 + iStack140 <= *(int *)(lVar6 + 0x48))) && (0 < iStack96)) {
83: lVar14 = lVar5 + (long)iStack124 * 8;
84: iVar8 = iVar4 * (uStack128 - iVar3);
85: do {
86: puVar2 = (undefined8 *)(lVar14 + 0x38);
87: lVar14 = lVar14 + 8;
88: (*pcVar7)(param_1,lVar6,*puVar2,lVar13,iVar8);
89: iVar11 = *(int *)(lVar6 + 0x24);
90: iVar8 = iVar8 + iVar11;
91: } while (lVar5 + 8 + ((ulong)(iStack96 - 1) + (long)iStack124) * 8 != lVar14);
92: iVar10 = *(int *)(lVar6 + 0x38);
93: }
94: iStack140 = iStack140 + 1;
95: lVar13 = lVar13 + (long)iVar11 * 8;
96: iStack124 = iStack124 + *(int *)(lVar6 + 0x34);
97: } while (iStack140 < iVar10);
98: iVar8 = *(int *)(param_1 + 0x1b0);
99: }
100: }
101: iVar11 = (int)lStack112;
102: lStack112 = lStack112 + 1;
103: } while (iVar11 < iVar8);
104: }
105: uStack128 = uStack128 + 1;
106: } while (uStack128 <= uVar9);
107: iVar8 = *(int *)(lVar5 + 0x30);
108: }
109: uVar12 = *(uint *)(param_1 + 0x1a4);
110: }
111: *(int *)(param_1 + 0xb8) = *(int *)(param_1 + 0xb8) + 1;
112: uVar9 = *(int *)(param_1 + 0xb0) + 1;
113: *(uint *)(param_1 + 0xb0) = uVar9;
114: if (uVar9 < uVar12) {
115: lVar5 = *(long *)(param_1 + 0x230);
116: if (*(int *)(param_1 + 0x1b0) < 2) {
117: if (uVar9 < uVar12 - 1) {
118: *(undefined4 *)(lVar5 + 0x30) = *(undefined4 *)(*(long *)(param_1 + 0x1b8) + 0xc);
119: }
120: else {
121: *(undefined4 *)(lVar5 + 0x30) = *(undefined4 *)(*(long *)(param_1 + 0x1b8) + 0x48);
122: }
123: }
124: else {
125: *(undefined4 *)(lVar5 + 0x30) = 1;
126: }
127: *(undefined8 *)(lVar5 + 0x28) = 0;
128: return 3;
129: }
130: (**(code **)(*(long *)(param_1 + 0x240) + 0x18))(param_1);
131: return 4;
132: }
133: 
