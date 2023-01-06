1: 
2: undefined  [16] FUN_0014e860(long param_1)
3: 
4: {
5: uint uVar1;
6: uint uVar2;
7: long lVar3;
8: long lVar4;
9: ulong uVar5;
10: ulong uVar6;
11: uint uVar7;
12: uint uVar8;
13: ulong uVar9;
14: int iVar10;
15: int iVar11;
16: int iVar12;
17: int iVar13;
18: int *piVar14;
19: int iVar15;
20: uint uStack76;
21: uint uStack60;
22: 
23: uVar2 = *(uint *)(param_1 + 0x38);
24: uVar1 = uVar2 - 1;
25: uStack76 = 0xffffffff;
26: uVar6 = 0;
27: do {
28: uVar7 = *(uint *)(&DAT_0018fd60 + uVar6 * 4);
29: uVar5 = uVar6 & 0xffffffff;
30: uVar9 = uVar6 * 4;
31: if ((uVar2 == uVar7) || ((uVar2 == 4 && *(int *)(param_1 + 0x3c) - 4U < 2 && (uVar7 == 3)))) {
32: iVar15 = *(int *)(&DAT_0018fdd0 + uVar9);
33: lVar3 = *(long *)(param_1 + 0x130);
34: iVar12 = iVar15 + 7;
35: if (-1 < iVar15) {
36: iVar12 = iVar15;
37: }
38: iVar12 = iVar12 >> 3;
39: iVar15 = (int)uVar5;
40: if (*(int *)(lVar3 + 8) == iVar12) {
41: iVar10 = *(int *)(&DAT_0018fdb0 + uVar9);
42: iVar13 = iVar10 + 7;
43: if (-1 < iVar10) {
44: iVar13 = iVar10;
45: }
46: if (*(int *)(lVar3 + 0xc) == iVar13 >> 3) {
47: if ((int)uVar2 < 2) {
48: uStack60 = 0;
49: }
50: else {
51: piVar14 = (int *)(lVar3 + 0x68);
52: uVar8 = 1;
53: uStack60 = 0;
54: do {
55: if ((uVar8 != 3) ||
56: (iVar10 = *(int *)(lVar3 + 0xc), iVar13 = iVar12, 1 < *(int *)(param_1 + 0x3c) - 4U
57: )) {
58: iVar10 = 1;
59: iVar13 = 1;
60: }
61: if (iVar13 == *piVar14) {
62: uStack60 = uStack60 + (iVar10 == piVar14[1]);
63: }
64: uVar8 = uVar8 + 1;
65: piVar14 = piVar14 + 0x18;
66: } while (uVar2 != uVar8);
67: }
68: if (uVar1 == uStack60) goto LAB_0014e9a4;
69: }
70: }
71: if ((*(long *)(lVar3 + 8) == 0x200000002) && ((iVar15 == 1 || (iVar15 == 4)))) {
72: if ((int)uVar2 < 2) {
73: uStack60 = 0;
74: }
75: else {
76: iVar10 = *(int *)(&DAT_0018fdb0 + uVar9);
77: iVar13 = iVar10 + 7;
78: if (-1 < iVar10) {
79: iVar13 = iVar10;
80: }
81: piVar14 = (int *)(lVar3 + 0x68);
82: uVar9 = 1;
83: uStack60 = 0;
84: do {
85: if ((int)uVar9 == 3) {
86: iVar11 = 2;
87: iVar10 = 2;
88: if (1 < *(int *)(param_1 + 0x3c) - 4U) goto LAB_0014eaf9;
89: }
90: else {
91: LAB_0014eaf9:
92: iVar10 = iVar13 >> 3;
93: iVar11 = iVar12;
94: }
95: if (*piVar14 == iVar10) {
96: uStack60 = uStack60 + (piVar14[1] == iVar11);
97: }
98: uVar8 = (int)uVar9 + 1;
99: uVar9 = (ulong)uVar8;
100: piVar14 = piVar14 + 0x18;
101: } while (uVar2 != uVar8);
102: }
103: if (uVar1 == uStack60) goto LAB_0014e9a4;
104: }
105: uVar9 = 10 % (long)(int)uVar7 & 0xffffffff;
106: if (((*(int *)(lVar3 + 8) * *(int *)(lVar3 + 0xc) <= (int)(10 / (long)(int)uVar7)) &&
107: (iVar15 == 0)) && (1 < (int)uVar2)) {
108: lVar4 = lVar3 + 0x60;
109: uVar9 = 0;
110: do {
111: uVar7 = (int)uVar9 + (uint)(*(long *)(lVar3 + 8) == *(long *)(lVar4 + 8));
112: uVar9 = (ulong)uVar7;
113: if (uVar7 == uVar1) {
114: uStack76 = 0;
115: break;
116: }
117: lVar4 = lVar4 + 0x60;
118: } while (lVar4 != lVar3 + 0xc0 + (ulong)(uVar2 - 2) * 0x60);
119: }
120: }
121: uVar6 = uVar6 + 1;
122: } while (uVar6 != 6);
123: uVar5 = (ulong)uStack76;
124: LAB_0014e9a4:
125: return CONCAT88(uVar9,uVar5);
126: }
127: 
