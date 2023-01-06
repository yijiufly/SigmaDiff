1: 
2: void FUN_001274b0(long param_1)
3: 
4: {
5: int *piVar1;
6: long lVar2;
7: long lVar3;
8: bool bVar4;
9: int *piVar5;
10: short *psVar6;
11: long lVar7;
12: int *piVar8;
13: int iVar9;
14: int iVar10;
15: int iVar11;
16: long lVar12;
17: long lVar13;
18: 
19: lVar2 = *(long *)(param_1 + 0x230);
20: if (*(long *)(lVar2 + 0x20) != 0) {
21: if (((*(int *)(param_1 + 0x68) != 0) && (*(int *)(param_1 + 0x138) != 0)) &&
22: (*(long *)(param_1 + 0xc0) != 0)) {
23: piVar5 = *(int **)(lVar2 + 0xe0);
24: iVar10 = *(int *)(param_1 + 0x38);
25: if (piVar5 == (int *)0x0) {
26: piVar5 = (int *)(***(code ***)(param_1 + 8))(param_1,1,(long)(iVar10 * 2) * 0x28);
27: iVar10 = *(int *)(param_1 + 0x38);
28: *(int **)(lVar2 + 0xe0) = piVar5;
29: }
30: piVar8 = piVar5 + iVar10 * 10;
31: if ((((0 < iVar10) &&
32: (psVar6 = *(short **)(*(long *)(param_1 + 0x130) + 0x50), psVar6 != (short *)0x0)) &&
33: ((*psVar6 != 0 && ((psVar6[1] != 0 && (psVar6[8] != 0)))))) && (psVar6[0x10] != 0)) {
34: lVar13 = 0;
35: bVar4 = false;
36: iVar11 = 0;
37: lVar12 = *(long *)(param_1 + 0x130);
38: while( true ) {
39: if (((((psVar6[9] == 0) || (psVar6[2] == 0)) || (psVar6[3] == 0)) ||
40: ((psVar6[10] == 0 || (psVar6[0x11] == 0)))) || (psVar6[0x18] == 0)) goto LAB_001274d0;
41: lVar3 = *(long *)(param_1 + 0xc0);
42: lVar7 = (long)(iVar10 + iVar11) * 0x100;
43: piVar1 = (int *)(lVar3 + lVar13);
44: if (*piVar1 < 0) goto LAB_001274d0;
45: *piVar5 = *piVar1;
46: iVar9 = -1;
47: iVar10 = iVar9;
48: if (1 < *(int *)(param_1 + 0xac)) {
49: iVar10 = *(int *)(lVar3 + 4 + lVar7);
50: }
51: piVar8[1] = iVar10;
52: piVar5[1] = piVar1[1];
53: if (piVar1[1] != 0) {
54: bVar4 = true;
55: }
56: if (1 < *(int *)(param_1 + 0xac)) {
57: iVar9 = *(int *)(lVar3 + 8 + lVar7);
58: }
59: piVar8[2] = iVar9;
60: piVar5[2] = piVar1[2];
61: iVar10 = -1;
62: if (piVar1[2] != 0) {
63: bVar4 = true;
64: }
65: iVar9 = iVar10;
66: if (1 < *(int *)(param_1 + 0xac)) {
67: iVar9 = *(int *)(lVar3 + 0xc + lVar7);
68: }
69: piVar8[3] = iVar9;
70: piVar5[3] = piVar1[3];
71: if (piVar1[3] != 0) {
72: bVar4 = true;
73: }
74: iVar9 = iVar10;
75: if (1 < *(int *)(param_1 + 0xac)) {
76: iVar9 = *(int *)(lVar3 + 0x10 + lVar7);
77: }
78: piVar8[4] = iVar9;
79: piVar5[4] = piVar1[4];
80: if (piVar1[4] != 0) {
81: bVar4 = true;
82: }
83: iVar9 = iVar10;
84: if (1 < *(int *)(param_1 + 0xac)) {
85: iVar9 = *(int *)(lVar3 + 0x14 + lVar7);
86: }
87: piVar8[5] = iVar9;
88: piVar5[5] = piVar1[5];
89: if (piVar1[5] != 0) {
90: bVar4 = true;
91: }
92: if (1 < *(int *)(param_1 + 0xac)) {
93: iVar10 = *(int *)(lVar3 + 0x18 + lVar7);
94: }
95: piVar8[6] = iVar10;
96: piVar5[6] = piVar1[6];
97: iVar10 = -1;
98: if (piVar1[6] != 0) {
99: bVar4 = true;
100: }
101: iVar9 = iVar10;
102: if (1 < *(int *)(param_1 + 0xac)) {
103: iVar9 = *(int *)(lVar3 + 0x1c + lVar7);
104: }
105: piVar8[7] = iVar9;
106: piVar5[7] = piVar1[7];
107: if (piVar1[7] != 0) {
108: bVar4 = true;
109: }
110: iVar9 = iVar10;
111: if (1 < *(int *)(param_1 + 0xac)) {
112: iVar9 = *(int *)(lVar3 + 0x20 + lVar7);
113: }
114: piVar8[8] = iVar9;
115: piVar5[8] = piVar1[8];
116: if (piVar1[8] != 0) {
117: bVar4 = true;
118: }
119: if (1 < *(int *)(param_1 + 0xac)) {
120: iVar10 = *(int *)(lVar3 + 0x24 + lVar7);
121: }
122: piVar8[9] = iVar10;
123: piVar5[9] = piVar1[9];
124: iVar10 = *(int *)(param_1 + 0x38);
125: if (piVar1[9] != 0) {
126: bVar4 = true;
127: }
128: iVar11 = iVar11 + 1;
129: piVar5 = piVar5 + 10;
130: piVar8 = piVar8 + 10;
131: if (iVar10 <= iVar11) break;
132: psVar6 = *(short **)(lVar12 + 0xb0);
133: if (((psVar6 == (short *)0x0) || (*psVar6 == 0)) ||
134: ((psVar6[1] == 0 ||
135: ((psVar6[8] == 0 ||
136: (lVar13 = lVar13 + 0x100, lVar12 = lVar12 + 0x60, psVar6[0x10] == 0))))))
137: goto LAB_001274d0;
138: }
139: if (bVar4) {
140: *(code **)(lVar2 + 0x18) = FUN_00127b40;
141: goto LAB_001274db;
142: }
143: }
144: }
145: LAB_001274d0:
146: *(code **)(lVar2 + 0x18) = FUN_00127260;
147: }
148: LAB_001274db:
149: *(undefined4 *)(param_1 + 0xb8) = 0;
150: return;
151: }
152: 
