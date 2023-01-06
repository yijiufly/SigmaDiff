1: 
2: void FUN_0013d9c0(code **param_1)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: int iVar3;
8: int iVar4;
9: code **ppcVar5;
10: bool bVar6;
11: bool bVar7;
12: int iVar8;
13: int iVar9;
14: undefined4 uVar10;
15: int iVar11;
16: code **ppcVar12;
17: code *pcVar13;
18: code *pcVar14;
19: long lVar15;
20: 
21: if (*(int *)(param_1[0x44] + 0x6c) == 0) {
22: ppcVar12 = (code **)(**(code **)param_1[1])(param_1,1,0x100);
23: param_1[0x4c] = (code *)ppcVar12;
24: *(undefined4 *)(ppcVar12 + 2) = 0;
25: *ppcVar12 = FUN_0013c8b0;
26: ppcVar12[1] = FUN_0013c8d0;
27: }
28: else {
29: ppcVar12 = (code **)param_1[0x4c];
30: }
31: if (*(int *)(param_1 + 0x31) != 0) {
32: ppcVar5 = (code **)*param_1;
33: *(undefined4 *)(ppcVar5 + 5) = 0x19;
34: (**ppcVar5)();
35: }
36: if (*(int *)((long)param_1 + 100) == 0) {
37: bVar7 = false;
38: bVar6 = false;
39: }
40: else {
41: bVar6 = 1 < *(int *)(param_1 + 0x34);
42: bVar7 = 1 < *(int *)(param_1 + 0x34);
43: }
44: pcVar14 = param_1[0x26];
45: if (0 < *(int *)(param_1 + 7)) {
46: lVar15 = 1;
47: do {
48: while( true ) {
49: iVar11 = *(int *)(pcVar14 + 0x24);
50: iVar1 = *(int *)(param_1 + 0x34);
51: iVar2 = *(int *)(pcVar14 + 8);
52: iVar3 = *(int *)(param_1 + 0x33);
53: iVar4 = *(int *)((long)param_1 + 0x19c);
54: iVar9 = (*(int *)(pcVar14 + 0xc) * iVar11) / iVar1;
55: *(int *)((long)ppcVar12 + lVar15 * 4 + 0xbc) = iVar9;
56: iVar8 = (int)lVar15;
57: if (*(int *)(pcVar14 + 0x30) == 0) break;
58: iVar1 = (iVar2 * iVar11) / iVar1;
59: if ((iVar1 != iVar3) || (iVar9 != iVar4)) {
60: if ((iVar1 * 2 != iVar3) || (iVar9 != iVar4)) {
61: if ((iVar1 == iVar3) && ((iVar9 * 2 == iVar4 && (bVar7)))) {
62: ppcVar12[lVar15 + 0xc] = FUN_0013d340;
63: *(undefined4 *)(ppcVar12 + 2) = 1;
64: }
65: else {
66: if ((iVar1 * 2 == iVar3) && (iVar9 * 2 == iVar4)) {
67: if ((bVar6) && (2 < *(uint *)(pcVar14 + 0x28))) {
68: iVar11 = FUN_0016c010();
69: pcVar13 = FUN_0013d3f0;
70: if (iVar11 != 0) {
71: pcVar13 = FUN_0016c040;
72: }
73: ppcVar12[lVar15 + 0xc] = pcVar13;
74: *(undefined4 *)(ppcVar12 + 2) = 1;
75: }
76: else {
77: iVar11 = FUN_0016bfb0();
78: if (iVar11 == 0) {
79: ppcVar12[lVar15 + 0xc] = FUN_0013d720;
80: }
81: else {
82: ppcVar12[lVar15 + 0xc] = FUN_0016bff0;
83: }
84: }
85: }
86: else {
87: if ((iVar3 % iVar1 == 0) && (iVar4 % iVar9 == 0)) {
88: ppcVar12[lVar15 + 0xc] = FUN_0013d550;
89: *(char *)((long)ppcVar12 + lVar15 + 0xe7) = (char)(iVar3 / iVar1);
90: *(char *)((long)ppcVar12 + lVar15 + 0xf1) = (char)(iVar4 / iVar9);
91: }
92: else {
93: ppcVar5 = (code **)*param_1;
94: *(undefined4 *)(ppcVar5 + 5) = 0x26;
95: (**ppcVar5)();
96: }
97: }
98: }
99: }
100: else {
101: if ((bVar6) && (2 < *(uint *)(pcVar14 + 0x28))) {
102: iVar11 = FUN_0016c020();
103: if (iVar11 == 0) {
104: ppcVar12[lVar15 + 0xc] = FUN_0013cc90;
105: }
106: else {
107: ppcVar12[lVar15 + 0xc] = FUN_0016c050;
108: }
109: }
110: else {
111: iVar11 = FUN_0016bfc0();
112: if (iVar11 == 0) {
113: ppcVar12[lVar15 + 0xc] = FUN_0013ca30;
114: }
115: else {
116: ppcVar12[lVar15 + 0xc] = FUN_0016c000;
117: }
118: }
119: }
120: if (*(int *)(param_1[0x44] + 0x6c) == 0) {
121: pcVar13 = *(code **)(param_1[1] + 0x10);
122: uVar10 = FUN_001489e0(*(undefined4 *)(param_1 + 0x11),(long)*(int *)(param_1 + 0x33));
123: pcVar13 = (code *)(*pcVar13)(param_1,1,uVar10);
124: ppcVar12[lVar15 + 2] = pcVar13;
125: }
126: goto LAB_0013da7c;
127: }
128: pcVar14 = pcVar14 + 0x60;
129: ppcVar12[lVar15 + 0xc] = FUN_0013ca10;
130: lVar15 = lVar15 + 1;
131: if (*(int *)(param_1 + 7) == iVar8 || *(int *)(param_1 + 7) < iVar8) {
132: return;
133: }
134: }
135: ppcVar12[lVar15 + 0xc] = FUN_0013ca20;
136: LAB_0013da7c:
137: pcVar14 = pcVar14 + 0x60;
138: lVar15 = lVar15 + 1;
139: } while (*(int *)(param_1 + 7) != iVar8 && iVar8 <= *(int *)(param_1 + 7));
140: }
141: return;
142: }
143: 
