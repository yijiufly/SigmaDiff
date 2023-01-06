1: 
2: void FUN_00128cd0(long param_1,undefined8 param_2,uint *param_3,uint param_4)
3: 
4: {
5: undefined8 *puVar1;
6: int iVar2;
7: long lVar3;
8: long lVar4;
9: int iVar5;
10: int iVar6;
11: undefined8 *puVar7;
12: uint uVar8;
13: long lVar9;
14: int iVar10;
15: undefined8 *puVar11;
16: int iVar12;
17: long lVar13;
18: long lVar14;
19: long lVar15;
20: uint uVar16;
21: 
22: lVar3 = *(long *)(param_1 + 0x228);
23: if (*(int *)(lVar3 + 0x60) == 0) {
24: iVar5 = (**(code **)(*(long *)(param_1 + 0x230) + 0x18))
25: (param_1,*(undefined8 *)(lVar3 + 0x68 + (long)*(int *)(lVar3 + 0x78) * 8));
26: if (iVar5 == 0) {
27: return;
28: }
29: iVar5 = *(int *)(lVar3 + 0x7c);
30: *(int *)(lVar3 + 0x84) = *(int *)(lVar3 + 0x84) + 1;
31: *(undefined4 *)(lVar3 + 0x60) = 1;
32: }
33: else {
34: iVar5 = *(int *)(lVar3 + 0x7c);
35: }
36: if (iVar5 == 1) {
37: iVar5 = *(int *)(lVar3 + 0x80);
38: }
39: else {
40: if (iVar5 == 2) {
41: (**(code **)(*(long *)(param_1 + 0x238) + 8))
42: (param_1,*(undefined8 *)(lVar3 + 0x68 + (long)*(int *)(lVar3 + 0x78) * 8),
43: lVar3 + 100);
44: if (*(uint *)(lVar3 + 100) < *(uint *)(lVar3 + 0x80)) {
45: return;
46: }
47: *(undefined4 *)(lVar3 + 0x7c) = 0;
48: if (param_4 < *param_3 || param_4 == *param_3) {
49: return;
50: }
51: }
52: else {
53: if (iVar5 != 0) {
54: return;
55: }
56: }
57: iVar10 = *(int *)(param_1 + 0x1a0);
58: iVar2 = *(int *)(param_1 + 0x1a4);
59: *(undefined4 *)(lVar3 + 100) = 0;
60: iVar5 = iVar10 + -1;
61: *(int *)(lVar3 + 0x80) = iVar5;
62: if (*(int *)(lVar3 + 0x84) == iVar2) {
63: iVar2 = *(int *)(param_1 + 0x38);
64: lVar4 = *(long *)(param_1 + 0x228);
65: lVar13 = *(long *)(param_1 + 0x130);
66: if (0 < iVar2) {
67: iVar5 = *(int *)(lVar4 + 0x78);
68: lVar14 = 0;
69: iVar6 = 0;
70: do {
71: uVar16 = *(int *)(lVar13 + 0xc) * *(int *)(lVar13 + 0x24);
72: iVar12 = (int)uVar16 / iVar10;
73: uVar8 = *(uint *)(lVar13 + 0x2c) % uVar16;
74: if (uVar8 != 0) {
75: uVar16 = uVar8;
76: }
77: if (iVar6 == 0) {
78: *(int *)(lVar4 + 0x80) = (int)(uVar16 - 1) / iVar12 + 1;
79: }
80: iVar12 = iVar12 * 2;
81: lVar15 = *(long *)(*(long *)(lVar4 + 0x68 + (long)iVar5 * 8) + lVar14);
82: if (0 < iVar12) {
83: lVar9 = 0;
84: do {
85: *(undefined8 *)(lVar15 + (long)(int)uVar16 * 8 + lVar9 * 8) =
86: *(undefined8 *)(lVar15 + -8 + (long)(int)uVar16 * 8);
87: lVar9 = lVar9 + 1;
88: } while ((int)lVar9 < iVar12);
89: }
90: iVar6 = iVar6 + 1;
91: lVar13 = lVar13 + 0x60;
92: lVar14 = lVar14 + 8;
93: } while (iVar6 != iVar2);
94: iVar5 = *(int *)(lVar3 + 0x80);
95: }
96: }
97: *(undefined4 *)(lVar3 + 0x7c) = 1;
98: }
99: (**(code **)(*(long *)(param_1 + 0x238) + 8))
100: (param_1,*(undefined8 *)(lVar3 + 0x68 + (long)*(int *)(lVar3 + 0x78) * 8),lVar3 + 100,
101: iVar5,param_2,param_3,param_4);
102: if (*(uint *)(lVar3 + 0x80) <= *(uint *)(lVar3 + 100)) {
103: if (*(int *)(lVar3 + 0x84) == 1) {
104: iVar2 = *(int *)(param_1 + 0x1a0);
105: lVar4 = *(long *)(param_1 + 0x228);
106: lVar13 = *(long *)(param_1 + 0x130);
107: iVar5 = iVar2 + 1;
108: iVar10 = iVar2 + 2;
109: if (0 < *(int *)(param_1 + 0x38)) {
110: lVar14 = 0;
111: lVar15 = ((ulong)(*(int *)(param_1 + 0x38) - 1) * 3 + 3) * 0x20 + lVar13;
112: do {
113: iVar6 = (*(int *)(lVar13 + 0xc) * *(int *)(lVar13 + 0x24)) / iVar2;
114: puVar7 = *(undefined8 **)(*(long *)(lVar4 + 0x68) + lVar14);
115: puVar11 = *(undefined8 **)(*(long *)(lVar4 + 0x70) + lVar14);
116: if (0 < iVar6) {
117: iVar12 = iVar6 * iVar5;
118: puVar1 = puVar7 + (ulong)(iVar6 - 1) + 1;
119: do {
120: puVar7[-iVar6] = puVar7[iVar12];
121: puVar11[-iVar6] = puVar11[iVar12];
122: puVar7[iVar12 + iVar6] = *puVar7;
123: puVar7 = puVar7 + 1;
124: puVar11[iVar12 + iVar6] = *puVar11;
125: puVar11 = puVar11 + 1;
126: } while (puVar7 != puVar1);
127: }
128: lVar13 = lVar13 + 0x60;
129: lVar14 = lVar14 + 8;
130: } while (lVar13 != lVar15);
131: }
132: }
133: else {
134: iVar5 = *(int *)(param_1 + 0x1a0) + 1;
135: iVar10 = *(int *)(param_1 + 0x1a0) + 2;
136: }
137: *(uint *)(lVar3 + 0x78) = *(uint *)(lVar3 + 0x78) ^ 1;
138: *(undefined4 *)(lVar3 + 0x60) = 0;
139: *(int *)(lVar3 + 100) = iVar5;
140: *(int *)(lVar3 + 0x80) = iVar10;
141: *(undefined4 *)(lVar3 + 0x7c) = 2;
142: return;
143: }
144: return;
145: }
146: 
