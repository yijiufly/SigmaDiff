1: 
2: void FUN_001337d0(long param_1,undefined8 param_2,uint *param_3,uint param_4)
3: 
4: {
5: undefined8 uVar1;
6: int iVar2;
7: long lVar3;
8: long lVar4;
9: long lVar5;
10: int iVar6;
11: long lVar7;
12: uint uVar8;
13: undefined8 *puVar9;
14: uint uVar10;
15: uint uVar11;
16: undefined8 *puVar12;
17: int iVar13;
18: long lVar14;
19: long lVar15;
20: long lVar16;
21: undefined8 *puVar17;
22: long lVar18;
23: uint uVar19;
24: int iVar20;
25: long lVar21;
26: bool bVar22;
27: 
28: lVar3 = *(long *)(param_1 + 0x228);
29: if (*(int *)(lVar3 + 0x60) == 0) {
30: iVar6 = (**(code **)(*(long *)(param_1 + 0x230) + 0x18))(param_1);
31: if (iVar6 == 0) {
32: return;
33: }
34: *(int *)(lVar3 + 0x84) = *(int *)(lVar3 + 0x84) + 1;
35: *(undefined4 *)(lVar3 + 0x60) = 1;
36: }
37: iVar6 = *(int *)(lVar3 + 0x7c);
38: if (iVar6 == 1) {
39: iVar6 = *(int *)(lVar3 + 0x80);
40: }
41: else {
42: if (iVar6 == 2) {
43: (**(code **)(*(long *)(param_1 + 0x238) + 8))
44: (param_1,*(undefined8 *)(lVar3 + 0x68 + (long)*(int *)(lVar3 + 0x78) * 8),
45: lVar3 + 100,*(undefined4 *)(lVar3 + 0x80),param_2,param_3,param_4);
46: if (*(uint *)(lVar3 + 100) < *(uint *)(lVar3 + 0x80)) {
47: return;
48: }
49: *(undefined4 *)(lVar3 + 0x7c) = 0;
50: if (param_4 <= *param_3) {
51: return;
52: }
53: }
54: else {
55: if (iVar6 != 0) {
56: return;
57: }
58: }
59: iVar2 = *(int *)(param_1 + 0x1a0);
60: *(undefined4 *)(lVar3 + 100) = 0;
61: iVar6 = iVar2 + -1;
62: iVar20 = *(int *)(param_1 + 0x1a4);
63: *(int *)(lVar3 + 0x80) = iVar6;
64: if (*(int *)(lVar3 + 0x84) == iVar20) {
65: lVar16 = *(long *)(param_1 + 0x228);
66: lVar15 = *(long *)(param_1 + 0x130);
67: if (0 < *(int *)(param_1 + 0x38)) {
68: lVar18 = 0;
69: lVar4 = *(long *)(lVar16 + 0x68 + (long)*(int *)(lVar16 + 0x78) * 8);
70: lVar7 = ((ulong)(*(int *)(param_1 + 0x38) - 1) * 3 + 3) * 0x20 + lVar15;
71: do {
72: uVar8 = *(int *)(lVar15 + 0xc) * *(int *)(lVar15 + 0x24);
73: iVar6 = (int)uVar8 / iVar2;
74: uVar10 = *(uint *)(lVar15 + 0x2c) % uVar8;
75: if (uVar10 != 0) {
76: uVar8 = uVar10;
77: }
78: if (lVar18 == 0) {
79: *(int *)(lVar16 + 0x80) = (int)(uVar8 - 1) / iVar6 + 1;
80: }
81: iVar6 = iVar6 * 2;
82: lVar5 = *(long *)(lVar4 + lVar18 * 8);
83: if (0 < iVar6) {
84: lVar14 = (long)(int)uVar8;
85: puVar9 = (undefined8 *)(lVar5 + -8 + lVar14 * 8);
86: puVar12 = (undefined8 *)(lVar14 * 8 + lVar5);
87: if (iVar6 < 0x19) {
88: do {
89: puVar17 = puVar12 + 1;
90: *puVar12 = *puVar9;
91: puVar12 = puVar17;
92: } while (puVar17 != (undefined8 *)(lVar5 + 8 + (lVar14 + (ulong)(iVar6 - 1)) * 8));
93: }
94: else {
95: uVar10 = (uint)((ulong)puVar12 >> 3) & 1;
96: bVar22 = ((ulong)puVar12 >> 3 & 1) != 0;
97: if (bVar22) {
98: *puVar12 = *puVar9;
99: }
100: uVar1 = *puVar9;
101: uVar19 = iVar6 - uVar10;
102: uVar11 = 0;
103: puVar12 = (undefined8 *)(lVar5 + ((ulong)uVar10 + lVar14) * 8);
104: do {
105: uVar11 = uVar11 + 1;
106: *puVar12 = uVar1;
107: puVar12[1] = uVar1;
108: puVar12 = puVar12 + 2;
109: } while (uVar11 < uVar19 >> 1);
110: iVar20 = (uint)bVar22 + (uVar19 & 0xfffffffe);
111: if ((uVar19 & 0xfffffffe) != uVar19) {
112: iVar13 = iVar20 + 1;
113: *(undefined8 *)(lVar5 + (long)(int)(uVar8 + iVar20) * 8) = *puVar9;
114: if (iVar13 < iVar6) {
115: *(undefined8 *)(lVar5 + (long)(int)(iVar13 + uVar8) * 8) = *puVar9;
116: }
117: }
118: }
119: }
120: lVar15 = lVar15 + 0x60;
121: lVar18 = lVar18 + 1;
122: } while (lVar15 != lVar7);
123: iVar6 = *(int *)(lVar3 + 0x80);
124: }
125: }
126: *(undefined4 *)(lVar3 + 0x7c) = 1;
127: }
128: (**(code **)(*(long *)(param_1 + 0x238) + 8))
129: (param_1,*(undefined8 *)(lVar3 + 0x68 + (long)*(int *)(lVar3 + 0x78) * 8),lVar3 + 100,
130: iVar6,param_2,param_3,param_4);
131: if (*(uint *)(lVar3 + 100) < *(uint *)(lVar3 + 0x80)) {
132: return;
133: }
134: iVar6 = *(int *)(param_1 + 0x1a0);
135: if (*(int *)(lVar3 + 0x84) == 1) {
136: lVar16 = *(long *)(param_1 + 0x130);
137: if (0 < *(int *)(param_1 + 0x38)) {
138: lVar15 = *(long *)(*(long *)(param_1 + 0x228) + 0x68);
139: lVar4 = *(long *)(*(long *)(param_1 + 0x228) + 0x70);
140: lVar18 = 0;
141: lVar7 = ((ulong)(*(int *)(param_1 + 0x38) - 1) * 3 + 3) * 0x20 + lVar16;
142: do {
143: lVar5 = *(long *)(lVar15 + lVar18);
144: iVar2 = (*(int *)(lVar16 + 0xc) * *(int *)(lVar16 + 0x24)) / iVar6;
145: if (0 < iVar2) {
146: iVar20 = iVar2 * (iVar6 + 1);
147: lVar21 = (long)iVar20;
148: puVar9 = (undefined8 *)(lVar5 + lVar21 * 8);
149: puVar12 = (undefined8 *)(*(long *)(lVar4 + lVar18) + lVar21 * 8);
150: lVar14 = (iVar2 + iVar20) - lVar21;
151: do {
152: puVar9[-iVar2 - lVar21] = *puVar9;
153: puVar12[-iVar2 - lVar21] = *puVar12;
154: puVar9[lVar14] = puVar9[-lVar21];
155: puVar9 = puVar9 + 1;
156: puVar12[lVar14] = puVar12[-lVar21];
157: puVar12 = puVar12 + 1;
158: } while ((undefined8 *)(lVar5 + 8 + ((ulong)(iVar2 - 1) + lVar21) * 8) != puVar9);
159: }
160: lVar16 = lVar16 + 0x60;
161: lVar18 = lVar18 + 8;
162: } while (lVar7 != lVar16);
163: }
164: }
165: *(uint *)(lVar3 + 0x78) = *(uint *)(lVar3 + 0x78) ^ 1;
166: *(undefined4 *)(lVar3 + 0x60) = 0;
167: *(int *)(lVar3 + 100) = iVar6 + 1;
168: *(int *)(lVar3 + 0x80) = iVar6 + 2;
169: *(undefined4 *)(lVar3 + 0x7c) = 2;
170: return;
171: }
172: 
