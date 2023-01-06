1: 
2: /* WARNING: Could not reconcile some variable overlaps */
3: 
4: undefined8 FUN_0013f200(long param_1,long param_2)
5: 
6: {
7: short sVar1;
8: long lVar2;
9: short *psVar3;
10: int iVar4;
11: long lVar5;
12: int *piVar6;
13: long lVar7;
14: int iVar8;
15: int iVar9;
16: int iVar10;
17: int iVar11;
18: uint uVar12;
19: long lVar13;
20: uint uVar14;
21: long lVar15;
22: long lVar16;
23: long lVar17;
24: long lStack104;
25: long lStack88;
26: 
27: lVar2 = *(long *)(param_1 + 0x1f0);
28: if (*(int *)(param_1 + 0x118) != 0) {
29: iVar9 = *(int *)(lVar2 + 0x60);
30: if (iVar9 == 0) {
31: FUN_0013ef30(param_1,*(undefined4 *)(lVar2 + 100));
32: iVar9 = *(int *)(param_1 + 0x118);
33: *(uint *)(lVar2 + 100) = *(int *)(lVar2 + 100) + 1U & 7;
34: }
35: *(int *)(lVar2 + 0x60) = iVar9 + -1;
36: }
37: if (*(int *)(param_1 + 0x170) < 1) {
38: return 1;
39: }
40: lStack104 = 0;
41: LAB_0013f26a:
42: psVar3 = *(short **)(param_2 + lStack104 * 8);
43: lVar5 = (long)*(int *)(param_1 + 0x174 + lStack104 * 4);
44: lVar16 = *(long *)(param_1 + 0x148 + lVar5 * 8);
45: lVar5 = lVar2 + lVar5 * 4;
46: lVar7 = (long)*(int *)(lVar16 + 0x14);
47: lVar13 = lVar2 + lVar7 * 8;
48: lVar15 = (long)*(int *)(lVar5 + 0x50) + *(long *)(lVar13 + 0x68);
49: iVar9 = (int)*psVar3 - *(int *)(lVar5 + 0x40);
50: if (iVar9 == 0) {
51: FUN_0013e1a0(param_1,lVar15);
52: *(undefined4 *)(lVar5 + 0x50) = 0;
53: }
54: else {
55: *(int *)(lVar5 + 0x40) = (int)*psVar3;
56: FUN_0013dd70(param_1,lVar15);
57: if (iVar9 < 1) {
58: iVar9 = -iVar9;
59: lVar17 = lVar15 + 3;
60: FUN_0013dd70(param_1,lVar15 + 1);
61: *(undefined4 *)(lVar5 + 0x50) = 8;
62: }
63: else {
64: lVar17 = lVar15 + 2;
65: FUN_0013e1a0(param_1,lVar15 + 1);
66: *(undefined4 *)(lVar5 + 0x50) = 4;
67: }
68: uVar12 = 0;
69: uVar14 = iVar9 - 1;
70: lStack88._0_4_ = 0;
71: if (uVar14 != 0) {
72: FUN_0013dd70(param_1,lVar17);
73: iVar9 = (int)uVar14 >> 1;
74: lVar17 = *(long *)(lVar13 + 0x68) + 0x14;
75: if (iVar9 == 0) {
76: lStack88._0_4_ = 0;
77: uVar12 = (uint)lStack88;
78: lStack88._0_4_ = 1;
79: }
80: else {
81: lStack88._0_4_ = 1;
82: do {
83: lStack88._0_4_ = (uint)lStack88 * 2;
84: FUN_0013dd70(param_1,lVar17);
85: lVar17 = lVar17 + 1;
86: iVar9 = iVar9 >> 1;
87: } while (iVar9 != 0);
88: uVar12 = (int)(uint)lStack88 >> 1;
89: }
90: }
91: FUN_0013e1a0(param_1,lVar17);
92: if ((int)(uint)lStack88 < (int)((1 << (*(byte *)(param_1 + 0xc0 + lVar7) & 0x3f)) >> 1)) {
93: *(undefined4 *)(lVar5 + 0x50) = 0;
94: }
95: else {
96: if ((int)((1 << (*(byte *)(param_1 + 0xd0 + lVar7) & 0x3f)) >> 1) < (int)(uint)lStack88) {
97: *(int *)(lVar5 + 0x50) = *(int *)(lVar5 + 0x50) + 8;
98: }
99: }
100: while (uVar12 != 0) {
101: FUN_0013e5d0(param_1,lVar17 + 0xe,(uVar12 & uVar14) != 0);
102: uVar12 = (int)uVar12 >> 1;
103: }
104: }
105: iVar8 = 0x3f;
106: iVar9 = *(int *)(lVar16 + 0x18);
107: piVar6 = (int *)&UNK_0018b55c;
108: do {
109: if (psVar3[*piVar6] != 0) {
110: iVar10 = 1;
111: lVar5 = lVar2 + (long)iVar9 * 8;
112: goto LAB_0013f330;
113: }
114: piVar6 = piVar6 + -1;
115: iVar8 = iVar8 + -1;
116: } while (iVar8 != 0);
117: lVar5 = 0;
118: goto LAB_0013f5a7;
119: LAB_0013f330:
120: do {
121: lVar13 = (long)(iVar10 * 3 + -3) + *(long *)(lVar5 + 0xe8);
122: FUN_0013e1a0(param_1,lVar13);
123: while( true ) {
124: lVar16 = lVar13 + 1;
125: sVar1 = psVar3[*(int *)(&DAT_0018b460 + (long)iVar10 * 4)];
126: iVar11 = (int)sVar1;
127: if (sVar1 != 0) break;
128: lVar13 = lVar13 + 3;
129: iVar10 = iVar10 + 1;
130: FUN_0013e1a0(param_1,lVar16);
131: }
132: FUN_0013dd70();
133: if (sVar1 < 1) {
134: iVar11 = -iVar11;
135: FUN_0013dd70(param_1,lVar2 + 0x168);
136: }
137: else {
138: FUN_0013e1a0(param_1,lVar2 + 0x168);
139: }
140: lVar13 = lVar13 + 2;
141: uVar12 = iVar11 - 1;
142: if ((uVar12 == 0) || (FUN_0013dd70(param_1,lVar13), uVar12 >> 1 == 0)) {
143: FUN_0013e1a0(param_1,lVar13);
144: }
145: else {
146: lVar16 = 0xbd;
147: FUN_0013dd70(param_1,lVar13);
148: if ((int)(uint)*(byte *)(param_1 + 0xe0 + (long)iVar9) < iVar10) {
149: lVar16 = 0xd9;
150: }
151: iVar11 = (int)uVar12 >> 2;
152: lVar16 = lVar16 + *(long *)(lVar5 + 0xe8);
153: if (iVar11 == 0) {
154: lVar13 = lVar16 + 0xe;
155: FUN_0013e1a0(param_1,lVar16);
156: uVar14 = 1;
157: }
158: else {
159: iVar4 = 2;
160: do {
161: lVar7 = lVar16;
162: iVar4 = iVar4 * 2;
163: FUN_0013dd70(param_1,lVar7);
164: iVar11 = iVar11 >> 1;
165: lVar16 = lVar7 + 1;
166: } while (iVar11 != 0);
167: lVar13 = lVar7 + 0xf;
168: FUN_0013e1a0(param_1,lVar7 + 1);
169: uVar14 = iVar4 >> 1;
170: if (uVar14 == 0) goto LAB_0013f3b4;
171: }
172: do {
173: FUN_0013e5d0(param_1,lVar13,(uVar14 & uVar12) != 0);
174: uVar14 = (int)uVar14 >> 1;
175: } while (uVar14 != 0);
176: }
177: LAB_0013f3b4:
178: iVar10 = iVar10 + 1;
179: } while (iVar10 <= iVar8);
180: if (iVar10 < 0x40) {
181: lVar5 = (long)(iVar10 * 3 + -3);
182: LAB_0013f5a7:
183: lStack88 = (long)iVar9;
184: FUN_0013dd70(param_1,lVar5 + *(long *)(lVar2 + 0xe8 + lStack88 * 8));
185: }
186: lStack104 = lStack104 + 1;
187: if (*(int *)(param_1 + 0x170) == (int)lStack104 + 1 ||
188: *(int *)(param_1 + 0x170) < (int)lStack104 + 1) {
189: return 1;
190: }
191: goto LAB_0013f26a;
192: }
193: 
