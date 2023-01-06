1: 
2: undefined8 FUN_0014c2f0(long param_1,long param_2)
3: 
4: {
5: long lVar1;
6: long lVar2;
7: short sVar3;
8: long lVar4;
9: short *psVar5;
10: uint uVar6;
11: long lVar7;
12: long lVar8;
13: long lVar9;
14: long lVar10;
15: int iVar11;
16: uint uVar12;
17: int iVar13;
18: int iStack120;
19: long lStack96;
20: 
21: lVar4 = *(long *)(param_1 + 0x1f0);
22: if (*(int *)(param_1 + 0x118) != 0) {
23: iVar11 = *(int *)(lVar4 + 0x60);
24: if (iVar11 == 0) {
25: FUN_0014b810(param_1,*(undefined4 *)(lVar4 + 100));
26: iVar11 = *(int *)(param_1 + 0x118);
27: *(uint *)(lVar4 + 100) = *(int *)(lVar4 + 100) + 1U & 7;
28: }
29: *(int *)(lVar4 + 0x60) = iVar11 + -1;
30: }
31: if (*(int *)(param_1 + 0x170) < 1) {
32: return 1;
33: }
34: lStack96 = 1;
35: LAB_0014c358:
36: psVar5 = *(short **)(param_2 + -8 + lStack96 * 8);
37: lVar7 = (long)*(int *)(param_1 + 0x170 + lStack96 * 4);
38: lVar10 = *(long *)(param_1 + 0x148 + lVar7 * 8);
39: lVar9 = lVar4 + lVar7 * 4;
40: lVar8 = (long)*(int *)(lVar10 + 0x14);
41: lVar2 = lVar4 + lVar8 * 8;
42: lVar7 = (long)*(int *)(lVar9 + 0x50) + *(long *)(lVar2 + 0x68);
43: iVar11 = (int)*psVar5 - *(int *)(lVar9 + 0x40);
44: if (iVar11 == 0) {
45: FUN_0014a8b0(param_1,lVar7);
46: *(undefined4 *)(lVar9 + 0x50) = 0;
47: }
48: else {
49: *(int *)(lVar9 + 0x40) = (int)*psVar5;
50: FUN_0014ac60(param_1,lVar7);
51: if (iVar11 < 1) {
52: iVar11 = -iVar11;
53: FUN_0014ac60(param_1,lVar7 + 1);
54: lVar7 = lVar7 + 3;
55: *(undefined4 *)(lVar9 + 0x50) = 8;
56: }
57: else {
58: FUN_0014a8b0(param_1);
59: lVar7 = lVar7 + 2;
60: *(undefined4 *)(lVar9 + 0x50) = 4;
61: }
62: uVar6 = 0;
63: uVar12 = iVar11 - 1;
64: iStack120 = 0;
65: if (uVar12 != 0) {
66: FUN_0014ac60(param_1,lVar7);
67: lVar7 = *(long *)(lVar2 + 0x68) + 0x14;
68: uVar6 = (int)uVar12 >> 1;
69: if (uVar6 == 0) {
70: iStack120 = 1;
71: }
72: else {
73: iStack120 = 1;
74: do {
75: iStack120 = iStack120 * 2;
76: FUN_0014ac60(param_1,lVar7);
77: lVar7 = lVar7 + 1;
78: uVar6 = (int)uVar6 >> 1;
79: } while (uVar6 != 0);
80: uVar6 = iStack120 >> 1;
81: }
82: }
83: FUN_0014a8b0(param_1,lVar7);
84: if (iStack120 < (int)((1 << (*(byte *)(param_1 + 0xc0 + lVar8) & 0x3f)) >> 1)) {
85: *(undefined4 *)(lVar9 + 0x50) = 0;
86: }
87: else {
88: if ((int)((1 << (*(byte *)(param_1 + 0xd0 + lVar8) & 0x3f)) >> 1) < iStack120) {
89: *(int *)(lVar9 + 0x50) = *(int *)(lVar9 + 0x50) + 8;
90: }
91: }
92: while (uVar6 != 0) {
93: FUN_0014b010(param_1,lVar7 + 0xe,(uVar12 & uVar6) != 0);
94: uVar6 = (int)uVar6 >> 1;
95: }
96: }
97: lVar9 = (long)*(int *)(lVar10 + 0x18);
98: lVar7 = 0x3f;
99: do {
100: if (psVar5[*(int *)(&DAT_0018f100 + lVar7 * 4)] != 0) {
101: lVar2 = lVar4 + lVar9 * 8;
102: iVar11 = 1;
103: goto LAB_0014c410;
104: }
105: lVar7 = lVar7 + -1;
106: } while (lVar7 != 0);
107: goto LAB_0014c708;
108: LAB_0014c410:
109: do {
110: iVar13 = iVar11;
111: lVar10 = (long)(iVar13 * 3 + -3) + *(long *)(lVar2 + 0xe8);
112: FUN_0014a8b0(param_1,lVar10);
113: sVar3 = psVar5[*(int *)(&DAT_0018f100 + (long)iVar13 * 4)];
114: if (sVar3 == 0) {
115: lVar8 = (long)(iVar13 + 1);
116: do {
117: lVar1 = lVar10 + 1;
118: lVar10 = lVar10 + 3;
119: iVar13 = (int)lVar8;
120: FUN_0014a8b0(param_1,lVar1);
121: lVar1 = lVar8 * 4;
122: lVar8 = lVar8 + 1;
123: sVar3 = psVar5[*(int *)(&DAT_0018f100 + lVar1)];
124: } while (sVar3 == 0);
125: }
126: iVar11 = (int)sVar3;
127: FUN_0014ac60(param_1,lVar10 + 1);
128: if (iVar11 < 1) {
129: FUN_0014ac60(param_1,lVar4 + 0x168);
130: uVar6 = 0xffffffff - iVar11;
131: if (uVar6 != 0) goto LAB_0014c522;
132: LAB_0014c4a8:
133: FUN_0014a8b0(param_1,lVar10 + 2);
134: }
135: else {
136: FUN_0014a8b0(param_1,lVar4 + 0x168);
137: uVar6 = iVar11 - 1;
138: if (uVar6 == 0) goto LAB_0014c4a8;
139: LAB_0014c522:
140: FUN_0014ac60(param_1,lVar10 + 2);
141: if (uVar6 >> 1 == 0) goto LAB_0014c4a8;
142: FUN_0014ac60(param_1,lVar10 + 2);
143: lVar10 = 0xd9;
144: if (iVar13 <= (int)(uint)*(byte *)(param_1 + 0xe0 + lVar9)) {
145: lVar10 = 0xbd;
146: }
147: lVar10 = lVar10 + *(long *)(lVar2 + 0xe8);
148: iVar11 = (int)uVar6 >> 2;
149: if (iVar11 == 0) {
150: FUN_0014a8b0(param_1,lVar10);
151: FUN_0014b010(param_1,lVar10 + 0xe,uVar6 & 1);
152: }
153: else {
154: uVar12 = 2;
155: do {
156: lVar8 = lVar10;
157: uVar12 = uVar12 * 2;
158: FUN_0014ac60(param_1,lVar8);
159: iVar11 = iVar11 >> 1;
160: lVar10 = lVar8 + 1;
161: } while (iVar11 != 0);
162: FUN_0014a8b0(param_1);
163: while (uVar12 = (int)uVar12 >> 1, uVar12 != 0) {
164: FUN_0014b010(param_1,lVar8 + 0xf,(uVar6 & uVar12) != 0);
165: }
166: }
167: }
168: iVar11 = iVar13 + 1;
169: } while (iVar11 <= (int)lVar7);
170: if (iVar11 < 0x40) {
171: lVar7 = (long)(iVar13 * 3);
172: LAB_0014c708:
173: FUN_0014ac60(param_1,lVar7 + *(long *)(lVar4 + 0xe8 + lVar9 * 8));
174: }
175: iVar11 = (int)lStack96;
176: lStack96 = lStack96 + 1;
177: if (*(int *)(param_1 + 0x170) == iVar11 || *(int *)(param_1 + 0x170) < iVar11) {
178: return 1;
179: }
180: goto LAB_0014c358;
181: }
182: 
