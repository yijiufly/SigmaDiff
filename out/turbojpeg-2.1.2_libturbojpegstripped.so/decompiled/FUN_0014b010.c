1: 
2: void FUN_0014b010(code **param_1,byte *param_2,int param_3)
3: 
4: {
5: char **ppcVar1;
6: long *plVar2;
7: byte bVar3;
8: code *pcVar4;
9: char **ppcVar5;
10: char *pcVar6;
11: long lVar7;
12: long *plVar8;
13: undefined8 *puVar9;
14: undefined *puVar10;
15: code **ppcVar11;
16: int iVar12;
17: long lVar13;
18: long lVar14;
19: ulong uVar15;
20: int iVar16;
21: long lVar17;
22: 
23: bVar3 = *param_2;
24: pcVar4 = param_1[0x3e];
25: lVar14 = *(long *)(&DAT_0018f280 + (ulong)(bVar3 & 0x7f) * 8);
26: lVar17 = lVar14 >> 0x10;
27: lVar13 = *(long *)(pcVar4 + 0x20) - lVar17;
28: *(long *)(pcVar4 + 0x20) = lVar13;
29: if ((int)(uint)bVar3 >> 7 == param_3) {
30: if (0x7fff < lVar13) {
31: return;
32: }
33: if (lVar13 < lVar17) {
34: *(long *)(pcVar4 + 0x18) = *(long *)(pcVar4 + 0x18) + lVar13;
35: *(long *)(pcVar4 + 0x20) = lVar17;
36: }
37: *param_2 = bVar3 & 0x80 ^ (byte)((ulong)lVar14 >> 8);
38: }
39: else {
40: if (lVar17 <= lVar13) {
41: *(long *)(pcVar4 + 0x18) = *(long *)(pcVar4 + 0x18) + lVar13;
42: *(long *)(pcVar4 + 0x20) = lVar17;
43: }
44: *param_2 = bVar3 & 0x80 ^ (byte)lVar14;
45: }
46: lVar14 = *(long *)(pcVar4 + 0x20);
47: uVar15 = *(ulong *)(pcVar4 + 0x18);
48: iVar12 = *(int *)(pcVar4 + 0x38);
49: do {
50: iVar12 = iVar12 + -1;
51: lVar14 = lVar14 * 2;
52: uVar15 = uVar15 * 2;
53: *(long *)(pcVar4 + 0x20) = lVar14;
54: *(ulong *)(pcVar4 + 0x18) = uVar15;
55: *(int *)(pcVar4 + 0x38) = iVar12;
56: if (iVar12 == 0) {
57: lVar13 = (long)uVar15 >> 0x13;
58: if (lVar13 < 0x100) {
59: if (lVar13 == 0xff) {
60: *(long *)(pcVar4 + 0x28) = *(long *)(pcVar4 + 0x28) + 1;
61: }
62: else {
63: iVar12 = *(int *)(pcVar4 + 0x3c);
64: if (iVar12 == 0) {
65: *(long *)(pcVar4 + 0x30) = *(long *)(pcVar4 + 0x30) + 1;
66: LAB_0014b15f:
67: lVar14 = *(long *)(pcVar4 + 0x28);
68: }
69: else {
70: if (iVar12 < 0) goto LAB_0014b15f;
71: if (*(long *)(pcVar4 + 0x30) != 0) {
72: do {
73: puVar9 = (undefined8 *)param_1[5];
74: puVar10 = (undefined *)*puVar9;
75: *puVar9 = puVar10 + 1;
76: *puVar10 = 0;
77: plVar2 = puVar9 + 1;
78: *plVar2 = *plVar2 + -1;
79: if ((*plVar2 == 0) && (iVar12 = (*(code *)puVar9[3])(), iVar12 == 0)) {
80: ppcVar11 = (code **)*param_1;
81: *(undefined4 *)(ppcVar11 + 5) = 0x18;
82: (**ppcVar11)();
83: }
84: plVar2 = (long *)(pcVar4 + 0x30);
85: *plVar2 = *plVar2 + -1;
86: } while (*plVar2 != 0);
87: iVar12 = *(int *)(pcVar4 + 0x3c);
88: }
89: plVar8 = (long *)param_1[5];
90: puVar10 = (undefined *)*plVar8;
91: *plVar8 = (long)(puVar10 + 1);
92: *puVar10 = (char)iVar12;
93: plVar2 = plVar8 + 1;
94: *plVar2 = *plVar2 + -1;
95: if ((*plVar2 != 0) || (iVar12 = (*(code *)plVar8[3])(), iVar12 != 0)) goto LAB_0014b15f;
96: ppcVar11 = (code **)*param_1;
97: *(undefined4 *)(ppcVar11 + 5) = 0x18;
98: (**ppcVar11)();
99: lVar14 = *(long *)(pcVar4 + 0x28);
100: }
101: if (lVar14 != 0) {
102: lVar14 = *(long *)(pcVar4 + 0x30);
103: while (lVar14 != 0) {
104: puVar9 = (undefined8 *)param_1[5];
105: puVar10 = (undefined *)*puVar9;
106: *puVar9 = puVar10 + 1;
107: *puVar10 = 0;
108: plVar2 = puVar9 + 1;
109: *plVar2 = *plVar2 + -1;
110: if ((*plVar2 == 0) && (iVar12 = (*(code *)puVar9[3])(), iVar12 == 0)) {
111: ppcVar11 = (code **)*param_1;
112: *(undefined4 *)(ppcVar11 + 5) = 0x18;
113: (**ppcVar11)();
114: }
115: plVar2 = (long *)(pcVar4 + 0x30);
116: *plVar2 = *plVar2 + -1;
117: lVar14 = *plVar2;
118: }
119: do {
120: puVar9 = (undefined8 *)param_1[5];
121: puVar10 = (undefined *)*puVar9;
122: *puVar9 = puVar10 + 1;
123: *puVar10 = 0xff;
124: plVar2 = puVar9 + 1;
125: *plVar2 = *plVar2 + -1;
126: if ((*plVar2 == 0) && (iVar12 = (*(code *)puVar9[3])(), iVar12 == 0)) {
127: ppcVar11 = (code **)*param_1;
128: *(undefined4 *)(ppcVar11 + 5) = 0x18;
129: (**ppcVar11)();
130: }
131: puVar9 = (undefined8 *)param_1[5];
132: puVar10 = (undefined *)*puVar9;
133: *puVar9 = puVar10 + 1;
134: *puVar10 = 0;
135: plVar2 = puVar9 + 1;
136: *plVar2 = *plVar2 + -1;
137: if ((*plVar2 == 0) && (iVar12 = (*(code *)puVar9[3])(), iVar12 == 0)) {
138: ppcVar11 = (code **)*param_1;
139: *(undefined4 *)(ppcVar11 + 5) = 0x18;
140: (**ppcVar11)();
141: }
142: plVar2 = (long *)(pcVar4 + 0x28);
143: *plVar2 = *plVar2 + -1;
144: } while (*plVar2 != 0);
145: }
146: uVar15 = *(ulong *)(pcVar4 + 0x18);
147: iVar12 = *(int *)(pcVar4 + 0x38);
148: *(uint *)(pcVar4 + 0x3c) = (uint)lVar13 & 0xff;
149: lVar14 = *(long *)(pcVar4 + 0x20);
150: }
151: }
152: else {
153: iVar16 = *(int *)(pcVar4 + 0x3c);
154: lVar17 = *(long *)(pcVar4 + 0x30);
155: if (-1 < iVar16) {
156: if (lVar17 != 0) {
157: do {
158: puVar9 = (undefined8 *)param_1[5];
159: puVar10 = (undefined *)*puVar9;
160: *puVar9 = puVar10 + 1;
161: *puVar10 = 0;
162: plVar2 = puVar9 + 1;
163: *plVar2 = *plVar2 + -1;
164: if ((*plVar2 == 0) && (iVar12 = (*(code *)puVar9[3])(), iVar12 == 0)) {
165: ppcVar11 = (code **)*param_1;
166: *(undefined4 *)(ppcVar11 + 5) = 0x18;
167: (**ppcVar11)();
168: }
169: plVar2 = (long *)(pcVar4 + 0x30);
170: *plVar2 = *plVar2 + -1;
171: } while (*plVar2 != 0);
172: iVar16 = *(int *)(pcVar4 + 0x3c);
173: }
174: ppcVar5 = (char **)param_1[5];
175: pcVar6 = *ppcVar5;
176: *ppcVar5 = pcVar6 + 1;
177: *pcVar6 = (char)iVar16 + '\x01';
178: ppcVar1 = ppcVar5 + 1;
179: *ppcVar1 = *ppcVar1 + -1;
180: if ((*ppcVar1 == (char *)0x0) && (iVar12 = (*(code *)ppcVar5[3])(), iVar12 == 0)) {
181: ppcVar11 = (code **)*param_1;
182: *(undefined4 *)(ppcVar11 + 5) = 0x18;
183: (**ppcVar11)();
184: }
185: if (*(int *)(pcVar4 + 0x3c) == 0xfe) {
186: puVar9 = (undefined8 *)param_1[5];
187: puVar10 = (undefined *)*puVar9;
188: *puVar9 = puVar10 + 1;
189: *puVar10 = 0;
190: plVar2 = puVar9 + 1;
191: *plVar2 = *plVar2 + -1;
192: if ((*plVar2 == 0) && (iVar12 = (*(code *)puVar9[3])(), iVar12 == 0)) {
193: ppcVar11 = (code **)*param_1;
194: *(undefined4 *)(ppcVar11 + 5) = 0x18;
195: (**ppcVar11)();
196: }
197: }
198: lVar17 = *(long *)(pcVar4 + 0x30);
199: uVar15 = *(ulong *)(pcVar4 + 0x18);
200: iVar12 = *(int *)(pcVar4 + 0x38);
201: lVar14 = *(long *)(pcVar4 + 0x20);
202: }
203: lVar7 = *(long *)(pcVar4 + 0x28);
204: *(undefined8 *)(pcVar4 + 0x28) = 0;
205: *(uint *)(pcVar4 + 0x3c) = (uint)lVar13 & 0xff;
206: *(long *)(pcVar4 + 0x30) = lVar17 + lVar7;
207: }
208: uVar15 = (ulong)((uint)uVar15 & 0x7ffff);
209: iVar12 = iVar12 + 8;
210: *(ulong *)(pcVar4 + 0x18) = uVar15;
211: *(int *)(pcVar4 + 0x38) = iVar12;
212: }
213: if (0x7fff < lVar14) {
214: return;
215: }
216: } while( true );
217: }
218: 