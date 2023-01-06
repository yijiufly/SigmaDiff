1: 
2: long FUN_0014b730(long param_1,code **param_2,long param_3,int *param_4)
3: 
4: {
5: char *pcVar1;
6: code *pcVar2;
7: undefined2 uVar3;
8: undefined4 uVar4;
9: undefined4 uVar5;
10: code **ppcVar6;
11: char *pcVar7;
12: undefined2 *puVar8;
13: char cVar9;
14: bool bVar10;
15: code *pcVar11;
16: undefined2 *puVar12;
17: uint uVar13;
18: uint uVar14;
19: code *pcVar15;
20: undefined2 *puVar16;
21: uint uVar17;
22: uint uVar18;
23: long lVar19;
24: int iVar20;
25: int iVar21;
26: uint uVar22;
27: uint uVar23;
28: uint uVar24;
29: uint uVar25;
30: 
31: if (param_4[3] == 0) {
32: if (param_4[0xe] == 1) {
33: pcVar2 = param_2[0xb];
34: *(undefined4 *)(pcVar2 + 8) = 1;
35: *(undefined4 *)(pcVar2 + 0xc) = 1;
36: }
37: }
38: else {
39: if (*(int *)(param_2 + 10) == 3) {
40: if (*(int *)((long)param_2 + 0x4c) == 3) goto LAB_0014baa2;
41: }
42: else {
43: if ((*(int *)(param_2 + 10) == 1) && (*(int *)((long)param_2 + 0x4c) == 1)) {
44: LAB_0014baa2:
45: if (*(long *)(*(long *)(param_1 + 0x130) + 8) == *(long *)(param_1 + 0x198)) {
46: uVar4 = *(undefined4 *)(param_2[0xb] + 0x10);
47: FUN_001169b0();
48: *(undefined4 *)(param_2[0xb] + 0x10) = uVar4;
49: goto LAB_0014b776;
50: }
51: }
52: }
53: ppcVar6 = (code **)*param_2;
54: *(undefined4 *)(ppcVar6 + 5) = 0x1b;
55: (**ppcVar6)();
56: }
57: LAB_0014b776:
58: if ((*param_4 - 3U < 5) && ((1 << ((byte)(*param_4 - 3U) & 0x3f) & 0x17U) != 0)) {
59: iVar20 = *(int *)((long)param_2 + 0x4c);
60: iVar21 = param_4[0x12];
61: *(int *)((long)param_2 + 0x34) = param_4[0x13];
62: *(int *)(param_2 + 6) = iVar21;
63: if (0 < iVar20) {
64: pcVar2 = param_2[0xb] + 0x60;
65: pcVar11 = param_2[0xb];
66: pcVar15 = pcVar2;
67: while( true ) {
68: uVar4 = *(undefined4 *)(pcVar11 + 8);
69: *(undefined4 *)(pcVar11 + 8) = *(undefined4 *)(pcVar11 + 0xc);
70: *(undefined4 *)(pcVar11 + 0xc) = uVar4;
71: if (pcVar15 == pcVar2 + (ulong)(iVar20 - 1) * 0x60) break;
72: pcVar11 = pcVar15;
73: pcVar15 = pcVar15 + 0x60;
74: }
75: }
76: lVar19 = 0;
77: do {
78: puVar8 = *(undefined2 **)((long)param_2 + lVar19 + 0x60);
79: if (puVar8 != (undefined2 *)0x0) {
80: iVar21 = 1;
81: iVar20 = 0;
82: puVar12 = puVar8;
83: puVar16 = puVar8;
84: do {
85: if (iVar20 != 0) {
86: uVar3 = *puVar16;
87: *puVar16 = *puVar12;
88: *puVar12 = uVar3;
89: if (iVar20 != 1) {
90: uVar3 = puVar16[1];
91: puVar16[1] = puVar12[8];
92: puVar12[8] = uVar3;
93: if (iVar20 != 2) {
94: uVar3 = puVar16[2];
95: puVar16[2] = puVar12[0x10];
96: puVar12[0x10] = uVar3;
97: if (iVar20 != 3) {
98: uVar3 = puVar16[3];
99: puVar16[3] = puVar12[0x18];
100: puVar12[0x18] = uVar3;
101: if (iVar20 != 4) {
102: uVar3 = puVar16[4];
103: puVar16[4] = puVar12[0x20];
104: puVar12[0x20] = uVar3;
105: if (iVar20 != 5) {
106: uVar3 = puVar16[5];
107: puVar16[5] = puVar12[0x28];
108: puVar12[0x28] = uVar3;
109: if (iVar20 == 7) {
110: uVar3 = puVar8[iVar20 * 8 + 6];
111: puVar8[iVar20 * 8 + 6] = puVar8[0x37];
112: puVar8[0x37] = uVar3;
113: break;
114: }
115: if (iVar21 == 8) break;
116: }
117: }
118: }
119: }
120: }
121: }
122: iVar20 = iVar20 + 1;
123: iVar21 = iVar21 + 1;
124: puVar16 = puVar16 + 8;
125: puVar12 = puVar12 + 1;
126: } while( true );
127: }
128: lVar19 = lVar19 + 8;
129: } while (lVar19 != 0x20);
130: }
131: else {
132: *(int *)(param_2 + 6) = param_4[0x12];
133: *(int *)((long)param_2 + 0x34) = param_4[0x13];
134: }
135: lVar19 = *(long *)(param_1 + 400);
136: if ((((((lVar19 != 0) && (*(char *)(lVar19 + 8) == -0x1f)) &&
137: (uVar18 = *(uint *)(lVar19 + 0x10), 5 < uVar18)) &&
138: ((pcVar7 = *(char **)(lVar19 + 0x18), *pcVar7 == 'E' && (pcVar7[1] == 'x')))) &&
139: (pcVar7[2] == 'i')) &&
140: (((pcVar7[3] == 'f' && (pcVar7[4] == '\0')) &&
141: ((pcVar7[5] == '\0' &&
142: (*(undefined4 *)(param_2 + 0x24) = 0, param_2[6] != *(code **)(param_1 + 0x30))))))) {
143: uVar4 = *(undefined4 *)((long)param_2 + 0x34);
144: uVar5 = *(undefined4 *)(param_2 + 6);
145: pcVar1 = pcVar7 + 6;
146: if (0xb < uVar18 - 6) {
147: if (pcVar7[6] == 'I') {
148: if (((((pcVar7[7] != 'I') || (pcVar7[9] != '\0')) || (pcVar7[8] != '*')) ||
149: ((pcVar7[0xd] != '\0' || (pcVar7[0xc] != '\0')))) ||
150: (uVar17 = (uint)(byte)pcVar7[0xb] * 0x100 + (uint)(byte)pcVar7[10], uVar18 - 8 < uVar17))
151: goto LAB_0014b7b2;
152: iVar20 = (uint)(byte)pcVar7[(ulong)uVar17 + 6] +
153: (uint)(byte)pcVar7[(ulong)(uVar17 + 1) + 6] * 0x100;
154: bVar10 = false;
155: }
156: else {
157: if ((((pcVar7[6] != 'M') || (pcVar7[7] != 'M')) ||
158: ((pcVar7[8] != '\0' ||
159: (((pcVar7[9] != '*' || (pcVar7[10] != '\0')) || (pcVar7[0xb] != '\0')))))) ||
160: (uVar17 = (uint)(byte)pcVar7[0xc] * 0x100 + (uint)(byte)pcVar7[0xd], uVar18 - 8 < uVar17)
161: ) goto LAB_0014b7b2;
162: iVar20 = (uint)(byte)pcVar7[(ulong)(uVar17 + 1) + 6] +
163: (uint)(byte)pcVar7[(ulong)uVar17 + 6] * 0x100;
164: bVar10 = true;
165: }
166: if (iVar20 != 0) {
167: uVar17 = uVar17 + 2;
168: uVar13 = uVar18 - 0x12;
169: if (uVar17 <= uVar13) {
170: if (bVar10) {
171: while ((uint)(byte)pcVar1[uVar17] * 0x100 + (uint)(byte)pcVar1[uVar17 + 1] != 0x8769) {
172: iVar20 = iVar20 + -1;
173: if ((iVar20 == 0) || (uVar17 = uVar17 + 0xc, uVar13 < uVar17)) goto LAB_0014b7b2;
174: }
175: if (((pcVar7[(ulong)(uVar17 + 8) + 6] == '\0') &&
176: (pcVar7[(ulong)(uVar17 + 9) + 6] == '\0')) &&
177: (uVar17 = (uint)(byte)pcVar7[(ulong)(uVar17 + 10) + 6] * 0x100 +
178: (uint)(byte)pcVar7[(ulong)(uVar17 + 0xb) + 6], uVar17 <= uVar18 - 8)) {
179: uVar18 = (uint)(byte)pcVar7[(ulong)uVar17 + 6] * 0x100 +
180: (uint)(byte)pcVar7[(ulong)(uVar17 + 1) + 6];
181: goto LAB_0014bb6d;
182: }
183: }
184: else {
185: while ((uint)(byte)pcVar1[uVar17 + 1] * 0x100 + (uint)(byte)pcVar1[uVar17] != 0x8769) {
186: iVar20 = iVar20 + -1;
187: if ((iVar20 == 0) || (uVar17 = uVar17 + 0xc, uVar13 < uVar17)) goto LAB_0014b7b2;
188: }
189: if (((pcVar7[(ulong)(uVar17 + 0xb) + 6] == '\0') &&
190: (pcVar7[(ulong)(uVar17 + 10) + 6] == '\0')) &&
191: (uVar17 = (uint)(byte)pcVar7[(ulong)(uVar17 + 9) + 6] * 0x100 +
192: (uint)(byte)pcVar7[(ulong)(uVar17 + 8) + 6], uVar17 <= uVar18 - 8)) {
193: uVar18 = (uint)(byte)pcVar7[(ulong)(uVar17 + 1) + 6] * 0x100 +
194: (uint)(byte)pcVar7[(ulong)uVar17 + 6];
195: LAB_0014bb6d:
196: if ((1 < uVar18) && (uVar14 = uVar17 + 2, uVar14 <= uVar13)) {
197: uVar25 = uVar17 + 4;
198: uVar24 = uVar17 + 5;
199: uVar23 = uVar17 + 6;
200: uVar22 = uVar17 + 7;
201: uVar17 = uVar17 + 8;
202: while( true ) {
203: if (bVar10) {
204: iVar20 = (uint)(byte)pcVar1[uVar14] * 0x100 + (uint)(byte)pcVar1[uVar14 + 1];
205: }
206: else {
207: iVar20 = (uint)(byte)pcVar1[uVar14 + 1] * 0x100 + (uint)(byte)pcVar1[uVar14];
208: }
209: if (iVar20 - 0xa002U < 2) {
210: uVar3 = (short)uVar5;
211: if (iVar20 != 0xa002) {
212: uVar3 = (undefined2)uVar4;
213: }
214: cVar9 = (char)((ushort)uVar3 >> 8);
215: if (bVar10) {
216: pcVar1[uVar25] = '\0';
217: pcVar1[uVar24] = '\x04';
218: pcVar1[uVar23] = '\0';
219: pcVar1[uVar22] = '\0';
220: pcVar1[uVar17] = '\0';
221: pcVar1[uVar14 + 7] = '\x01';
222: pcVar1[uVar14 + 8] = '\0';
223: pcVar1[uVar14 + 9] = '\0';
224: pcVar1[uVar14 + 10] = cVar9;
225: pcVar1[uVar14 + 0xb] = (char)uVar3;
226: }
227: else {
228: pcVar1[uVar25] = '\x04';
229: pcVar1[uVar24] = '\0';
230: pcVar1[uVar23] = '\x01';
231: pcVar1[uVar22] = '\0';
232: pcVar1[uVar17] = '\0';
233: pcVar1[uVar14 + 7] = '\0';
234: pcVar1[uVar14 + 8] = (char)uVar3;
235: pcVar1[uVar14 + 9] = cVar9;
236: pcVar1[uVar14 + 10] = '\0';
237: pcVar1[uVar14 + 0xb] = '\0';
238: }
239: }
240: uVar14 = uVar14 + 0xc;
241: uVar18 = uVar18 - 1;
242: if (uVar18 == 0) break;
243: uVar25 = uVar25 + 0xc;
244: uVar24 = uVar24 + 0xc;
245: uVar23 = uVar23 + 0xc;
246: uVar22 = uVar22 + 0xc;
247: uVar17 = uVar17 + 0xc;
248: if (uVar13 < uVar14) break;
249: }
250: }
251: }
252: }
253: }
254: }
255: }
256: }
257: LAB_0014b7b2:
258: lVar19 = *(long *)(param_4 + 0x10);
259: if (*(long *)(param_4 + 0x10) == 0) {
260: lVar19 = param_3;
261: }
262: return lVar19;
263: }
264: 
