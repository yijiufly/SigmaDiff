1: 
2: undefined8 FUN_00132830(code **param_1,void **param_2,uint *param_3)
3: 
4: {
5: undefined4 *puVar1;
6: undefined4 *puVar2;
7: code cVar3;
8: int iVar4;
9: undefined4 uVar5;
10: undefined4 uVar6;
11: undefined4 uVar7;
12: code **ppcVar8;
13: void *pvVar9;
14: undefined8 uVar10;
15: uint uVar11;
16: uint uVar12;
17: long lVar13;
18: ulong uVar14;
19: code *pcVar15;
20: undefined8 *puVar16;
21: code *pcVar17;
22: code *pcVar18;
23: uint uVar20;
24: uint uVar21;
25: uint uVar22;
26: ulong uVar23;
27: code **ppcVar24;
28: long in_FS_OFFSET;
29: byte bVar25;
30: uint auStack2376 [256];
31: uint auStack1352 [256];
32: char cStack328;
33: undefined auStack327 [247];
34: undefined8 uStack80;
35: long lStack64;
36: code *pcVar19;
37: 
38: bVar25 = 0;
39: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
40: if ((param_2 == (void **)0x0) || (param_3 == (uint *)0x0)) {
41: ppcVar24 = (code **)*param_1;
42: *(undefined4 *)(ppcVar24 + 5) = 0x17;
43: (**ppcVar24)(param_1);
44: }
45: iVar4 = *(int *)((long)param_1 + 0x24);
46: if (iVar4 < 0xca) {
47: ppcVar24 = (code **)*param_1;
48: *(undefined4 *)(ppcVar24 + 5) = 0x14;
49: *(int *)((long)ppcVar24 + 0x2c) = iVar4;
50: (**ppcVar24)(param_1);
51: }
52: lVar13 = 0x1f;
53: *param_2 = (void *)0x0;
54: *param_3 = 0;
55: auStack327._0_8_ = 0;
56: uStack80 = 0;
57: puVar16 = (undefined8 *)(auStack327 + 7);
58: while (lVar13 != 0) {
59: lVar13 = lVar13 + -1;
60: *puVar16 = 0;
61: puVar16 = puVar16 + (ulong)bVar25 * -2 + 1;
62: }
63: ppcVar24 = (code **)param_1[0x32];
64: ppcVar8 = ppcVar24;
65: uVar12 = 0;
66: if (ppcVar24 != (code **)0x0) {
67: do {
68: while (((((*(code *)(ppcVar8 + 1) == (code)0xe2 &&
69: (uVar11 = *(uint *)(ppcVar8 + 2), 0xd < uVar11)) &&
70: (pcVar19 = ppcVar8[3], *pcVar19 == (code)0x49)) &&
71: ((pcVar19[1] == (code)0x43 && (pcVar19[2] == (code)0x43)))) &&
72: ((((pcVar19[3] == (code)0x5f &&
73: ((pcVar19[4] == (code)0x50 && (pcVar19[5] == (code)0x52)))) &&
74: (pcVar19[6] == (code)0x4f)) &&
75: ((((pcVar19[7] == (code)0x46 && (pcVar19[8] == (code)0x49)) &&
76: (pcVar19[9] == (code)0x4c)) &&
77: ((pcVar19[10] == (code)0x45 && (pcVar19[0xb] == (code)0x0))))))))) {
78: uVar21 = (uint)(byte)pcVar19[0xd];
79: if ((uVar12 != 0) && (uVar21 = uVar12, (byte)pcVar19[0xd] != uVar12)) goto LAB_001329c0;
80: cVar3 = pcVar19[0xc];
81: uVar14 = (ulong)(byte)cVar3;
82: if ((cVar3 == (code)0x0) || ((uVar21 < (byte)cVar3 || ((&cStack328)[uVar14] != '\0'))))
83: goto LAB_001329c0;
84: ppcVar8 = (code **)*ppcVar8;
85: (&cStack328)[uVar14] = '\x01';
86: auStack2376[uVar14] = uVar11 - 0xe;
87: uVar12 = uVar21;
88: if (ppcVar8 == (code **)0x0) goto LAB_00132995;
89: }
90: ppcVar8 = (code **)*ppcVar8;
91: } while (ppcVar8 != (code **)0x0);
92: LAB_00132995:
93: if (uVar12 != 0) {
94: lVar13 = 1;
95: uVar11 = 0;
96: do {
97: if ((&cStack328)[lVar13] == '\0') goto LAB_001329c0;
98: auStack1352[lVar13] = uVar11;
99: uVar11 = uVar11 + auStack2376[lVar13];
100: lVar13 = lVar13 + 1;
101: } while ((int)lVar13 <= (int)uVar12);
102: if (uVar11 != 0) {
103: pvVar9 = malloc((ulong)uVar11);
104: if (pvVar9 != (void *)0x0) goto LAB_00132a4d;
105: ppcVar24 = (code **)*param_1;
106: ppcVar24[5] = (code *)0xb00000036;
107: (**ppcVar24)(param_1);
108: ppcVar24 = (code **)param_1[0x32];
109: while (ppcVar24 != (code **)0x0) {
110: LAB_00132a4d:
111: if (((((*(code *)(ppcVar24 + 1) == (code)0xe2) && (0xd < *(uint *)(ppcVar24 + 2))) &&
112: (pcVar19 = ppcVar24[3], *pcVar19 == (code)0x49)) &&
113: (((pcVar19[1] == (code)0x43 && (pcVar19[2] == (code)0x43)) &&
114: ((pcVar19[3] == (code)0x5f &&
115: ((pcVar19[4] == (code)0x50 && (pcVar19[5] == (code)0x52)))))))) &&
116: ((pcVar19[6] == (code)0x4f &&
117: ((((pcVar19[7] == (code)0x46 && (pcVar19[8] == (code)0x49)) &&
118: (pcVar19[9] == (code)0x4c)) &&
119: ((pcVar19[10] == (code)0x45 && (pcVar19[0xb] == (code)0x0)))))))) {
120: pcVar15 = pcVar19 + 0xe;
121: uVar23 = (ulong)auStack1352[(byte)pcVar19[0xc]];
122: uVar21 = auStack2376[(byte)pcVar19[0xc]];
123: uVar12 = uVar21 - 1;
124: uVar14 = (ulong)uVar12;
125: pcVar17 = (code *)((long)pvVar9 + uVar23);
126: if (uVar21 != 0) {
127: if ((pcVar15 < (code *)((long)pvVar9 + uVar23 + 0x10) && pcVar17 < pcVar19 + 0x1e) ||
128: (uVar21 < 0x17)) {
129: lVar13 = 0;
130: do {
131: pcVar17[lVar13] = pcVar19[lVar13 + 0xe];
132: lVar13 = lVar13 + 1;
133: } while (lVar13 != uVar14 + 1);
134: }
135: else {
136: uVar20 = -(int)pcVar15 & 0xf;
137: if (uVar20 + 0xf <= uVar12) {
138: pcVar18 = pcVar17;
139: if (uVar20 != 0) {
140: pcVar15 = pcVar19 + 0xf;
141: *pcVar17 = pcVar19[0xe];
142: uVar12 = uVar21 - 2;
143: pcVar18 = pcVar17 + 1;
144: if (uVar20 != 1) {
145: pcVar15 = pcVar19 + 0x10;
146: pcVar17[1] = pcVar19[0xf];
147: uVar12 = uVar21 - 3;
148: pcVar18 = pcVar17 + 2;
149: if (uVar20 != 2) {
150: pcVar15 = pcVar19 + 0x11;
151: pcVar17[2] = pcVar19[0x10];
152: uVar12 = uVar21 - 4;
153: pcVar18 = pcVar17 + 3;
154: if (uVar20 != 3) {
155: pcVar15 = pcVar19 + 0x12;
156: pcVar17[3] = pcVar19[0x11];
157: uVar12 = uVar21 - 5;
158: pcVar18 = pcVar17 + 4;
159: if (uVar20 != 4) {
160: pcVar15 = pcVar19 + 0x13;
161: pcVar17[4] = pcVar19[0x12];
162: uVar12 = uVar21 - 6;
163: pcVar18 = pcVar17 + 5;
164: if (uVar20 != 5) {
165: pcVar15 = pcVar19 + 0x14;
166: pcVar17[5] = pcVar19[0x13];
167: uVar12 = uVar21 - 7;
168: pcVar18 = pcVar17 + 6;
169: if (uVar20 != 6) {
170: pcVar15 = pcVar19 + 0x15;
171: pcVar17[6] = pcVar19[0x14];
172: uVar12 = uVar21 - 8;
173: pcVar18 = pcVar17 + 7;
174: if (uVar20 != 7) {
175: pcVar15 = pcVar19 + 0x16;
176: pcVar17[7] = pcVar19[0x15];
177: uVar12 = uVar21 - 9;
178: pcVar18 = pcVar17 + 8;
179: if (uVar20 != 8) {
180: pcVar15 = pcVar19 + 0x17;
181: pcVar17[8] = pcVar19[0x16];
182: uVar12 = uVar21 - 10;
183: pcVar18 = pcVar17 + 9;
184: if (uVar20 != 9) {
185: pcVar15 = pcVar19 + 0x18;
186: pcVar17[9] = pcVar19[0x17];
187: uVar12 = uVar21 - 0xb;
188: pcVar18 = pcVar17 + 10;
189: if (uVar20 != 10) {
190: pcVar15 = pcVar19 + 0x19;
191: pcVar17[10] = pcVar19[0x18];
192: uVar12 = uVar21 - 0xc;
193: pcVar18 = pcVar17 + 0xb;
194: if (uVar20 != 0xb) {
195: pcVar15 = pcVar19 + 0x1a;
196: pcVar17[0xb] = pcVar19[0x19];
197: uVar12 = uVar21 - 0xd;
198: pcVar18 = pcVar17 + 0xc;
199: if (uVar20 != 0xc) {
200: pcVar15 = pcVar19 + 0x1b;
201: pcVar17[0xc] = pcVar19[0x1a];
202: uVar12 = uVar21 - 0xe;
203: pcVar18 = pcVar17 + 0xd;
204: if (uVar20 != 0xd) {
205: pcVar15 = pcVar19 + 0x1c;
206: pcVar17[0xd] = pcVar19[0x1b];
207: uVar12 = uVar21 - 0xf;
208: pcVar18 = pcVar17 + 0xe;
209: if (uVar20 == 0xf) {
210: pcVar15 = pcVar19 + 0x1d;
211: pcVar17[0xe] = pcVar19[0x1c];
212: uVar12 = uVar21 - 0x10;
213: pcVar18 = pcVar17 + 0xf;
214: }
215: }
216: }
217: }
218: }
219: }
220: }
221: }
222: }
223: }
224: }
225: }
226: }
227: }
228: }
229: uVar21 = uVar21 - uVar20;
230: lVar13 = 0;
231: uVar22 = 0;
232: do {
233: puVar1 = (undefined4 *)(pcVar19 + lVar13 + (ulong)uVar20 + 0xe);
234: uVar5 = puVar1[1];
235: uVar6 = puVar1[2];
236: uVar7 = puVar1[3];
237: uVar22 = uVar22 + 1;
238: puVar2 = (undefined4 *)((long)pvVar9 + lVar13 + uVar23 + uVar20);
239: *puVar2 = *puVar1;
240: puVar2[1] = uVar5;
241: puVar2[2] = uVar6;
242: puVar2[3] = uVar7;
243: lVar13 = lVar13 + 0x10;
244: } while (uVar22 < uVar21 >> 4);
245: uVar20 = uVar21 & 0xfffffff0;
246: uVar14 = (ulong)(uVar12 - uVar20);
247: pcVar15 = pcVar15 + uVar20;
248: pcVar17 = pcVar18 + uVar20;
249: if (uVar21 == uVar20) goto LAB_00132a40;
250: }
251: pcVar19 = pcVar17;
252: do {
253: pcVar18 = pcVar19 + (ulong)bVar25 * -2 + 1;
254: *pcVar19 = *pcVar15;
255: pcVar15 = pcVar15 + (ulong)bVar25 * -2 + 1;
256: pcVar19 = pcVar18;
257: } while (pcVar18 != pcVar17 + uVar14 + 1);
258: }
259: }
260: }
261: LAB_00132a40:
262: ppcVar24 = (code **)*ppcVar24;
263: }
264: *param_2 = pvVar9;
265: uVar10 = 1;
266: *param_3 = uVar11;
267: goto LAB_001329d8;
268: }
269: LAB_001329c0:
270: pcVar19 = *param_1;
271: *(undefined4 *)(pcVar19 + 0x28) = 0x7f;
272: (**(code **)(pcVar19 + 8))(param_1,0xffffffff);
273: }
274: }
275: uVar10 = 0;
276: LAB_001329d8:
277: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
278: return uVar10;
279: }
280: /* WARNING: Subroutine does not return */
281: __stack_chk_fail();
282: }
283: 
