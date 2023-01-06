1: 
2: /* WARNING: Could not reconcile some variable overlaps */
3: 
4: void FUN_0013a910(long param_1,int param_2,int param_3,int param_4)
5: 
6: {
7: int iVar1;
8: long *plVar2;
9: int iVar3;
10: byte bVar4;
11: uint uVar5;
12: int iVar6;
13: long lVar7;
14: long lVar8;
15: int iVar9;
16: int iVar10;
17: long lVar11;
18: long lVar12;
19: ulong uVar13;
20: long *plVar14;
21: uint uVar15;
22: long lVar16;
23: byte *pbVar17;
24: long lVar18;
25: long lVar19;
26: long lVar20;
27: long lVar21;
28: long lVar22;
29: long lVar23;
30: long lVar24;
31: long lVar25;
32: int iVar26;
33: byte *pbVar27;
34: int iVar28;
35: int iVar29;
36: long in_FS_OFFSET;
37: long lStack2672;
38: byte *pbStack2664;
39: long alStack2504 [128];
40: long alStack1480 [128];
41: byte abStack456 [128];
42: byte abStack328 [264];
43: long lStack64;
44: 
45: lVar7 = *(long *)(*(long *)(param_1 + 0x270) + 0x30);
46: iVar29 = (param_2 >> 2) * 0x20;
47: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
48: uVar5 = *(uint *)(param_1 + 0x40);
49: iVar10 = iVar29 + 4;
50: iVar28 = (param_3 >> 3) * 0x20;
51: iVar29 = iVar29 + 0x1c;
52: iVar1 = iVar28 + 2;
53: uVar13 = (ulong)uVar5;
54: iVar28 = iVar28 + 0x1e;
55: iVar26 = (param_4 >> 2) * 0x20;
56: iVar3 = iVar26 + 4;
57: iVar26 = iVar26 + 0x1c;
58: if (*(int *)(param_1 + 0x9c) < 1) {
59: iVar26 = 0;
60: }
61: else {
62: plVar14 = *(long **)(param_1 + 0xa0);
63: lVar18 = 0;
64: lVar22 = 0x7fffffff;
65: lVar25 = (ulong)(*(int *)(param_1 + 0x9c) - 1) + 1;
66: lVar12 = *plVar14;
67: lVar19 = plVar14[1];
68: lVar8 = plVar14[2];
69: iVar6 = *(int *)(&DAT_0018b320 + (long)*(int *)(&DAT_0018b340 + uVar13 * 4) * 4);
70: do {
71: uVar15 = (uint)*(byte *)(lVar12 + lVar18);
72: if ((int)uVar15 < iVar10) {
73: lVar11 = (long)(int)((uVar15 - iVar10) *
74: *(int *)(&DAT_0018b320 + (long)*(int *)(&DAT_0018b400 + uVar13 * 4) * 4)
75: );
76: lVar16 = (long)(int)((uVar15 - iVar29) *
77: *(int *)(&DAT_0018b320 + (long)*(int *)(&DAT_0018b400 + uVar13 * 4) * 4)
78: );
79: lVar11 = lVar11 * lVar11;
80: lVar16 = lVar16 * lVar16;
81: LAB_0013aaa3:
82: bVar4 = *(byte *)(lVar19 + lVar18);
83: uVar15 = (uint)bVar4;
84: if (iVar1 <= (int)(uint)bVar4) goto LAB_0013ab95;
85: LAB_0013aab4:
86: lVar24 = (long)(int)((uVar15 - iVar1) *
87: *(int *)(&DAT_0018b320 + (long)*(int *)(&DAT_0018b3a0 + uVar13 * 4) * 4)
88: );
89: lVar20 = (long)(int)((uVar15 - iVar28) *
90: *(int *)(&DAT_0018b320 + (long)*(int *)(&DAT_0018b3a0 + uVar13 * 4) * 4)
91: );
92: lVar11 = lVar11 + lVar24 * lVar24;
93: lVar16 = lVar16 + lVar20 * lVar20;
94: LAB_0013aae8:
95: bVar4 = *(byte *)(lVar8 + lVar18);
96: uVar15 = (uint)bVar4;
97: if (iVar3 <= (int)(uint)bVar4) goto LAB_0013abe3;
98: LAB_0013aafa:
99: lVar20 = (long)(int)((uVar15 - iVar3) * iVar6);
100: lVar11 = lVar11 + lVar20 * lVar20;
101: LAB_0013ab0e:
102: lVar20 = (long)(int)((uVar15 - iVar26) * iVar6);
103: lVar16 = lVar16 + lVar20 * lVar20;
104: }
105: else {
106: if ((int)uVar15 <= iVar29) {
107: iVar9 = iVar10;
108: if ((int)uVar15 <= iVar10 + iVar29 >> 1) {
109: iVar9 = iVar29;
110: }
111: lVar11 = 0;
112: lVar16 = (long)(int)((uVar15 - iVar9) *
113: *(int *)(&DAT_0018b320 +
114: (long)*(int *)(&DAT_0018b400 + uVar13 * 4) * 4));
115: lVar16 = lVar16 * lVar16;
116: goto LAB_0013aaa3;
117: }
118: lVar16 = (long)(int)((uVar15 - iVar10) *
119: *(int *)(&DAT_0018b320 + (long)*(int *)(&DAT_0018b400 + uVar13 * 4) * 4)
120: );
121: bVar4 = *(byte *)(lVar19 + lVar18);
122: lVar11 = (long)(int)((uVar15 - iVar29) *
123: *(int *)(&DAT_0018b320 + (long)*(int *)(&DAT_0018b400 + uVar13 * 4) * 4)
124: );
125: lVar11 = lVar11 * lVar11;
126: lVar16 = lVar16 * lVar16;
127: uVar15 = (uint)bVar4;
128: if ((int)uVar15 < iVar1) goto LAB_0013aab4;
129: LAB_0013ab95:
130: uVar15 = (uint)bVar4;
131: if ((int)uVar15 <= iVar28) {
132: iVar9 = iVar1;
133: if ((int)uVar15 <= iVar1 + iVar28 >> 1) {
134: iVar9 = iVar28;
135: }
136: lVar20 = (long)(int)((uVar15 - iVar9) *
137: *(int *)(&DAT_0018b320 +
138: (long)*(int *)(&DAT_0018b3a0 + uVar13 * 4) * 4));
139: lVar16 = lVar16 + lVar20 * lVar20;
140: goto LAB_0013aae8;
141: }
142: lVar20 = (long)(int)((uVar15 - iVar1) *
143: *(int *)(&DAT_0018b320 + (long)*(int *)(&DAT_0018b3a0 + uVar13 * 4) * 4)
144: );
145: lVar24 = (long)(int)((uVar15 - iVar28) *
146: *(int *)(&DAT_0018b320 + (long)*(int *)(&DAT_0018b3a0 + uVar13 * 4) * 4)
147: );
148: lVar16 = lVar16 + lVar20 * lVar20;
149: lVar11 = lVar11 + lVar24 * lVar24;
150: uVar15 = (uint)*(byte *)(lVar8 + lVar18);
151: if ((int)uVar15 < iVar3) goto LAB_0013aafa;
152: LAB_0013abe3:
153: if (iVar26 < (int)uVar15) {
154: lVar20 = (long)(int)((uVar15 - iVar26) * iVar6);
155: lVar11 = lVar11 + lVar20 * lVar20;
156: }
157: else {
158: if ((int)uVar15 <= iVar3 + iVar26 >> 1) goto LAB_0013ab0e;
159: }
160: lVar20 = (long)(int)((uVar15 - iVar3) * iVar6);
161: lVar16 = lVar16 + lVar20 * lVar20;
162: }
163: if (lVar16 < lVar22) {
164: lVar22 = lVar16;
165: }
166: alStack2504[lVar18] = lVar11;
167: lVar18 = lVar18 + 1;
168: } while (lVar18 != lVar25);
169: lVar12 = 0;
170: iVar26 = 0;
171: do {
172: plVar14 = alStack2504 + lVar12;
173: if (*plVar14 == lVar22 || *plVar14 < lVar22) {
174: lVar19 = (long)iVar26;
175: iVar26 = iVar26 + 1;
176: abStack328[lVar19] = (byte)lVar12;
177: }
178: lVar12 = lVar12 + 1;
179: } while (lVar12 != lVar25);
180: }
181: plVar14 = alStack2504;
182: do {
183: *plVar14 = 0x7fffffff;
184: plVar14[1] = 0x7fffffff;
185: plVar14 = plVar14 + 2;
186: } while (plVar14 != alStack1480);
187: if (iVar26 != 0) {
188: uVar13 = (ulong)uVar5;
189: lStack2672 = 0;
190: plVar14 = *(long **)(param_1 + 0xa0);
191: lVar12 = *plVar14;
192: lVar19 = plVar14[1];
193: lVar8 = plVar14[2];
194: iVar28 = *(int *)(&DAT_0018b320 + (long)*(int *)(&DAT_0018b400 + uVar13 * 4) * 4);
195: iVar29 = *(int *)(&DAT_0018b320 + (long)*(int *)(&DAT_0018b3a0 + uVar13 * 4) * 4);
196: iVar6 = *(int *)(&DAT_0018b320 + (long)*(int *)(&DAT_0018b340 + uVar13 * 4) * 4);
197: lVar22 = (long)(iVar6 * iVar6 * 0x80);
198: do {
199: bVar4 = abStack328[lStack2672];
200: uVar13 = (ulong)bVar4;
201: lVar11 = (long)(int)((iVar10 - (uint)*(byte *)(lVar12 + uVar13)) * iVar28);
202: lVar16 = (long)(int)(iVar29 * (iVar1 - (uint)*(byte *)(lVar19 + uVar13)));
203: lVar25 = (long)(int)(iVar6 * (iVar3 - (uint)*(byte *)(lVar8 + uVar13)));
204: lVar18 = lVar11 * (iVar28 << 4) + (long)(iVar28 * iVar28 * 0x40);
205: lVar20 = lVar11 * lVar11 + lVar16 * lVar16 + lVar25 * lVar25;
206: lVar25 = lVar25 * (iVar6 << 4) + (long)(iVar6 * iVar6 * 0x40);
207: lVar11 = lVar25 + lVar22;
208: plVar14 = alStack2504;
209: pbVar27 = abStack456;
210: do {
211: plVar2 = plVar14 + 0x20;
212: pbVar17 = pbVar27;
213: lVar24 = lVar20;
214: lVar23 = lVar16 * (iVar29 * 8) + (long)(iVar29 * iVar29 * 0x10);
215: do {
216: if (lVar24 < *plVar14) {
217: *plVar14 = lVar24;
218: *pbVar17 = bVar4;
219: }
220: lVar21 = lVar25 + lVar24;
221: if (lVar21 < plVar14[1]) {
222: plVar14[1] = lVar21;
223: pbVar17[1] = bVar4;
224: }
225: lVar21 = lVar21 + lVar11;
226: if (lVar21 < plVar14[2]) {
227: plVar14[2] = lVar21;
228: pbVar17[2] = bVar4;
229: }
230: lVar21 = lVar21 + lVar22 + lVar11;
231: if (lVar21 < plVar14[3]) {
232: plVar14[3] = lVar21;
233: pbVar17[3] = bVar4;
234: }
235: plVar14 = plVar14 + 4;
236: lVar24 = lVar24 + lVar23;
237: pbVar17 = pbVar17 + 4;
238: lVar23 = lVar23 + iVar29 * iVar29 * 0x20;
239: } while (plVar2 != plVar14);
240: lVar20 = lVar20 + lVar18;
241: pbVar27 = pbVar27 + 0x20;
242: lVar18 = lVar18 + iVar28 * iVar28 * 0x80;
243: plVar14 = plVar2;
244: } while (plVar2 != alStack1480);
245: lStack2672 = lStack2672 + 1;
246: } while ((int)lStack2672 < iVar26);
247: }
248: pbStack2664 = abStack456;
249: iVar10 = (param_3 >> 3) * 8;
250: plVar14 = (long *)(lVar7 + (long)((param_2 >> 2) << 2) * 8);
251: lVar19 = (long)(iVar10 + 1) * 0x40;
252: lVar12 = (long)((param_4 >> 2) << 2);
253: lVar7 = lVar12 * 2;
254: do {
255: lVar22 = *plVar14;
256: lVar8 = lVar22 + (long)iVar10 * 0x40;
257: *(ushort *)(lVar8 + lVar12 * 2) = *pbStack2664 + 1;
258: lVar8 = lVar8 + lVar7;
259: bVar4 = pbStack2664[4];
260: *(ushort *)(lVar8 + 2) = pbStack2664[1] + 1;
261: *(ushort *)(lVar8 + 4) = pbStack2664[2] + 1;
262: *(ushort *)(lVar8 + 6) = pbStack2664[3] + 1;
263: *(ushort *)(lVar22 + lVar19 + lVar12 * 2) = bVar4 + 1;
264: lVar8 = lVar22 + lVar19 + lVar7;
265: bVar4 = pbStack2664[8];
266: *(ushort *)(lVar8 + 2) = pbStack2664[5] + 1;
267: *(ushort *)(lVar8 + 4) = pbStack2664[6] + 1;
268: *(ushort *)(lVar8 + 6) = pbStack2664[7] + 1;
269: lVar8 = lVar22 + lVar19 + 0x40;
270: *(ushort *)(lVar8 + lVar12 * 2) = bVar4 + 1;
271: lVar8 = lVar8 + lVar7;
272: bVar4 = pbStack2664[0xc];
273: *(ushort *)(lVar8 + 2) = pbStack2664[9] + 1;
274: *(ushort *)(lVar8 + 4) = pbStack2664[10] + 1;
275: *(ushort *)(lVar8 + 6) = pbStack2664[0xb] + 1;
276: lVar8 = lVar22 + lVar19 + 0x80;
277: *(ushort *)(lVar8 + lVar12 * 2) = bVar4 + 1;
278: lVar8 = lVar8 + lVar7;
279: bVar4 = pbStack2664[0x10];
280: *(ushort *)(lVar8 + 2) = pbStack2664[0xd] + 1;
281: *(ushort *)(lVar8 + 4) = pbStack2664[0xe] + 1;
282: *(ushort *)(lVar8 + 6) = pbStack2664[0xf] + 1;
283: lVar8 = lVar22 + lVar19 + 0xc0;
284: *(ushort *)(lVar8 + lVar12 * 2) = bVar4 + 1;
285: lVar8 = lVar8 + lVar7;
286: bVar4 = pbStack2664[0x14];
287: *(ushort *)(lVar8 + 2) = pbStack2664[0x11] + 1;
288: *(ushort *)(lVar8 + 4) = pbStack2664[0x12] + 1;
289: *(ushort *)(lVar8 + 6) = pbStack2664[0x13] + 1;
290: lVar8 = lVar22 + lVar19 + 0x100;
291: *(ushort *)(lVar8 + lVar12 * 2) = bVar4 + 1;
292: lVar8 = lVar8 + lVar7;
293: bVar4 = pbStack2664[0x18];
294: *(ushort *)(lVar8 + 2) = pbStack2664[0x15] + 1;
295: *(ushort *)(lVar8 + 4) = pbStack2664[0x16] + 1;
296: *(ushort *)(lVar8 + 6) = pbStack2664[0x17] + 1;
297: lVar8 = lVar22 + lVar19 + 0x140;
298: lVar22 = lVar22 + lVar19 + 0x180;
299: *(ushort *)(lVar8 + lVar12 * 2) = bVar4 + 1;
300: lVar8 = lVar8 + lVar7;
301: *(ushort *)(lVar8 + 2) = pbStack2664[0x19] + 1;
302: *(ushort *)(lVar8 + 4) = pbStack2664[0x1a] + 1;
303: *(ushort *)(lVar8 + 6) = pbStack2664[0x1b] + 1;
304: lVar8 = lVar22 + lVar7;
305: *(ushort *)(lVar22 + lVar12 * 2) = pbStack2664[0x1c] + 1;
306: *(ushort *)(lVar8 + 2) = pbStack2664[0x1d] + 1;
307: *(ushort *)(lVar8 + 4) = pbStack2664[0x1e] + 1;
308: pbVar27 = pbStack2664 + 0x1f;
309: pbStack2664 = pbStack2664 + 0x20;
310: plVar14 = plVar14 + 1;
311: *(ushort *)(lVar8 + 6) = *pbVar27 + 1;
312: } while (pbStack2664 != abStack328);
313: if (lStack64 != *(long *)(in_FS_OFFSET + 0x28)) {
314: /* WARNING: Subroutine does not return */
315: __stack_chk_fail(0x7fffffff);
316: }
317: return;
318: }
319: 
