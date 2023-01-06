1: 
2: void FUN_00145d10(code **param_1)
3: 
4: {
5: code *pcVar1;
6: undefined4 uVar2;
7: long lVar3;
8: code *pcVar4;
9: ulong uVar5;
10: ulong uVar6;
11: uint uVar7;
12: uint uVar8;
13: uint uVar9;
14: code **ppcVar10;
15: long lVar11;
16: long *plVar12;
17: undefined8 uVar13;
18: int iVar14;
19: ulong uVar15;
20: undefined (*pauVar16) [16];
21: long lVar17;
22: long lVar18;
23: int iVar19;
24: uint uVar20;
25: uint uVar21;
26: long *plVar22;
27: int iVar23;
28: int iVar24;
29: int iVar25;
30: long lVar26;
31: long lVar27;
32: int iVar28;
33: long in_FS_OFFSET;
34: int iVar29;
35: long lVar30;
36: ulong uVar31;
37: ulong uVar32;
38: long lStack112;
39: 
40: lVar3 = *(long *)(in_FS_OFFSET + 0x28);
41: ppcVar10 = (code **)(**(code **)param_1[1])(param_1,1,0x98);
42: param_1[0x4e] = (code *)ppcVar10;
43: iVar24 = *(int *)(param_1 + 0x12);
44: ppcVar10[0xe] = (code *)0x0;
45: *ppcVar10 = FUN_001453a0;
46: ppcVar10[10] = (code *)0x0;
47: ppcVar10[2] = FUN_00145380;
48: ppcVar10[3] = FUN_00145390;
49: if (4 < iVar24) {
50: ppcVar10 = (code **)*param_1;
51: ppcVar10[5] = (code *)0x400000037;
52: (**ppcVar10)();
53: }
54: iVar24 = *(int *)(param_1 + 0xf);
55: ppcVar10 = (code **)*param_1;
56: if (0x100 < iVar24) {
57: ppcVar10[5] = (code *)0x10000000039;
58: (**ppcVar10)();
59: iVar24 = *(int *)(param_1 + 0xf);
60: ppcVar10 = (code **)*param_1;
61: }
62: lVar26 = (long)iVar24;
63: uVar8 = 1;
64: uVar21 = 2;
65: iVar24 = *(int *)(param_1 + 0x12);
66: pcVar4 = param_1[0x4e];
67: uVar31 = (ulong)*(uint *)(param_1 + 8);
68: uVar9 = iVar24 - 1;
69: pcVar1 = pcVar4 + 0x3c;
70: iVar28 = *(int *)(&DAT_0018eee0 + uVar31 * 4);
71: iVar14 = *(int *)(&DAT_0018ef40 + uVar31 * 4);
72: iVar25 = *(int *)(&DAT_0018ee80 + uVar31 * 4);
73: uVar15 = 2;
74: uVar31 = uVar15;
75: uVar7 = uVar8;
76: if (iVar24 < 2) goto joined_r0x00145f5b;
77: LAB_00145e4f:
78: uVar7 = uVar8;
79: if (iVar24 - 2U < 8) {
80: uVar32 = uVar15;
81: iVar19 = 1;
82: LAB_00145ef7:
83: uVar31 = uVar32 * uVar15;
84: if (((((iVar19 + 1 < iVar24) && (uVar31 = uVar32 * uVar15 * uVar15, iVar19 + 2 < iVar24)) &&
85: (uVar31 = uVar31 * uVar15, iVar19 + 3 < iVar24)) &&
86: ((uVar31 = uVar31 * uVar15, iVar19 + 4 < iVar24 &&
87: (uVar31 = uVar31 * uVar15, iVar19 + 5 < iVar24)))) &&
88: ((uVar31 = uVar31 * uVar15, iVar19 + 6 < iVar24 &&
89: (uVar31 = uVar31 * uVar15, iVar19 + 7 < iVar24)))) {
90: uVar31 = uVar31 * uVar15;
91: }
92: }
93: else {
94: uVar8 = 0;
95: uVar31 = 1;
96: uVar32 = 1;
97: do {
98: uVar8 = uVar8 + 1;
99: uVar31 = (uVar31 & 0xffffffff) * (uVar15 & 0xffffffff) +
100: ((uVar31 >> 0x20) * (uVar15 & 0xffffffff) + (uVar31 & 0xffffffff) * (uVar15 >> 0x20)
101: << 0x20);
102: uVar32 = (uVar32 & 0xffffffff) * (uVar15 & 0xffffffff) +
103: ((uVar32 >> 0x20) * (uVar15 & 0xffffffff) + (uVar32 & 0xffffffff) * (uVar15 >> 0x20)
104: << 0x20);
105: } while (uVar8 < uVar9 >> 1);
106: uVar32 = (((uVar31 & 0xffffffff) * (uVar32 >> 0x20) + (uVar32 & 0xffffffff) * (uVar31 >> 0x20)
107: << 0x20) + (uVar32 & 0xffffffff) * (uVar31 & 0xffffffff)) * uVar15;
108: iVar19 = (uVar9 & 0xfffffffe) + 1;
109: uVar31 = uVar32;
110: if ((uVar9 & 0xfffffffe) != uVar9) goto LAB_00145ef7;
111: }
112: joined_r0x00145f5b:
113: while (uVar8 = uVar21, (long)uVar31 <= lVar26) {
114: uVar15 = uVar15 + 1;
115: uVar21 = uVar8 + 1;
116: uVar31 = uVar15;
117: uVar7 = uVar8;
118: if (1 < iVar24) goto LAB_00145e4f;
119: }
120: if (uVar7 == 1) {
121: *(int *)((long)ppcVar10 + 0x2c) = (int)uVar31;
122: *(undefined4 *)(ppcVar10 + 5) = 0x38;
123: (**ppcVar10)();
124: ppcVar10 = (code **)*param_1;
125: }
126: if (iVar24 < 1) {
127: uVar9 = 1;
128: goto LAB_001462c9;
129: }
130: uVar8 = -(int)((ulong)pcVar1 >> 2) & 3;
131: if (uVar9 < 8) {
132: uVar9 = 1;
133: iVar19 = 0;
134: goto LAB_001460a4;
135: }
136: if (uVar8 == 0) {
137: uVar9 = 1;
138: iVar19 = 0;
139: }
140: else {
141: *(uint *)(pcVar4 + 0x3c) = uVar7;
142: if (uVar8 == 1) {
143: iVar19 = 1;
144: uVar9 = uVar7;
145: }
146: else {
147: *(uint *)(pcVar4 + 0x40) = uVar7;
148: iVar19 = 2;
149: uVar9 = uVar7 * uVar7;
150: if (uVar8 == 3) {
151: *(uint *)(pcVar4 + 0x44) = uVar7;
152: iVar19 = 3;
153: uVar9 = uVar7 * uVar7 * uVar7;
154: }
155: }
156: }
157: uVar31 = (ulong)uVar7;
158: uVar20 = iVar24 - uVar8;
159: uVar21 = 0;
160: uVar15 = 0x100000001;
161: uVar32 = 0x100000001;
162: pauVar16 = (undefined (*) [16])(pcVar4 + (ulong)uVar8 * 4 + 0x3c);
163: do {
164: uVar21 = uVar21 + 1;
165: lVar30 = (uVar32 & 0xffffffff) * uVar31;
166: uVar5 = (uVar15 & 0xffffffff) * uVar31 & 0xffffffff;
167: iVar29 = (int)(uVar32 >> 0x20) * uVar7;
168: uVar6 = (uVar15 >> 0x20) * uVar31 & 0xffffffff;
169: *pauVar16 = CONCAT412(uVar7,CONCAT48(uVar7,CONCAT44(uVar7,uVar7)));
170: iVar23 = (int)lVar30;
171: uVar32 = SUB168(CONCAT412(iVar29,CONCAT48(iVar23,lVar30 << 0x20)) >> 0x40,0);
172: uVar15 = uVar5 | uVar6 << 0x20;
173: pauVar16 = pauVar16[1];
174: } while (uVar21 < uVar20 >> 2);
175: uVar9 = iVar23 * (int)uVar5 * (int)uVar6 * iVar29 * uVar9;
176: iVar19 = (uVar20 & 0xfffffffc) + iVar19;
177: if ((uVar20 & 0xfffffffc) != uVar20) {
178: LAB_001460a4:
179: *(uint *)(pcVar1 + (long)iVar19 * 4) = uVar7;
180: uVar9 = uVar9 * uVar7;
181: if (iVar19 + 1 < iVar24) {
182: *(uint *)(pcVar1 + (long)(iVar19 + 1) * 4) = uVar7;
183: uVar9 = uVar9 * uVar7;
184: if (iVar19 + 2 < iVar24) {
185: *(uint *)(pcVar1 + (long)(iVar19 + 2) * 4) = uVar7;
186: uVar9 = uVar9 * uVar7;
187: if (iVar19 + 3 < iVar24) {
188: *(uint *)(pcVar1 + (long)(iVar19 + 3) * 4) = uVar7;
189: uVar9 = uVar9 * uVar7;
190: if (iVar19 + 4 < iVar24) {
191: *(uint *)(pcVar1 + (long)(iVar19 + 4) * 4) = uVar7;
192: uVar9 = uVar9 * uVar7;
193: if (iVar19 + 5 < iVar24) {
194: *(uint *)(pcVar1 + (long)(iVar19 + 5) * 4) = uVar7;
195: uVar9 = uVar9 * uVar7;
196: if (iVar19 + 6 < iVar24) {
197: uVar9 = uVar9 * uVar7;
198: *(uint *)(pcVar1 + (long)(iVar19 + 6) * 4) = uVar7;
199: if (iVar19 + 7 < iVar24) {
200: uVar9 = uVar9 * uVar7;
201: *(uint *)(pcVar1 + (long)(iVar19 + 7) * 4) = uVar7;
202: }
203: }
204: }
205: }
206: }
207: }
208: }
209: }
210: iVar19 = *(int *)(param_1 + 8);
211: do {
212: if (iVar19 == 2) {
213: while( true ) {
214: iVar19 = *(int *)(pcVar1 + (long)iVar28 * 4);
215: iVar23 = iVar19 + 1;
216: uVar31 = (long)iVar23 * (long)((int)uVar9 / iVar19);
217: if (lVar26 < (long)uVar31) break;
218: *(int *)(pcVar1 + (long)iVar28 * 4) = iVar23;
219: uVar9 = (uint)uVar31;
220: if (iVar24 != 1) {
221: iVar19 = *(int *)(pcVar1 + (long)iVar14 * 4);
222: iVar23 = iVar19 + 1;
223: uVar31 = (long)iVar23 *
224: (long)(int)((long)((ulong)(uint)((int)uVar9 >> 0x1f) << 0x20 |
225: uVar31 & 0xffffffff) / (long)iVar19);
226: if ((long)uVar31 <= lVar26) {
227: *(int *)(pcVar1 + (long)iVar14 * 4) = iVar23;
228: uVar9 = (uint)uVar31;
229: if (iVar24 != 2) {
230: iVar19 = *(int *)(pcVar1 + (long)iVar25 * 4);
231: iVar23 = iVar19 + 1;
232: lVar30 = (long)iVar23 *
233: (long)(int)((long)((ulong)(uint)((int)uVar9 >> 0x1f) << 0x20 |
234: uVar31 & 0xffffffff) / (long)iVar19);
235: if (lVar30 - lVar26 == 0 || lVar30 < lVar26) {
236: *(int *)(pcVar1 + (long)iVar25 * 4) = iVar23;
237: uVar9 = (uint)lVar30;
238: }
239: }
240: }
241: }
242: }
243: LAB_001462c9:
244: if (*(int *)(param_1 + 0x12) == 3) {
245: *(uint *)((long)ppcVar10 + 0x2c) = uVar9;
246: *(undefined4 *)(ppcVar10 + 6) = *(undefined4 *)(pcVar4 + 0x3c);
247: *(undefined4 *)((long)ppcVar10 + 0x34) = *(undefined4 *)(pcVar4 + 0x40);
248: uVar2 = *(undefined4 *)(pcVar4 + 0x44);
249: *(undefined4 *)(ppcVar10 + 5) = 0x5e;
250: *(undefined4 *)(ppcVar10 + 7) = uVar2;
251: (*ppcVar10[1])(param_1,1);
252: }
253: else {
254: *(undefined4 *)(ppcVar10 + 5) = 0x5f;
255: *(uint *)((long)ppcVar10 + 0x2c) = uVar9;
256: (*ppcVar10[1])(param_1,1);
257: }
258: plVar12 = (long *)(**(code **)(param_1[1] + 0x10))(param_1,1,uVar9);
259: iVar24 = *(int *)(param_1 + 0x12);
260: if (0 < iVar24) {
261: lStack112 = 1;
262: uVar31 = (ulong)uVar9;
263: plVar22 = plVar12;
264: do {
265: iVar28 = *(int *)(pcVar4 + lStack112 * 4 + 0x38);
266: iVar14 = (int)uVar31;
267: uVar31 = (long)iVar14 / (long)iVar28 & 0xffffffff;
268: iVar25 = (int)uVar31;
269: if (0 < iVar28) {
270: uVar8 = iVar28 - 1;
271: lVar18 = 0;
272: iVar24 = 0;
273: lVar26 = (long)((int)uVar8 >> 1) + 0xff;
274: lVar30 = (long)((int)uVar8 >> 1);
275: lVar11 = lVar26;
276: while( true ) {
277: if ((iVar24 < (int)uVar9) && (lVar27 = lVar18, iVar28 = iVar24, 0 < iVar25)) {
278: do {
279: lVar17 = lVar27;
280: do {
281: *(char *)(*plVar22 + lVar17) = (char)(lVar30 / (long)(int)uVar8);
282: lVar17 = lVar17 + 1;
283: } while ((ulong)(iVar25 - 1) + 1 + lVar27 != lVar17);
284: iVar28 = iVar28 + iVar14;
285: lVar27 = lVar27 + iVar14;
286: } while (iVar28 < (int)uVar9);
287: }
288: iVar24 = iVar24 + iVar25;
289: lVar18 = lVar18 + iVar25;
290: if (lVar11 == (ulong)uVar8 * 0xff + lVar26) break;
291: lVar30 = lVar11;
292: lVar11 = lVar11 + 0xff;
293: }
294: iVar24 = *(int *)(param_1 + 0x12);
295: }
296: iVar28 = (int)lStack112;
297: plVar22 = plVar22 + 1;
298: lStack112 = lStack112 + 1;
299: } while (iVar28 < iVar24);
300: }
301: *(long **)(pcVar4 + 0x20) = plVar12;
302: *(uint *)(pcVar4 + 0x28) = uVar9;
303: FUN_00144f70(param_1);
304: if ((*(int *)(param_1 + 0xe) == 2) &&
305: (iVar24 = *(int *)(param_1 + 0x11), 0 < *(int *)(param_1 + 0x12))) {
306: pcVar1 = param_1[0x4e];
307: lVar26 = 1;
308: do {
309: uVar13 = (**(code **)(param_1[1] + 8))(param_1,1,(ulong)(iVar24 + 2) * 2);
310: *(undefined8 *)(pcVar1 + lVar26 * 8 + 0x68) = uVar13;
311: iVar28 = (int)lVar26;
312: lVar26 = lVar26 + 1;
313: } while (iVar28 < *(int *)(param_1 + 0x12));
314: }
315: if (lVar3 != *(long *)(in_FS_OFFSET + 0x28)) {
316: /* WARNING: Subroutine does not return */
317: __stack_chk_fail();
318: }
319: return;
320: }
321: iVar23 = *(int *)(pcVar4 + 0x3c) + 1;
322: uVar31 = (long)iVar23 * (long)((int)uVar9 / *(int *)(pcVar4 + 0x3c));
323: if (uVar31 - lVar26 != 0 && lVar26 <= (long)uVar31) goto LAB_001462c9;
324: *(int *)(pcVar4 + 0x3c) = iVar23;
325: uVar9 = (uint)uVar31;
326: if (iVar24 != 1) {
327: iVar23 = *(int *)(pcVar4 + 0x40) + 1;
328: uVar31 = (long)iVar23 *
329: (long)(int)((long)((ulong)(uint)((int)uVar9 >> 0x1f) << 0x20 | uVar31 & 0xffffffff) /
330: (long)*(int *)(pcVar4 + 0x40));
331: if ((long)uVar31 <= lVar26) {
332: *(int *)(pcVar4 + 0x40) = iVar23;
333: uVar9 = (uint)uVar31;
334: if (iVar24 != 2) {
335: iVar23 = *(int *)(pcVar4 + 0x44) + 1;
336: uVar31 = (long)iVar23 *
337: (long)(int)((long)((ulong)(uint)((int)uVar9 >> 0x1f) << 0x20 |
338: uVar31 & 0xffffffff) / (long)*(int *)(pcVar4 + 0x44));
339: if ((long)uVar31 <= lVar26) {
340: *(int *)(pcVar4 + 0x44) = iVar23;
341: uVar9 = (uint)uVar31;
342: if (iVar24 != 3) {
343: iVar23 = *(int *)(pcVar4 + 0x48) + 1;
344: lVar30 = (long)iVar23 *
345: (long)(int)((long)((ulong)(uint)((int)uVar9 >> 0x1f) << 0x20 |
346: uVar31 & 0xffffffff) / (long)*(int *)(pcVar4 + 0x48));
347: if (lVar30 <= lVar26) {
348: *(int *)(pcVar4 + 0x48) = iVar23;
349: uVar9 = (uint)lVar30;
350: if (iVar24 != 4) {
351: lVar30 = 4;
352: do {
353: iVar23 = *(int *)(pcVar1 + lVar30 * 4) + 1;
354: lVar11 = (long)iVar23 * (long)((int)uVar9 / *(int *)(pcVar1 + lVar30 * 4));
355: if (lVar26 < lVar11) break;
356: *(int *)(pcVar1 + lVar30 * 4) = iVar23;
357: lVar30 = lVar30 + 1;
358: uVar9 = (uint)lVar11;
359: } while ((int)lVar30 < iVar24);
360: }
361: }
362: }
363: }
364: }
365: }
366: }
367: } while( true );
368: }
369: 
