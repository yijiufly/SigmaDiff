1: 
2: void FUN_00132db0(code **param_1)
3: 
4: {
5: code **ppcVar1;
6: undefined4 *puVar2;
7: int iVar3;
8: undefined8 uVar4;
9: undefined4 uVar5;
10: undefined4 uVar6;
11: undefined4 uVar7;
12: undefined4 *puVar8;
13: uint uVar9;
14: int iVar10;
15: code *pcVar11;
16: uint uVar12;
17: int iVar13;
18: long lVar14;
19: 
20: iVar13 = *(int *)(param_1 + 0x36);
21: if (iVar13 == 1) {
22: pcVar11 = param_1[0x37];
23: uVar7 = *(undefined4 *)(pcVar11 + 0x24);
24: uVar12 = *(uint *)(pcVar11 + 0xc);
25: *(undefined4 *)(param_1 + 0x3b) = *(undefined4 *)(pcVar11 + 0x1c);
26: uVar9 = *(uint *)(pcVar11 + 0x20);
27: *(uint *)((long)param_1 + 0x1dc) = uVar9;
28: *(undefined4 *)(pcVar11 + 0x40) = uVar7;
29: uVar9 = uVar9 % uVar12;
30: *(undefined4 *)(pcVar11 + 0x3c) = 1;
31: *(undefined4 *)(pcVar11 + 0x44) = 1;
32: *(undefined8 *)(pcVar11 + 0x34) = 0x100000001;
33: if (uVar9 != 0) {
34: uVar12 = uVar9;
35: }
36: lVar14 = *(long *)(pcVar11 + 0x50);
37: *(uint *)(pcVar11 + 0x48) = uVar12;
38: param_1[0x3c] = (code *)0x1;
39: if (lVar14 != 0) goto LAB_001330ab;
40: LAB_0013314b:
41: uVar12 = *(uint *)(pcVar11 + 0x10);
42: if ((3 < uVar12) || (param_1[(long)(int)uVar12 + 0x19] == (code *)0x0)) {
43: ppcVar1 = (code **)*param_1;
44: *(undefined4 *)(ppcVar1 + 5) = 0x34;
45: *(uint *)((long)ppcVar1 + 0x2c) = uVar12;
46: (**ppcVar1)(param_1);
47: }
48: puVar8 = (undefined4 *)(**(code **)param_1[1])(param_1,1,0x84);
49: puVar2 = (undefined4 *)param_1[(long)(int)uVar12 + 0x19];
50: uVar7 = puVar2[1];
51: uVar5 = puVar2[2];
52: uVar6 = puVar2[3];
53: *puVar8 = *puVar2;
54: puVar8[1] = uVar7;
55: puVar8[2] = uVar5;
56: puVar8[3] = uVar6;
57: uVar7 = puVar2[5];
58: uVar5 = puVar2[6];
59: uVar6 = puVar2[7];
60: puVar8[4] = puVar2[4];
61: puVar8[5] = uVar7;
62: puVar8[6] = uVar5;
63: puVar8[7] = uVar6;
64: uVar7 = puVar2[9];
65: uVar5 = puVar2[10];
66: uVar6 = puVar2[0xb];
67: puVar8[8] = puVar2[8];
68: puVar8[9] = uVar7;
69: puVar8[10] = uVar5;
70: puVar8[0xb] = uVar6;
71: uVar7 = puVar2[0xd];
72: uVar5 = puVar2[0xe];
73: uVar6 = puVar2[0xf];
74: puVar8[0xc] = puVar2[0xc];
75: puVar8[0xd] = uVar7;
76: puVar8[0xe] = uVar5;
77: puVar8[0xf] = uVar6;
78: uVar7 = puVar2[0x11];
79: uVar5 = puVar2[0x12];
80: uVar6 = puVar2[0x13];
81: puVar8[0x10] = puVar2[0x10];
82: puVar8[0x11] = uVar7;
83: puVar8[0x12] = uVar5;
84: puVar8[0x13] = uVar6;
85: uVar7 = puVar2[0x15];
86: uVar5 = puVar2[0x16];
87: uVar6 = puVar2[0x17];
88: puVar8[0x14] = puVar2[0x14];
89: puVar8[0x15] = uVar7;
90: puVar8[0x16] = uVar5;
91: puVar8[0x17] = uVar6;
92: uVar7 = puVar2[0x19];
93: uVar5 = puVar2[0x1a];
94: uVar6 = puVar2[0x1b];
95: puVar8[0x18] = puVar2[0x18];
96: puVar8[0x19] = uVar7;
97: puVar8[0x1a] = uVar5;
98: puVar8[0x1b] = uVar6;
99: uVar4 = *(undefined8 *)(puVar2 + 0x1e);
100: *(undefined8 *)(puVar8 + 0x1c) = *(undefined8 *)(puVar2 + 0x1c);
101: *(undefined8 *)(puVar8 + 0x1e) = uVar4;
102: puVar8[0x20] = puVar2[0x20];
103: *(undefined4 **)(pcVar11 + 0x50) = puVar8;
104: }
105: else {
106: if (3 < iVar13 - 1U) {
107: ppcVar1 = (code **)*param_1;
108: *(undefined4 *)(ppcVar1 + 5) = 0x1a;
109: *(int *)((long)ppcVar1 + 0x2c) = iVar13;
110: *(undefined4 *)(ppcVar1 + 6) = 4;
111: (**ppcVar1)();
112: }
113: uVar7 = FUN_001489d0();
114: *(undefined4 *)(param_1 + 0x3b) = uVar7;
115: uVar7 = FUN_001489d0();
116: *(undefined4 *)((long)param_1 + 0x1dc) = uVar7;
117: *(undefined4 *)(param_1 + 0x3c) = 0;
118: if (*(int *)(param_1 + 0x36) < 1) goto LAB_001330ab;
119: lVar14 = 0;
120: iVar13 = 0;
121: while( true ) {
122: pcVar11 = param_1[lVar14 + 0x37];
123: iVar3 = (int)lVar14;
124: uVar12 = *(uint *)(pcVar11 + 8);
125: uVar9 = *(uint *)(pcVar11 + 0xc);
126: *(uint *)(pcVar11 + 0x34) = uVar12;
127: iVar10 = uVar12 * uVar9;
128: *(uint *)(pcVar11 + 0x38) = uVar9;
129: *(uint *)(pcVar11 + 0x40) = *(int *)(pcVar11 + 0x24) * uVar12;
130: *(int *)(pcVar11 + 0x3c) = iVar10;
131: if (*(uint *)(pcVar11 + 0x1c) % uVar12 != 0) {
132: uVar12 = *(uint *)(pcVar11 + 0x1c) % uVar12;
133: }
134: *(uint *)(pcVar11 + 0x44) = uVar12;
135: if (*(uint *)(pcVar11 + 0x20) % uVar9 != 0) {
136: uVar9 = *(uint *)(pcVar11 + 0x20) % uVar9;
137: }
138: *(uint *)(pcVar11 + 0x48) = uVar9;
139: if (10 < iVar13 + iVar10) {
140: ppcVar1 = (code **)*param_1;
141: *(undefined4 *)(ppcVar1 + 5) = 0xd;
142: (**ppcVar1)();
143: }
144: if (0 < iVar10) {
145: iVar13 = *(int *)(param_1 + 0x3c);
146: *(int *)((long)param_1 + (long)iVar13 * 4 + 0x1e4) = iVar3;
147: if (0 < iVar10 + -1) {
148: *(int *)((long)param_1 + (long)(iVar13 + 1) * 4 + 0x1e4) = iVar3;
149: if (2 < iVar10) {
150: *(int *)((long)param_1 + (long)(iVar13 + 2) * 4 + 0x1e4) = iVar3;
151: if (3 < iVar10) {
152: *(int *)((long)param_1 + (long)(iVar13 + 3) * 4 + 0x1e4) = iVar3;
153: if (4 < iVar10) {
154: *(int *)((long)param_1 + (long)(iVar13 + 4) * 4 + 0x1e4) = iVar3;
155: if (5 < iVar10) {
156: *(int *)((long)param_1 + (long)(iVar13 + 5) * 4 + 0x1e4) = iVar3;
157: if (6 < iVar10) {
158: *(int *)((long)param_1 + (long)(iVar13 + 6) * 4 + 0x1e4) = iVar3;
159: if (7 < iVar10) {
160: *(int *)((long)param_1 + (long)(iVar13 + 7) * 4 + 0x1e4) = iVar3;
161: if (8 < iVar10) {
162: *(int *)((long)param_1 + (long)(iVar13 + 8) * 4 + 0x1e4) = iVar3;
163: if (9 < iVar10) {
164: *(int *)((long)param_1 + (long)(iVar13 + 9) * 4 + 0x1e4) = iVar3;
165: }
166: }
167: }
168: }
169: }
170: }
171: }
172: }
173: }
174: *(int *)(param_1 + 0x3c) = iVar10 + -1 + iVar13 + 1;
175: }
176: lVar14 = lVar14 + 1;
177: if (*(int *)(param_1 + 0x36) <= iVar3 + 1) break;
178: iVar13 = *(int *)(param_1 + 0x3c);
179: }
180: if (*(int *)(param_1 + 0x36) < 1) goto LAB_001330ab;
181: pcVar11 = param_1[0x37];
182: if (*(long *)(pcVar11 + 0x50) == 0) goto LAB_0013314b;
183: }
184: if (1 < *(int *)(param_1 + 0x36)) {
185: pcVar11 = param_1[0x38];
186: if (*(long *)(pcVar11 + 0x50) == 0) {
187: uVar12 = *(uint *)(pcVar11 + 0x10);
188: if ((3 < uVar12) || (param_1[(long)(int)uVar12 + 0x19] == (code *)0x0)) {
189: ppcVar1 = (code **)*param_1;
190: *(undefined4 *)(ppcVar1 + 5) = 0x34;
191: *(uint *)((long)ppcVar1 + 0x2c) = uVar12;
192: (**ppcVar1)(param_1);
193: }
194: puVar8 = (undefined4 *)(**(code **)param_1[1])(param_1,1,0x84);
195: puVar2 = (undefined4 *)param_1[(long)(int)uVar12 + 0x19];
196: uVar7 = puVar2[1];
197: uVar5 = puVar2[2];
198: uVar6 = puVar2[3];
199: *puVar8 = *puVar2;
200: puVar8[1] = uVar7;
201: puVar8[2] = uVar5;
202: puVar8[3] = uVar6;
203: uVar7 = puVar2[5];
204: uVar5 = puVar2[6];
205: uVar6 = puVar2[7];
206: puVar8[4] = puVar2[4];
207: puVar8[5] = uVar7;
208: puVar8[6] = uVar5;
209: puVar8[7] = uVar6;
210: uVar7 = puVar2[9];
211: uVar5 = puVar2[10];
212: uVar6 = puVar2[0xb];
213: puVar8[8] = puVar2[8];
214: puVar8[9] = uVar7;
215: puVar8[10] = uVar5;
216: puVar8[0xb] = uVar6;
217: uVar7 = puVar2[0xd];
218: uVar5 = puVar2[0xe];
219: uVar6 = puVar2[0xf];
220: puVar8[0xc] = puVar2[0xc];
221: puVar8[0xd] = uVar7;
222: puVar8[0xe] = uVar5;
223: puVar8[0xf] = uVar6;
224: uVar7 = puVar2[0x11];
225: uVar5 = puVar2[0x12];
226: uVar6 = puVar2[0x13];
227: puVar8[0x10] = puVar2[0x10];
228: puVar8[0x11] = uVar7;
229: puVar8[0x12] = uVar5;
230: puVar8[0x13] = uVar6;
231: uVar7 = puVar2[0x15];
232: uVar5 = puVar2[0x16];
233: uVar6 = puVar2[0x17];
234: puVar8[0x14] = puVar2[0x14];
235: puVar8[0x15] = uVar7;
236: puVar8[0x16] = uVar5;
237: puVar8[0x17] = uVar6;
238: uVar7 = puVar2[0x19];
239: uVar5 = puVar2[0x1a];
240: uVar6 = puVar2[0x1b];
241: puVar8[0x18] = puVar2[0x18];
242: puVar8[0x19] = uVar7;
243: puVar8[0x1a] = uVar5;
244: puVar8[0x1b] = uVar6;
245: uVar4 = *(undefined8 *)(puVar2 + 0x1e);
246: *(undefined8 *)(puVar8 + 0x1c) = *(undefined8 *)(puVar2 + 0x1c);
247: *(undefined8 *)(puVar8 + 0x1e) = uVar4;
248: puVar8[0x20] = puVar2[0x20];
249: *(undefined4 **)(pcVar11 + 0x50) = puVar8;
250: }
251: if (2 < *(int *)(param_1 + 0x36)) {
252: pcVar11 = param_1[0x39];
253: if (*(long *)(pcVar11 + 0x50) == 0) {
254: uVar12 = *(uint *)(pcVar11 + 0x10);
255: if ((3 < uVar12) || (param_1[(long)(int)uVar12 + 0x19] == (code *)0x0)) {
256: ppcVar1 = (code **)*param_1;
257: *(undefined4 *)(ppcVar1 + 5) = 0x34;
258: *(uint *)((long)ppcVar1 + 0x2c) = uVar12;
259: (**ppcVar1)(param_1);
260: }
261: puVar8 = (undefined4 *)(**(code **)param_1[1])(param_1,1,0x84);
262: puVar2 = (undefined4 *)param_1[(long)(int)uVar12 + 0x19];
263: uVar7 = puVar2[1];
264: uVar5 = puVar2[2];
265: uVar6 = puVar2[3];
266: *puVar8 = *puVar2;
267: puVar8[1] = uVar7;
268: puVar8[2] = uVar5;
269: puVar8[3] = uVar6;
270: uVar7 = puVar2[5];
271: uVar5 = puVar2[6];
272: uVar6 = puVar2[7];
273: puVar8[4] = puVar2[4];
274: puVar8[5] = uVar7;
275: puVar8[6] = uVar5;
276: puVar8[7] = uVar6;
277: uVar7 = puVar2[9];
278: uVar5 = puVar2[10];
279: uVar6 = puVar2[0xb];
280: puVar8[8] = puVar2[8];
281: puVar8[9] = uVar7;
282: puVar8[10] = uVar5;
283: puVar8[0xb] = uVar6;
284: uVar7 = puVar2[0xd];
285: uVar5 = puVar2[0xe];
286: uVar6 = puVar2[0xf];
287: puVar8[0xc] = puVar2[0xc];
288: puVar8[0xd] = uVar7;
289: puVar8[0xe] = uVar5;
290: puVar8[0xf] = uVar6;
291: uVar7 = puVar2[0x11];
292: uVar5 = puVar2[0x12];
293: uVar6 = puVar2[0x13];
294: puVar8[0x10] = puVar2[0x10];
295: puVar8[0x11] = uVar7;
296: puVar8[0x12] = uVar5;
297: puVar8[0x13] = uVar6;
298: uVar7 = puVar2[0x15];
299: uVar5 = puVar2[0x16];
300: uVar6 = puVar2[0x17];
301: puVar8[0x14] = puVar2[0x14];
302: puVar8[0x15] = uVar7;
303: puVar8[0x16] = uVar5;
304: puVar8[0x17] = uVar6;
305: uVar7 = puVar2[0x19];
306: uVar5 = puVar2[0x1a];
307: uVar6 = puVar2[0x1b];
308: puVar8[0x18] = puVar2[0x18];
309: puVar8[0x19] = uVar7;
310: puVar8[0x1a] = uVar5;
311: puVar8[0x1b] = uVar6;
312: uVar4 = *(undefined8 *)(puVar2 + 0x1e);
313: *(undefined8 *)(puVar8 + 0x1c) = *(undefined8 *)(puVar2 + 0x1c);
314: *(undefined8 *)(puVar8 + 0x1e) = uVar4;
315: puVar8[0x20] = puVar2[0x20];
316: *(undefined4 **)(pcVar11 + 0x50) = puVar8;
317: }
318: if ((3 < *(int *)(param_1 + 0x36)) &&
319: (pcVar11 = param_1[0x3a], *(long *)(pcVar11 + 0x50) == 0)) {
320: uVar12 = *(uint *)(pcVar11 + 0x10);
321: if ((3 < uVar12) || (param_1[(long)(int)uVar12 + 0x19] == (code *)0x0)) {
322: ppcVar1 = (code **)*param_1;
323: *(undefined4 *)(ppcVar1 + 5) = 0x34;
324: *(uint *)((long)ppcVar1 + 0x2c) = uVar12;
325: (**ppcVar1)(param_1);
326: }
327: puVar8 = (undefined4 *)(**(code **)param_1[1])(param_1,1,0x84);
328: puVar2 = (undefined4 *)param_1[(long)(int)uVar12 + 0x19];
329: uVar7 = puVar2[1];
330: uVar5 = puVar2[2];
331: uVar6 = puVar2[3];
332: *puVar8 = *puVar2;
333: puVar8[1] = uVar7;
334: puVar8[2] = uVar5;
335: puVar8[3] = uVar6;
336: uVar7 = puVar2[5];
337: uVar5 = puVar2[6];
338: uVar6 = puVar2[7];
339: puVar8[4] = puVar2[4];
340: puVar8[5] = uVar7;
341: puVar8[6] = uVar5;
342: puVar8[7] = uVar6;
343: uVar7 = puVar2[9];
344: uVar5 = puVar2[10];
345: uVar6 = puVar2[0xb];
346: puVar8[8] = puVar2[8];
347: puVar8[9] = uVar7;
348: puVar8[10] = uVar5;
349: puVar8[0xb] = uVar6;
350: uVar7 = puVar2[0xd];
351: uVar5 = puVar2[0xe];
352: uVar6 = puVar2[0xf];
353: puVar8[0xc] = puVar2[0xc];
354: puVar8[0xd] = uVar7;
355: puVar8[0xe] = uVar5;
356: puVar8[0xf] = uVar6;
357: uVar7 = puVar2[0x11];
358: uVar5 = puVar2[0x12];
359: uVar6 = puVar2[0x13];
360: puVar8[0x10] = puVar2[0x10];
361: puVar8[0x11] = uVar7;
362: puVar8[0x12] = uVar5;
363: puVar8[0x13] = uVar6;
364: uVar7 = puVar2[0x15];
365: uVar5 = puVar2[0x16];
366: uVar6 = puVar2[0x17];
367: puVar8[0x14] = puVar2[0x14];
368: puVar8[0x15] = uVar7;
369: puVar8[0x16] = uVar5;
370: puVar8[0x17] = uVar6;
371: uVar7 = puVar2[0x19];
372: uVar5 = puVar2[0x1a];
373: uVar6 = puVar2[0x1b];
374: puVar8[0x18] = puVar2[0x18];
375: puVar8[0x19] = uVar7;
376: puVar8[0x1a] = uVar5;
377: puVar8[0x1b] = uVar6;
378: uVar7 = puVar2[0x1d];
379: uVar5 = puVar2[0x1e];
380: uVar6 = puVar2[0x1f];
381: puVar8[0x1c] = puVar2[0x1c];
382: puVar8[0x1d] = uVar7;
383: puVar8[0x1e] = uVar5;
384: puVar8[0x1f] = uVar6;
385: puVar8[0x20] = puVar2[0x20];
386: *(undefined4 **)(pcVar11 + 0x50) = puVar8;
387: }
388: }
389: }
390: LAB_001330ab:
391: (**(code **)param_1[0x4a])(param_1);
392: (**(code **)param_1[0x46])(param_1);
393: *(undefined8 *)param_1[0x48] = *(undefined8 *)(param_1[0x46] + 8);
394: return;
395: }
396: 
