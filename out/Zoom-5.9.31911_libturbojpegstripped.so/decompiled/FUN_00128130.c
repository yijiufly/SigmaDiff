1: 
2: void FUN_00128130(code **param_1)
3: 
4: {
5: undefined uVar1;
6: undefined2 uVar2;
7: code *pcVar3;
8: code *pcVar4;
9: code **ppcVar5;
10: long lVar6;
11: undefined4 uVar7;
12: undefined8 *puVar8;
13: ulong uVar9;
14: uint uVar10;
15: uint uVar11;
16: int iVar12;
17: undefined8 *puVar13;
18: undefined8 *puVar14;
19: undefined8 *puVar15;
20: int iVar16;
21: int iVar17;
22: code **ppcVar18;
23: bool bVar19;
24: byte bVar20;
25: 
26: bVar20 = 0;
27: iVar16 = *(int *)(param_1 + 0x36);
28: if (iVar16 == 1) {
29: pcVar3 = param_1[0x37];
30: pcVar4 = param_1[0x37];
31: uVar7 = *(undefined4 *)(pcVar3 + 0x24);
32: uVar11 = *(uint *)(pcVar3 + 0xc);
33: *(undefined4 *)(param_1 + 0x3b) = *(undefined4 *)(pcVar3 + 0x1c);
34: uVar10 = *(uint *)(pcVar3 + 0x20);
35: *(uint *)((long)param_1 + 0x1dc) = uVar10;
36: *(undefined4 *)(pcVar3 + 0x40) = uVar7;
37: uVar10 = uVar10 % uVar11;
38: *(undefined4 *)(pcVar3 + 0x34) = 1;
39: *(undefined4 *)(pcVar3 + 0x38) = 1;
40: iVar16 = 1;
41: *(undefined4 *)(pcVar3 + 0x3c) = 1;
42: *(undefined4 *)(pcVar3 + 0x44) = 1;
43: if (uVar10 != 0) {
44: uVar11 = uVar10;
45: }
46: lVar6 = *(long *)(pcVar4 + 0x50);
47: *(uint *)(pcVar3 + 0x48) = uVar11;
48: *(undefined4 *)(param_1 + 0x3c) = 1;
49: *(undefined4 *)((long)param_1 + 0x1e4) = 0;
50: }
51: else {
52: if (3 < iVar16 - 1U) {
53: pcVar3 = *param_1;
54: *(int *)(pcVar3 + 0x2c) = iVar16;
55: pcVar4 = *param_1;
56: *(undefined4 *)(pcVar3 + 0x28) = 0x1a;
57: *(undefined4 *)(pcVar4 + 0x30) = 4;
58: (**(code **)*param_1)();
59: }
60: uVar7 = FUN_0013be20();
61: *(undefined4 *)(param_1 + 0x3b) = uVar7;
62: uVar7 = FUN_0013be20();
63: *(undefined4 *)((long)param_1 + 0x1dc) = uVar7;
64: *(undefined4 *)(param_1 + 0x3c) = 0;
65: if (*(int *)(param_1 + 0x36) < 1) goto LAB_00128408;
66: iVar16 = 0;
67: iVar12 = 0;
68: ppcVar18 = param_1;
69: while( true ) {
70: pcVar3 = ppcVar18[0x37];
71: uVar11 = *(uint *)(pcVar3 + 8);
72: uVar10 = *(uint *)(pcVar3 + 0xc);
73: *(uint *)(pcVar3 + 0x34) = uVar11;
74: iVar17 = uVar11 * uVar10;
75: *(uint *)(pcVar3 + 0x38) = uVar10;
76: *(uint *)(pcVar3 + 0x40) = *(int *)(pcVar3 + 0x24) * uVar11;
77: *(int *)(pcVar3 + 0x3c) = iVar17;
78: if (*(uint *)(pcVar3 + 0x1c) % uVar11 != 0) {
79: uVar11 = *(uint *)(pcVar3 + 0x1c) % uVar11;
80: }
81: *(uint *)(pcVar3 + 0x44) = uVar11;
82: if (*(uint *)(pcVar3 + 0x20) % uVar10 != 0) {
83: uVar10 = *(uint *)(pcVar3 + 0x20) % uVar10;
84: }
85: *(uint *)(pcVar3 + 0x48) = uVar10;
86: if (10 < iVar16 + iVar17) {
87: ppcVar5 = (code **)*param_1;
88: *(undefined4 *)(ppcVar5 + 5) = 0xd;
89: (**ppcVar5)();
90: }
91: if (0 < iVar17) {
92: iVar16 = *(int *)(param_1 + 0x3c);
93: *(int *)((long)param_1 + (long)iVar16 * 4 + 0x1e4) = iVar12;
94: if (0 < iVar17 + -1) {
95: *(int *)((long)param_1 + (long)(iVar16 + 1) * 4 + 0x1e4) = iVar12;
96: if (2 < iVar17) {
97: *(int *)((long)param_1 + (long)(iVar16 + 2) * 4 + 0x1e4) = iVar12;
98: if (3 < iVar17) {
99: *(int *)((long)param_1 + (long)(iVar16 + 3) * 4 + 0x1e4) = iVar12;
100: if (4 < iVar17) {
101: *(int *)((long)param_1 + (long)(iVar16 + 4) * 4 + 0x1e4) = iVar12;
102: if (5 < iVar17) {
103: *(int *)((long)param_1 + (long)(iVar16 + 5) * 4 + 0x1e4) = iVar12;
104: if (6 < iVar17) {
105: *(int *)((long)param_1 + (long)(iVar16 + 6) * 4 + 0x1e4) = iVar12;
106: if (7 < iVar17) {
107: *(int *)((long)param_1 + (long)(iVar16 + 7) * 4 + 0x1e4) = iVar12;
108: if (8 < iVar17) {
109: *(int *)((long)param_1 + (long)(iVar16 + 8) * 4 + 0x1e4) = iVar12;
110: if (9 < iVar17) {
111: *(int *)((long)param_1 + (long)(iVar16 + 9) * 4 + 0x1e4) = iVar12;
112: }
113: }
114: }
115: }
116: }
117: }
118: }
119: }
120: }
121: *(int *)(param_1 + 0x3c) = iVar17 + -1 + iVar16 + 1;
122: }
123: iVar16 = *(int *)(param_1 + 0x36);
124: iVar12 = iVar12 + 1;
125: ppcVar18 = ppcVar18 + 1;
126: if (iVar16 <= iVar12) break;
127: iVar16 = *(int *)(param_1 + 0x3c);
128: }
129: if (iVar16 < 1) goto LAB_00128408;
130: pcVar4 = param_1[0x37];
131: lVar6 = *(long *)(pcVar4 + 0x50);
132: }
133: if (lVar6 == 0) {
134: uVar11 = *(uint *)(pcVar4 + 0x10);
135: if ((3 < uVar11) || (param_1[(long)(int)uVar11 + 0x19] == (code *)0x0)) {
136: pcVar3 = *param_1;
137: *(uint *)(pcVar3 + 0x2c) = uVar11;
138: ppcVar18 = (code **)*param_1;
139: *(undefined4 *)(pcVar3 + 0x28) = 0x34;
140: (**ppcVar18)(param_1);
141: }
142: puVar8 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x84);
143: bVar19 = ((ulong)puVar8 & 1) != 0;
144: puVar13 = (undefined8 *)param_1[(long)(int)uVar11 + 0x19];
145: uVar11 = 0x84;
146: puVar14 = puVar8;
147: if (bVar19) {
148: uVar1 = *(undefined *)puVar13;
149: puVar14 = (undefined8 *)((long)puVar8 + 1);
150: puVar13 = (undefined8 *)((long)puVar13 + 1);
151: *(undefined *)puVar8 = uVar1;
152: uVar11 = 0x83;
153: }
154: puVar15 = puVar14;
155: if (((ulong)puVar14 & 2) != 0) {
156: uVar2 = *(undefined2 *)puVar13;
157: puVar15 = (undefined8 *)((long)puVar14 + 2);
158: puVar13 = (undefined8 *)((long)puVar13 + 2);
159: uVar11 = uVar11 - 2;
160: *(undefined2 *)puVar14 = uVar2;
161: }
162: puVar14 = puVar15;
163: if (((ulong)puVar15 & 4) != 0) {
164: uVar7 = *(undefined4 *)puVar13;
165: puVar14 = (undefined8 *)((long)puVar15 + 4);
166: puVar13 = (undefined8 *)((long)puVar13 + 4);
167: uVar11 = uVar11 - 4;
168: *(undefined4 *)puVar15 = uVar7;
169: }
170: uVar9 = (ulong)(uVar11 >> 3);
171: while (uVar9 != 0) {
172: uVar9 = uVar9 - 1;
173: *puVar14 = *puVar13;
174: puVar13 = puVar13 + (ulong)bVar20 * -2 + 1;
175: puVar14 = puVar14 + (ulong)bVar20 * -2 + 1;
176: }
177: if ((uVar11 & 4) != 0) {
178: *(undefined4 *)puVar14 = *(undefined4 *)puVar13;
179: uVar9 = 4;
180: }
181: if ((uVar11 & 2) != 0) {
182: *(undefined2 *)((long)puVar14 + uVar9) = *(undefined2 *)((long)puVar13 + uVar9);
183: uVar9 = uVar9 + 2;
184: }
185: if (bVar19) {
186: *(undefined *)((long)puVar14 + uVar9) = *(undefined *)((long)puVar13 + uVar9);
187: }
188: *(undefined8 **)(pcVar4 + 0x50) = puVar8;
189: iVar16 = *(int *)(param_1 + 0x36);
190: }
191: if (1 < iVar16) {
192: pcVar3 = param_1[0x38];
193: if (*(long *)(pcVar3 + 0x50) == 0) {
194: uVar11 = *(uint *)(pcVar3 + 0x10);
195: if ((3 < uVar11) || (param_1[(long)(int)uVar11 + 0x19] == (code *)0x0)) {
196: pcVar4 = *param_1;
197: *(uint *)(pcVar4 + 0x2c) = uVar11;
198: ppcVar18 = (code **)*param_1;
199: *(undefined4 *)(pcVar4 + 0x28) = 0x34;
200: (**ppcVar18)(param_1);
201: }
202: puVar8 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x84);
203: bVar19 = ((ulong)puVar8 & 1) != 0;
204: puVar13 = (undefined8 *)param_1[(long)(int)uVar11 + 0x19];
205: uVar11 = 0x84;
206: puVar14 = puVar8;
207: if (bVar19) {
208: uVar1 = *(undefined *)puVar13;
209: puVar14 = (undefined8 *)((long)puVar8 + 1);
210: puVar13 = (undefined8 *)((long)puVar13 + 1);
211: *(undefined *)puVar8 = uVar1;
212: uVar11 = 0x83;
213: }
214: puVar15 = puVar14;
215: if (((ulong)puVar14 & 2) != 0) {
216: uVar2 = *(undefined2 *)puVar13;
217: puVar15 = (undefined8 *)((long)puVar14 + 2);
218: puVar13 = (undefined8 *)((long)puVar13 + 2);
219: uVar11 = uVar11 - 2;
220: *(undefined2 *)puVar14 = uVar2;
221: }
222: puVar14 = puVar15;
223: if (((ulong)puVar15 & 4) != 0) {
224: uVar7 = *(undefined4 *)puVar13;
225: puVar14 = (undefined8 *)((long)puVar15 + 4);
226: puVar13 = (undefined8 *)((long)puVar13 + 4);
227: uVar11 = uVar11 - 4;
228: *(undefined4 *)puVar15 = uVar7;
229: }
230: uVar9 = (ulong)(uVar11 >> 3);
231: while (uVar9 != 0) {
232: uVar9 = uVar9 - 1;
233: *puVar14 = *puVar13;
234: puVar13 = puVar13 + (ulong)bVar20 * -2 + 1;
235: puVar14 = puVar14 + (ulong)bVar20 * -2 + 1;
236: }
237: if ((uVar11 & 4) != 0) {
238: *(undefined4 *)puVar14 = *(undefined4 *)puVar13;
239: uVar9 = 4;
240: }
241: if ((uVar11 & 2) != 0) {
242: *(undefined2 *)((long)puVar14 + uVar9) = *(undefined2 *)((long)puVar13 + uVar9);
243: uVar9 = uVar9 + 2;
244: }
245: if (bVar19) {
246: *(undefined *)((long)puVar14 + uVar9) = *(undefined *)((long)puVar13 + uVar9);
247: }
248: *(undefined8 **)(pcVar3 + 0x50) = puVar8;
249: iVar16 = *(int *)(param_1 + 0x36);
250: }
251: if (2 < iVar16) {
252: pcVar3 = param_1[0x39];
253: if (*(long *)(pcVar3 + 0x50) == 0) {
254: uVar11 = *(uint *)(pcVar3 + 0x10);
255: if ((3 < uVar11) || (param_1[(long)(int)uVar11 + 0x19] == (code *)0x0)) {
256: pcVar4 = *param_1;
257: *(uint *)(pcVar4 + 0x2c) = uVar11;
258: ppcVar18 = (code **)*param_1;
259: *(undefined4 *)(pcVar4 + 0x28) = 0x34;
260: (**ppcVar18)(param_1);
261: }
262: puVar8 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x84);
263: bVar19 = ((ulong)puVar8 & 1) != 0;
264: puVar13 = (undefined8 *)param_1[(long)(int)uVar11 + 0x19];
265: uVar11 = 0x84;
266: puVar14 = puVar8;
267: if (bVar19) {
268: uVar1 = *(undefined *)puVar13;
269: puVar14 = (undefined8 *)((long)puVar8 + 1);
270: puVar13 = (undefined8 *)((long)puVar13 + 1);
271: *(undefined *)puVar8 = uVar1;
272: uVar11 = 0x83;
273: }
274: puVar15 = puVar14;
275: if (((ulong)puVar14 & 2) != 0) {
276: uVar2 = *(undefined2 *)puVar13;
277: puVar15 = (undefined8 *)((long)puVar14 + 2);
278: puVar13 = (undefined8 *)((long)puVar13 + 2);
279: uVar11 = uVar11 - 2;
280: *(undefined2 *)puVar14 = uVar2;
281: }
282: puVar14 = puVar15;
283: if (((ulong)puVar15 & 4) != 0) {
284: uVar7 = *(undefined4 *)puVar13;
285: puVar14 = (undefined8 *)((long)puVar15 + 4);
286: puVar13 = (undefined8 *)((long)puVar13 + 4);
287: uVar11 = uVar11 - 4;
288: *(undefined4 *)puVar15 = uVar7;
289: }
290: uVar9 = (ulong)(uVar11 >> 3);
291: while (uVar9 != 0) {
292: uVar9 = uVar9 - 1;
293: *puVar14 = *puVar13;
294: puVar13 = puVar13 + (ulong)bVar20 * -2 + 1;
295: puVar14 = puVar14 + (ulong)bVar20 * -2 + 1;
296: }
297: if ((uVar11 & 4) != 0) {
298: *(undefined4 *)puVar14 = *(undefined4 *)puVar13;
299: uVar9 = 4;
300: }
301: if ((uVar11 & 2) != 0) {
302: *(undefined2 *)((long)puVar14 + uVar9) = *(undefined2 *)((long)puVar13 + uVar9);
303: uVar9 = uVar9 + 2;
304: }
305: if (bVar19) {
306: *(undefined *)((long)puVar14 + uVar9) = *(undefined *)((long)puVar13 + uVar9);
307: }
308: *(undefined8 **)(pcVar3 + 0x50) = puVar8;
309: iVar16 = *(int *)(param_1 + 0x36);
310: }
311: if ((3 < iVar16) && (pcVar3 = param_1[0x3a], *(long *)(pcVar3 + 0x50) == 0)) {
312: uVar11 = *(uint *)(pcVar3 + 0x10);
313: if ((3 < uVar11) || (param_1[(long)(int)uVar11 + 0x19] == (code *)0x0)) {
314: pcVar4 = *param_1;
315: *(uint *)(pcVar4 + 0x2c) = uVar11;
316: ppcVar18 = (code **)*param_1;
317: *(undefined4 *)(pcVar4 + 0x28) = 0x34;
318: (**ppcVar18)(param_1);
319: }
320: puVar8 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x84);
321: bVar19 = ((ulong)puVar8 & 1) != 0;
322: puVar13 = (undefined8 *)param_1[(long)(int)uVar11 + 0x19];
323: uVar11 = 0x84;
324: puVar14 = puVar8;
325: if (bVar19) {
326: uVar1 = *(undefined *)puVar13;
327: puVar14 = (undefined8 *)((long)puVar8 + 1);
328: puVar13 = (undefined8 *)((long)puVar13 + 1);
329: *(undefined *)puVar8 = uVar1;
330: uVar11 = 0x83;
331: }
332: puVar15 = puVar14;
333: if (((ulong)puVar14 & 2) != 0) {
334: uVar2 = *(undefined2 *)puVar13;
335: puVar15 = (undefined8 *)((long)puVar14 + 2);
336: puVar13 = (undefined8 *)((long)puVar13 + 2);
337: uVar11 = uVar11 - 2;
338: *(undefined2 *)puVar14 = uVar2;
339: }
340: puVar14 = puVar15;
341: if (((ulong)puVar15 & 4) != 0) {
342: uVar7 = *(undefined4 *)puVar13;
343: puVar14 = (undefined8 *)((long)puVar15 + 4);
344: puVar13 = (undefined8 *)((long)puVar13 + 4);
345: uVar11 = uVar11 - 4;
346: *(undefined4 *)puVar15 = uVar7;
347: }
348: uVar9 = (ulong)(uVar11 >> 3);
349: while (uVar9 != 0) {
350: uVar9 = uVar9 - 1;
351: *puVar14 = *puVar13;
352: puVar13 = puVar13 + (ulong)bVar20 * -2 + 1;
353: puVar14 = puVar14 + (ulong)bVar20 * -2 + 1;
354: }
355: if ((uVar11 & 4) != 0) {
356: *(undefined4 *)puVar14 = *(undefined4 *)puVar13;
357: uVar9 = 4;
358: }
359: if ((uVar11 & 2) != 0) {
360: *(undefined2 *)((long)puVar14 + uVar9) = *(undefined2 *)((long)puVar13 + uVar9);
361: uVar9 = uVar9 + 2;
362: }
363: if (bVar19) {
364: *(undefined *)((long)puVar14 + uVar9) = *(undefined *)((long)puVar13 + uVar9);
365: }
366: *(undefined8 **)(pcVar3 + 0x50) = puVar8;
367: }
368: }
369: }
370: LAB_00128408:
371: (**(code **)param_1[0x4a])(param_1);
372: (**(code **)param_1[0x46])(param_1);
373: *(undefined8 *)param_1[0x48] = *(undefined8 *)(param_1[0x46] + 8);
374: return;
375: }
376: 
