1: 
2: void FUN_00117cb0(code **param_1,int param_2)
3: 
4: {
5: uint uVar1;
6: undefined4 uVar2;
7: code *pcVar3;
8: int iVar4;
9: code *pcVar5;
10: undefined8 uVar6;
11: ulong uVar7;
12: ulong uVar8;
13: undefined8 *puVar9;
14: undefined8 *puVar10;
15: long lVar11;
16: bool bVar12;
17: byte bVar13;
18: 
19: bVar13 = 0;
20: iVar4 = *(int *)((long)param_1 + 0x1a4);
21: pcVar3 = param_1[0x3e];
22: bVar12 = *(int *)((long)param_1 + 0x19c) == 0;
23: *(code ***)(pcVar3 + 0x50) = param_1;
24: *(int *)(pcVar3 + 0x28) = param_2;
25: if (iVar4 == 0) {
26: pcVar5 = FUN_00119c30;
27: if (bVar12) {
28: pcVar5 = FUN_00118f60;
29: }
30: *(code **)(pcVar3 + 8) = pcVar5;
31: iVar4 = FUN_00168a10();
32: if (iVar4 == 0) {
33: *(code **)(pcVar3 + 0x18) = FUN_00117b80;
34: }
35: else {
36: *(code **)(pcVar3 + 0x18) = thunk_FUN_00158ea0;
37: }
38: }
39: else {
40: if (bVar12) {
41: *(code **)(pcVar3 + 8) = FUN_00119160;
42: }
43: else {
44: *(code **)(pcVar3 + 8) = FUN_001193c0;
45: iVar4 = FUN_00168a60();
46: pcVar5 = FUN_00117c00;
47: if (iVar4 != 0) {
48: pcVar5 = thunk_FUN_00159360;
49: }
50: *(code **)(pcVar3 + 0x20) = pcVar5;
51: if (*(long *)(pcVar3 + 0x78) == 0) {
52: uVar6 = (**(code **)param_1[1])(param_1,1,1000);
53: *(undefined8 *)(pcVar3 + 0x78) = uVar6;
54: }
55: }
56: }
57: iVar4 = *(int *)((long)param_1 + 0x144);
58: pcVar5 = FUN_00118b60;
59: if (param_2 != 0) {
60: pcVar5 = FUN_001188c0;
61: }
62: *(code **)(pcVar3 + 0x10) = pcVar5;
63: if (0 < iVar4) {
64: if (bVar12) {
65: pcVar5 = param_1[0x29];
66: *(undefined4 *)(pcVar3 + 0x58) = 0;
67: if (param_2 == 0) {
68: if (*(int *)((long)param_1 + 0x1a4) == 0) {
69: FUN_00111780();
70: }
71: if (1 < *(int *)((long)param_1 + 0x144)) {
72: iVar4 = *(int *)((long)param_1 + 0x1a4);
73: *(undefined4 *)(pcVar3 + 0x5c) = 0;
74: if (iVar4 == 0) {
75: FUN_00111780(param_1);
76: }
77: if (2 < *(int *)((long)param_1 + 0x144)) {
78: iVar4 = *(int *)((long)param_1 + 0x1a4);
79: *(undefined4 *)(pcVar3 + 0x60) = 0;
80: if (iVar4 == 0) {
81: FUN_00111780(param_1,1);
82: }
83: if (3 < *(int *)((long)param_1 + 0x144)) {
84: iVar4 = *(int *)((long)param_1 + 0x1a4);
85: pcVar5 = param_1[0x2c];
86: *(undefined4 *)(pcVar3 + 100) = 0;
87: if (iVar4 == 0) {
88: FUN_00111780(param_1,1,*(int *)(pcVar5 + 0x14),
89: pcVar3 + (long)*(int *)(pcVar5 + 0x14) * 8 + 0x88);
90: }
91: }
92: }
93: }
94: }
95: else {
96: if (*(int *)((long)param_1 + 0x1a4) == 0) {
97: uVar1 = *(uint *)(pcVar5 + 0x14);
98: if (3 < uVar1) {
99: pcVar5 = *param_1;
100: *(undefined4 *)(pcVar5 + 0x28) = 0x32;
101: *(uint *)(pcVar5 + 0x2c) = uVar1;
102: (**(code **)*param_1)(param_1);
103: }
104: puVar10 = *(undefined8 **)(pcVar3 + (long)(int)uVar1 * 8 + 0xa8);
105: if (puVar10 == (undefined8 *)0x0) {
106: puVar10 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x808);
107: *(undefined8 **)(pcVar3 + (long)(int)uVar1 * 8 + 0xa8) = puVar10;
108: }
109: bVar12 = ((ulong)puVar10 & 1) != 0;
110: uVar8 = 0x808;
111: if (bVar12) {
112: *(undefined *)puVar10 = 0;
113: uVar8 = 0x807;
114: puVar10 = (undefined8 *)((long)puVar10 + 1);
115: }
116: puVar9 = puVar10;
117: if (((ulong)puVar10 & 2) != 0) {
118: puVar9 = (undefined8 *)((long)puVar10 + 2);
119: uVar8 = (ulong)((int)uVar8 - 2);
120: *(undefined2 *)puVar10 = 0;
121: }
122: if (((ulong)puVar9 & 4) != 0) {
123: *(undefined4 *)puVar9 = 0;
124: uVar8 = (ulong)((int)uVar8 - 4);
125: puVar9 = (undefined8 *)((long)puVar9 + 4);
126: }
127: uVar7 = uVar8 >> 3;
128: while (uVar7 != 0) {
129: uVar7 = uVar7 - 1;
130: *puVar9 = 0;
131: puVar9 = puVar9 + (ulong)bVar13 * -2 + 1;
132: }
133: if ((uVar8 & 4) != 0) {
134: *(undefined4 *)puVar9 = 0;
135: puVar9 = (undefined8 *)((long)puVar9 + 4);
136: }
137: puVar10 = puVar9;
138: if ((uVar8 & 2) != 0) {
139: puVar10 = (undefined8 *)((long)puVar9 + 2);
140: *(undefined2 *)puVar9 = 0;
141: }
142: if (bVar12) {
143: *(undefined *)puVar10 = 0;
144: }
145: }
146: if (1 < *(int *)((long)param_1 + 0x144)) {
147: iVar4 = *(int *)((long)param_1 + 0x1a4);
148: pcVar5 = param_1[0x2a];
149: *(undefined4 *)(pcVar3 + 0x5c) = 0;
150: if (iVar4 == 0) {
151: uVar1 = *(uint *)(pcVar5 + 0x14);
152: if (3 < uVar1) {
153: pcVar5 = *param_1;
154: *(undefined4 *)(pcVar5 + 0x28) = 0x32;
155: *(uint *)(pcVar5 + 0x2c) = uVar1;
156: (**(code **)*param_1)(param_1);
157: }
158: puVar10 = *(undefined8 **)(pcVar3 + (long)(int)uVar1 * 8 + 0xa8);
159: if (puVar10 == (undefined8 *)0x0) {
160: puVar10 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x808);
161: *(undefined8 **)(pcVar3 + (long)(int)uVar1 * 8 + 0xa8) = puVar10;
162: }
163: bVar12 = ((ulong)puVar10 & 1) != 0;
164: uVar8 = 0x808;
165: if (bVar12) {
166: *(undefined *)puVar10 = 0;
167: uVar8 = 0x807;
168: puVar10 = (undefined8 *)((long)puVar10 + 1);
169: }
170: puVar9 = puVar10;
171: if (((ulong)puVar10 & 2) != 0) {
172: puVar9 = (undefined8 *)((long)puVar10 + 2);
173: uVar8 = (ulong)((int)uVar8 - 2);
174: *(undefined2 *)puVar10 = 0;
175: }
176: if (((ulong)puVar9 & 4) != 0) {
177: *(undefined4 *)puVar9 = 0;
178: uVar8 = (ulong)((int)uVar8 - 4);
179: puVar9 = (undefined8 *)((long)puVar9 + 4);
180: }
181: uVar7 = uVar8 >> 3;
182: while (uVar7 != 0) {
183: uVar7 = uVar7 - 1;
184: *puVar9 = 0;
185: puVar9 = puVar9 + (ulong)bVar13 * -2 + 1;
186: }
187: if ((uVar8 & 4) != 0) {
188: *(undefined4 *)puVar9 = 0;
189: puVar9 = (undefined8 *)((long)puVar9 + 4);
190: }
191: puVar10 = puVar9;
192: if ((uVar8 & 2) != 0) {
193: puVar10 = (undefined8 *)((long)puVar9 + 2);
194: *(undefined2 *)puVar9 = 0;
195: }
196: if (bVar12) {
197: *(undefined *)puVar10 = 0;
198: }
199: }
200: if (2 < *(int *)((long)param_1 + 0x144)) {
201: iVar4 = *(int *)((long)param_1 + 0x1a4);
202: pcVar5 = param_1[0x2b];
203: *(undefined4 *)(pcVar3 + 0x60) = 0;
204: if (iVar4 == 0) {
205: uVar1 = *(uint *)(pcVar5 + 0x14);
206: if (3 < uVar1) {
207: pcVar5 = *param_1;
208: *(undefined4 *)(pcVar5 + 0x28) = 0x32;
209: *(uint *)(pcVar5 + 0x2c) = uVar1;
210: (**(code **)*param_1)(param_1);
211: }
212: puVar10 = *(undefined8 **)(pcVar3 + (long)(int)uVar1 * 8 + 0xa8);
213: if (puVar10 == (undefined8 *)0x0) {
214: puVar10 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x808);
215: *(undefined8 **)(pcVar3 + (long)(int)uVar1 * 8 + 0xa8) = puVar10;
216: }
217: bVar12 = ((ulong)puVar10 & 1) != 0;
218: uVar8 = 0x808;
219: if (bVar12) {
220: *(undefined *)puVar10 = 0;
221: uVar8 = 0x807;
222: puVar10 = (undefined8 *)((long)puVar10 + 1);
223: }
224: puVar9 = puVar10;
225: if (((ulong)puVar10 & 2) != 0) {
226: puVar9 = (undefined8 *)((long)puVar10 + 2);
227: uVar8 = (ulong)((int)uVar8 - 2);
228: *(undefined2 *)puVar10 = 0;
229: }
230: if (((ulong)puVar9 & 4) != 0) {
231: *(undefined4 *)puVar9 = 0;
232: uVar8 = (ulong)((int)uVar8 - 4);
233: puVar9 = (undefined8 *)((long)puVar9 + 4);
234: }
235: uVar7 = uVar8 >> 3;
236: while (uVar7 != 0) {
237: uVar7 = uVar7 - 1;
238: *puVar9 = 0;
239: puVar9 = puVar9 + (ulong)bVar13 * -2 + 1;
240: }
241: if ((uVar8 & 4) != 0) {
242: *(undefined4 *)puVar9 = 0;
243: puVar9 = (undefined8 *)((long)puVar9 + 4);
244: }
245: puVar10 = puVar9;
246: if ((uVar8 & 2) != 0) {
247: puVar10 = (undefined8 *)((long)puVar9 + 2);
248: *(undefined2 *)puVar9 = 0;
249: }
250: if (bVar12) {
251: *(undefined *)puVar10 = 0;
252: }
253: }
254: if (3 < *(int *)((long)param_1 + 0x144)) {
255: iVar4 = *(int *)((long)param_1 + 0x1a4);
256: pcVar5 = param_1[0x2c];
257: *(undefined4 *)(pcVar3 + 100) = 0;
258: if (iVar4 == 0) {
259: uVar1 = *(uint *)(pcVar5 + 0x14);
260: if (3 < uVar1) {
261: pcVar5 = *param_1;
262: *(undefined4 *)(pcVar5 + 0x28) = 0x32;
263: *(uint *)(pcVar5 + 0x2c) = uVar1;
264: (**(code **)*param_1)(param_1);
265: }
266: puVar10 = *(undefined8 **)(pcVar3 + (long)(int)uVar1 * 8 + 0xa8);
267: if (puVar10 == (undefined8 *)0x0) {
268: puVar10 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x808);
269: *(undefined8 **)(pcVar3 + (long)(int)uVar1 * 8 + 0xa8) = puVar10;
270: }
271: bVar12 = ((ulong)puVar10 & 1) != 0;
272: uVar8 = 0x808;
273: if (bVar12) {
274: *(undefined *)puVar10 = 0;
275: uVar8 = 0x807;
276: puVar10 = (undefined8 *)((long)puVar10 + 1);
277: }
278: puVar9 = puVar10;
279: if (((ulong)puVar10 & 2) != 0) {
280: puVar9 = (undefined8 *)((long)puVar10 + 2);
281: uVar8 = (ulong)((int)uVar8 - 2);
282: *(undefined2 *)puVar10 = 0;
283: }
284: if (((ulong)puVar9 & 4) != 0) {
285: *(undefined4 *)puVar9 = 0;
286: uVar8 = (ulong)((int)uVar8 - 4);
287: puVar9 = (undefined8 *)((long)puVar9 + 4);
288: }
289: uVar7 = uVar8 >> 3;
290: while (uVar7 != 0) {
291: uVar7 = uVar7 - 1;
292: *puVar9 = 0;
293: puVar9 = puVar9 + (ulong)bVar13 * -2 + 1;
294: }
295: if ((uVar8 & 4) != 0) {
296: *(undefined4 *)puVar9 = 0;
297: puVar9 = (undefined8 *)((long)puVar9 + 4);
298: }
299: puVar10 = puVar9;
300: if ((uVar8 & 2) != 0) {
301: puVar10 = (undefined8 *)((long)puVar9 + 2);
302: *(undefined2 *)puVar9 = 0;
303: }
304: if (bVar12) {
305: *(undefined *)puVar10 = 0;
306: }
307: }
308: }
309: }
310: }
311: }
312: }
313: else {
314: lVar11 = 0;
315: if (param_2 == 0) {
316: do {
317: pcVar5 = param_1[lVar11 + 0x29];
318: *(undefined4 *)(pcVar3 + lVar11 * 4 + 0x58) = 0;
319: iVar4 = *(int *)(pcVar5 + 0x18);
320: *(int *)(pcVar3 + 0x68) = iVar4;
321: FUN_00111780(param_1,0,iVar4,pcVar3 + (long)iVar4 * 8 + 0x88);
322: iVar4 = (int)lVar11 + 1;
323: lVar11 = lVar11 + 1;
324: } while (*(int *)((long)param_1 + 0x144) != iVar4 &&
325: iVar4 <= *(int *)((long)param_1 + 0x144));
326: }
327: else {
328: do {
329: pcVar5 = param_1[lVar11 + 0x29];
330: *(undefined4 *)(pcVar3 + lVar11 * 4 + 0x58) = 0;
331: uVar1 = *(uint *)(pcVar5 + 0x18);
332: *(uint *)(pcVar3 + 0x68) = uVar1;
333: if (3 < uVar1) {
334: pcVar5 = *param_1;
335: *(uint *)(pcVar5 + 0x2c) = uVar1;
336: *(undefined4 *)(pcVar5 + 0x28) = 0x32;
337: (**(code **)*param_1)(param_1);
338: }
339: puVar10 = *(undefined8 **)(pcVar3 + (long)(int)uVar1 * 8 + 0xa8);
340: if (puVar10 == (undefined8 *)0x0) {
341: puVar10 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x808);
342: *(undefined8 **)(pcVar3 + (long)(int)uVar1 * 8 + 0xa8) = puVar10;
343: }
344: bVar12 = ((ulong)puVar10 & 1) != 0;
345: uVar8 = 0x808;
346: if (bVar12) {
347: *(undefined *)puVar10 = 0;
348: puVar10 = (undefined8 *)((long)puVar10 + 1);
349: uVar8 = 0x807;
350: }
351: puVar9 = puVar10;
352: if (((ulong)puVar10 & 2) != 0) {
353: puVar9 = (undefined8 *)((long)puVar10 + 2);
354: uVar8 = (ulong)((int)uVar8 - 2);
355: *(undefined2 *)puVar10 = 0;
356: }
357: if (((ulong)puVar9 & 4) != 0) {
358: *(undefined4 *)puVar9 = 0;
359: uVar8 = (ulong)((int)uVar8 - 4);
360: puVar9 = (undefined8 *)((long)puVar9 + 4);
361: }
362: uVar7 = uVar8 >> 3;
363: while (uVar7 != 0) {
364: uVar7 = uVar7 - 1;
365: *puVar9 = 0;
366: puVar9 = puVar9 + (ulong)bVar13 * -2 + 1;
367: }
368: if ((uVar8 & 4) != 0) {
369: *(undefined4 *)puVar9 = 0;
370: puVar9 = (undefined8 *)((long)puVar9 + 4);
371: }
372: puVar10 = puVar9;
373: if ((uVar8 & 2) != 0) {
374: puVar10 = (undefined8 *)((long)puVar9 + 2);
375: *(undefined2 *)puVar9 = 0;
376: }
377: if (bVar12) {
378: *(undefined *)puVar10 = 0;
379: }
380: iVar4 = (int)lVar11 + 1;
381: lVar11 = lVar11 + 1;
382: } while (*(int *)((long)param_1 + 0x144) != iVar4 &&
383: iVar4 <= *(int *)((long)param_1 + 0x144));
384: }
385: }
386: }
387: uVar2 = *(undefined4 *)(param_1 + 0x23);
388: *(undefined4 *)(pcVar3 + 0x6c) = 0;
389: *(undefined4 *)(pcVar3 + 0x70) = 0;
390: *(undefined8 *)(pcVar3 + 0x40) = 0;
391: *(undefined4 *)(pcVar3 + 0x48) = 0;
392: *(undefined4 *)(pcVar3 + 0x84) = 0;
393: *(undefined4 *)(pcVar3 + 0x80) = uVar2;
394: return;
395: }
396: 
