1: 
2: void FUN_00113040(code **param_1)
3: 
4: {
5: undefined uVar1;
6: ushort uVar2;
7: code *pcVar3;
8: undefined *puVar4;
9: long lVar5;
10: code **ppcVar6;
11: long *plVar7;
12: int iVar8;
13: undefined8 *puVar9;
14: 
15: puVar9 = (undefined8 *)param_1[5];
16: pcVar3 = param_1[0x3a];
17: puVar4 = (undefined *)*puVar9;
18: *puVar9 = puVar4 + 1;
19: *puVar4 = 0xff;
20: lVar5 = puVar9[1];
21: puVar9[1] = lVar5 + -1;
22: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(), iVar8 == 0)) {
23: ppcVar6 = (code **)*param_1;
24: *(undefined4 *)(ppcVar6 + 5) = 0x18;
25: (**ppcVar6)(param_1);
26: }
27: puVar9 = (undefined8 *)param_1[5];
28: puVar4 = (undefined *)*puVar9;
29: *puVar9 = puVar4 + 1;
30: *puVar4 = 0xd8;
31: lVar5 = puVar9[1];
32: puVar9[1] = lVar5 + -1;
33: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
34: ppcVar6 = (code **)*param_1;
35: *(undefined4 *)(ppcVar6 + 5) = 0x18;
36: (**ppcVar6)(param_1);
37: }
38: iVar8 = *(int *)(param_1 + 0x24);
39: *(undefined4 *)(pcVar3 + 0x38) = 0;
40: if (iVar8 != 0) {
41: puVar9 = (undefined8 *)param_1[5];
42: puVar4 = (undefined *)*puVar9;
43: *puVar9 = puVar4 + 1;
44: *puVar4 = 0xff;
45: lVar5 = puVar9[1];
46: puVar9[1] = lVar5 + -1;
47: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
48: ppcVar6 = (code **)*param_1;
49: *(undefined4 *)(ppcVar6 + 5) = 0x18;
50: (**ppcVar6)(param_1);
51: }
52: puVar9 = (undefined8 *)param_1[5];
53: puVar4 = (undefined *)*puVar9;
54: *puVar9 = puVar4 + 1;
55: *puVar4 = 0xe0;
56: lVar5 = puVar9[1];
57: puVar9[1] = lVar5 + -1;
58: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
59: ppcVar6 = (code **)*param_1;
60: *(undefined4 *)(ppcVar6 + 5) = 0x18;
61: (**ppcVar6)(param_1);
62: }
63: puVar9 = (undefined8 *)param_1[5];
64: puVar4 = (undefined *)*puVar9;
65: *puVar9 = puVar4 + 1;
66: *puVar4 = 0;
67: lVar5 = puVar9[1];
68: puVar9[1] = lVar5 + -1;
69: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
70: ppcVar6 = (code **)*param_1;
71: *(undefined4 *)(ppcVar6 + 5) = 0x18;
72: (**ppcVar6)(param_1);
73: }
74: puVar9 = (undefined8 *)param_1[5];
75: puVar4 = (undefined *)*puVar9;
76: *puVar9 = puVar4 + 1;
77: *puVar4 = 0x10;
78: lVar5 = puVar9[1];
79: puVar9[1] = lVar5 + -1;
80: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
81: ppcVar6 = (code **)*param_1;
82: *(undefined4 *)(ppcVar6 + 5) = 0x18;
83: (**ppcVar6)(param_1);
84: }
85: puVar9 = (undefined8 *)param_1[5];
86: puVar4 = (undefined *)*puVar9;
87: *puVar9 = puVar4 + 1;
88: *puVar4 = 0x4a;
89: lVar5 = puVar9[1];
90: puVar9[1] = lVar5 + -1;
91: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
92: ppcVar6 = (code **)*param_1;
93: *(undefined4 *)(ppcVar6 + 5) = 0x18;
94: (**ppcVar6)(param_1);
95: }
96: puVar9 = (undefined8 *)param_1[5];
97: puVar4 = (undefined *)*puVar9;
98: *puVar9 = puVar4 + 1;
99: *puVar4 = 0x46;
100: lVar5 = puVar9[1];
101: puVar9[1] = lVar5 + -1;
102: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
103: ppcVar6 = (code **)*param_1;
104: *(undefined4 *)(ppcVar6 + 5) = 0x18;
105: (**ppcVar6)(param_1);
106: }
107: puVar9 = (undefined8 *)param_1[5];
108: puVar4 = (undefined *)*puVar9;
109: *puVar9 = puVar4 + 1;
110: *puVar4 = 0x49;
111: lVar5 = puVar9[1];
112: puVar9[1] = lVar5 + -1;
113: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
114: ppcVar6 = (code **)*param_1;
115: *(undefined4 *)(ppcVar6 + 5) = 0x18;
116: (**ppcVar6)(param_1);
117: }
118: puVar9 = (undefined8 *)param_1[5];
119: puVar4 = (undefined *)*puVar9;
120: *puVar9 = puVar4 + 1;
121: *puVar4 = 0x46;
122: lVar5 = puVar9[1];
123: puVar9[1] = lVar5 + -1;
124: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
125: ppcVar6 = (code **)*param_1;
126: *(undefined4 *)(ppcVar6 + 5) = 0x18;
127: (**ppcVar6)(param_1);
128: }
129: puVar9 = (undefined8 *)param_1[5];
130: puVar4 = (undefined *)*puVar9;
131: *puVar9 = puVar4 + 1;
132: *puVar4 = 0;
133: lVar5 = puVar9[1];
134: puVar9[1] = lVar5 + -1;
135: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
136: ppcVar6 = (code **)*param_1;
137: *(undefined4 *)(ppcVar6 + 5) = 0x18;
138: (**ppcVar6)(param_1);
139: }
140: plVar7 = (long *)param_1[5];
141: uVar1 = *(undefined *)((long)param_1 + 0x124);
142: puVar4 = (undefined *)*plVar7;
143: *plVar7 = (long)(puVar4 + 1);
144: *puVar4 = uVar1;
145: lVar5 = plVar7[1];
146: plVar7[1] = lVar5 + -1;
147: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)plVar7[3])(param_1), iVar8 == 0)) {
148: ppcVar6 = (code **)*param_1;
149: *(undefined4 *)(ppcVar6 + 5) = 0x18;
150: (**ppcVar6)(param_1);
151: }
152: plVar7 = (long *)param_1[5];
153: uVar1 = *(undefined *)((long)param_1 + 0x125);
154: puVar4 = (undefined *)*plVar7;
155: *plVar7 = (long)(puVar4 + 1);
156: *puVar4 = uVar1;
157: lVar5 = plVar7[1];
158: plVar7[1] = lVar5 + -1;
159: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)plVar7[3])(param_1), iVar8 == 0)) {
160: ppcVar6 = (code **)*param_1;
161: *(undefined4 *)(ppcVar6 + 5) = 0x18;
162: (**ppcVar6)(param_1);
163: }
164: plVar7 = (long *)param_1[5];
165: uVar1 = *(undefined *)((long)param_1 + 0x126);
166: puVar4 = (undefined *)*plVar7;
167: *plVar7 = (long)(puVar4 + 1);
168: *puVar4 = uVar1;
169: lVar5 = plVar7[1];
170: plVar7[1] = lVar5 + -1;
171: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)plVar7[3])(param_1), iVar8 == 0)) {
172: ppcVar6 = (code **)*param_1;
173: *(undefined4 *)(ppcVar6 + 5) = 0x18;
174: (**ppcVar6)(param_1);
175: }
176: plVar7 = (long *)param_1[5];
177: uVar2 = *(ushort *)(param_1 + 0x25);
178: puVar4 = (undefined *)*plVar7;
179: *plVar7 = (long)(puVar4 + 1);
180: *puVar4 = (char)((ulong)uVar2 >> 8);
181: lVar5 = plVar7[1];
182: plVar7[1] = lVar5 + -1;
183: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)plVar7[3])(param_1), iVar8 == 0)) {
184: ppcVar6 = (code **)*param_1;
185: *(undefined4 *)(ppcVar6 + 5) = 0x18;
186: (**ppcVar6)(param_1);
187: }
188: plVar7 = (long *)param_1[5];
189: puVar4 = (undefined *)*plVar7;
190: *plVar7 = (long)(puVar4 + 1);
191: *puVar4 = (char)uVar2;
192: lVar5 = plVar7[1];
193: plVar7[1] = lVar5 + -1;
194: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)plVar7[3])(param_1), iVar8 == 0)) {
195: ppcVar6 = (code **)*param_1;
196: *(undefined4 *)(ppcVar6 + 5) = 0x18;
197: (**ppcVar6)(param_1);
198: }
199: plVar7 = (long *)param_1[5];
200: uVar2 = *(ushort *)((long)param_1 + 0x12a);
201: puVar4 = (undefined *)*plVar7;
202: *plVar7 = (long)(puVar4 + 1);
203: *puVar4 = (char)((ulong)uVar2 >> 8);
204: lVar5 = plVar7[1];
205: plVar7[1] = lVar5 + -1;
206: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)plVar7[3])(param_1), iVar8 == 0)) {
207: ppcVar6 = (code **)*param_1;
208: *(undefined4 *)(ppcVar6 + 5) = 0x18;
209: (**ppcVar6)(param_1);
210: }
211: plVar7 = (long *)param_1[5];
212: puVar4 = (undefined *)*plVar7;
213: *plVar7 = (long)(puVar4 + 1);
214: *puVar4 = (char)uVar2;
215: lVar5 = plVar7[1];
216: plVar7[1] = lVar5 + -1;
217: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)plVar7[3])(param_1), iVar8 == 0)) {
218: ppcVar6 = (code **)*param_1;
219: *(undefined4 *)(ppcVar6 + 5) = 0x18;
220: (**ppcVar6)(param_1);
221: }
222: puVar9 = (undefined8 *)param_1[5];
223: puVar4 = (undefined *)*puVar9;
224: *puVar9 = puVar4 + 1;
225: *puVar4 = 0;
226: lVar5 = puVar9[1];
227: puVar9[1] = lVar5 + -1;
228: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
229: ppcVar6 = (code **)*param_1;
230: *(undefined4 *)(ppcVar6 + 5) = 0x18;
231: (**ppcVar6)(param_1);
232: }
233: puVar9 = (undefined8 *)param_1[5];
234: puVar4 = (undefined *)*puVar9;
235: *puVar9 = puVar4 + 1;
236: *puVar4 = 0;
237: lVar5 = puVar9[1];
238: puVar9[1] = lVar5 + -1;
239: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
240: ppcVar6 = (code **)*param_1;
241: *(undefined4 *)(ppcVar6 + 5) = 0x18;
242: (**ppcVar6)(param_1);
243: }
244: }
245: if (*(int *)((long)param_1 + 300) == 0) {
246: return;
247: }
248: puVar9 = (undefined8 *)param_1[5];
249: puVar4 = (undefined *)*puVar9;
250: *puVar9 = puVar4 + 1;
251: *puVar4 = 0xff;
252: lVar5 = puVar9[1];
253: puVar9[1] = lVar5 + -1;
254: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
255: ppcVar6 = (code **)*param_1;
256: *(undefined4 *)(ppcVar6 + 5) = 0x18;
257: (**ppcVar6)(param_1);
258: }
259: puVar9 = (undefined8 *)param_1[5];
260: puVar4 = (undefined *)*puVar9;
261: *puVar9 = puVar4 + 1;
262: *puVar4 = 0xee;
263: lVar5 = puVar9[1];
264: puVar9[1] = lVar5 + -1;
265: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
266: ppcVar6 = (code **)*param_1;
267: *(undefined4 *)(ppcVar6 + 5) = 0x18;
268: (**ppcVar6)(param_1);
269: }
270: puVar9 = (undefined8 *)param_1[5];
271: puVar4 = (undefined *)*puVar9;
272: *puVar9 = puVar4 + 1;
273: *puVar4 = 0;
274: lVar5 = puVar9[1];
275: puVar9[1] = lVar5 + -1;
276: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
277: ppcVar6 = (code **)*param_1;
278: *(undefined4 *)(ppcVar6 + 5) = 0x18;
279: (**ppcVar6)(param_1);
280: }
281: puVar9 = (undefined8 *)param_1[5];
282: puVar4 = (undefined *)*puVar9;
283: *puVar9 = puVar4 + 1;
284: *puVar4 = 0xe;
285: lVar5 = puVar9[1];
286: puVar9[1] = lVar5 + -1;
287: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
288: ppcVar6 = (code **)*param_1;
289: *(undefined4 *)(ppcVar6 + 5) = 0x18;
290: (**ppcVar6)(param_1);
291: }
292: puVar9 = (undefined8 *)param_1[5];
293: puVar4 = (undefined *)*puVar9;
294: *puVar9 = puVar4 + 1;
295: *puVar4 = 0x41;
296: lVar5 = puVar9[1];
297: puVar9[1] = lVar5 + -1;
298: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
299: ppcVar6 = (code **)*param_1;
300: *(undefined4 *)(ppcVar6 + 5) = 0x18;
301: (**ppcVar6)(param_1);
302: }
303: puVar9 = (undefined8 *)param_1[5];
304: puVar4 = (undefined *)*puVar9;
305: *puVar9 = puVar4 + 1;
306: *puVar4 = 100;
307: lVar5 = puVar9[1];
308: puVar9[1] = lVar5 + -1;
309: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
310: ppcVar6 = (code **)*param_1;
311: *(undefined4 *)(ppcVar6 + 5) = 0x18;
312: (**ppcVar6)(param_1);
313: }
314: puVar9 = (undefined8 *)param_1[5];
315: puVar4 = (undefined *)*puVar9;
316: *puVar9 = puVar4 + 1;
317: *puVar4 = 0x6f;
318: lVar5 = puVar9[1];
319: puVar9[1] = lVar5 + -1;
320: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
321: ppcVar6 = (code **)*param_1;
322: *(undefined4 *)(ppcVar6 + 5) = 0x18;
323: (**ppcVar6)(param_1);
324: }
325: puVar9 = (undefined8 *)param_1[5];
326: puVar4 = (undefined *)*puVar9;
327: *puVar9 = puVar4 + 1;
328: *puVar4 = 0x62;
329: lVar5 = puVar9[1];
330: puVar9[1] = lVar5 + -1;
331: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
332: ppcVar6 = (code **)*param_1;
333: *(undefined4 *)(ppcVar6 + 5) = 0x18;
334: (**ppcVar6)(param_1);
335: }
336: puVar9 = (undefined8 *)param_1[5];
337: puVar4 = (undefined *)*puVar9;
338: *puVar9 = puVar4 + 1;
339: *puVar4 = 0x65;
340: lVar5 = puVar9[1];
341: puVar9[1] = lVar5 + -1;
342: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
343: ppcVar6 = (code **)*param_1;
344: *(undefined4 *)(ppcVar6 + 5) = 0x18;
345: (**ppcVar6)(param_1);
346: }
347: puVar9 = (undefined8 *)param_1[5];
348: puVar4 = (undefined *)*puVar9;
349: *puVar9 = puVar4 + 1;
350: *puVar4 = 0;
351: lVar5 = puVar9[1];
352: puVar9[1] = lVar5 + -1;
353: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
354: ppcVar6 = (code **)*param_1;
355: *(undefined4 *)(ppcVar6 + 5) = 0x18;
356: (**ppcVar6)(param_1);
357: }
358: puVar9 = (undefined8 *)param_1[5];
359: puVar4 = (undefined *)*puVar9;
360: *puVar9 = puVar4 + 1;
361: *puVar4 = 100;
362: lVar5 = puVar9[1];
363: puVar9[1] = lVar5 + -1;
364: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
365: ppcVar6 = (code **)*param_1;
366: *(undefined4 *)(ppcVar6 + 5) = 0x18;
367: (**ppcVar6)(param_1);
368: }
369: puVar9 = (undefined8 *)param_1[5];
370: puVar4 = (undefined *)*puVar9;
371: *puVar9 = puVar4 + 1;
372: *puVar4 = 0;
373: lVar5 = puVar9[1];
374: puVar9[1] = lVar5 + -1;
375: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
376: ppcVar6 = (code **)*param_1;
377: *(undefined4 *)(ppcVar6 + 5) = 0x18;
378: (**ppcVar6)(param_1);
379: }
380: puVar9 = (undefined8 *)param_1[5];
381: puVar4 = (undefined *)*puVar9;
382: *puVar9 = puVar4 + 1;
383: *puVar4 = 0;
384: lVar5 = puVar9[1];
385: puVar9[1] = lVar5 + -1;
386: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
387: ppcVar6 = (code **)*param_1;
388: *(undefined4 *)(ppcVar6 + 5) = 0x18;
389: (**ppcVar6)(param_1);
390: }
391: puVar9 = (undefined8 *)param_1[5];
392: puVar4 = (undefined *)*puVar9;
393: *puVar9 = puVar4 + 1;
394: *puVar4 = 0;
395: lVar5 = puVar9[1];
396: puVar9[1] = lVar5 + -1;
397: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
398: ppcVar6 = (code **)*param_1;
399: *(undefined4 *)(ppcVar6 + 5) = 0x18;
400: (**ppcVar6)(param_1);
401: }
402: puVar9 = (undefined8 *)param_1[5];
403: puVar4 = (undefined *)*puVar9;
404: *puVar9 = puVar4 + 1;
405: *puVar4 = 0;
406: lVar5 = puVar9[1];
407: puVar9[1] = lVar5 + -1;
408: if ((lVar5 + -1 == 0) && (iVar8 = (*(code *)puVar9[3])(param_1), iVar8 == 0)) {
409: ppcVar6 = (code **)*param_1;
410: *(undefined4 *)(ppcVar6 + 5) = 0x18;
411: (**ppcVar6)(param_1);
412: }
413: if (*(int *)(param_1 + 10) == 3) {
414: puVar9 = (undefined8 *)param_1[5];
415: puVar4 = (undefined *)*puVar9;
416: *puVar9 = puVar4 + 1;
417: *puVar4 = 1;
418: }
419: else {
420: if (*(int *)(param_1 + 10) == 5) {
421: puVar9 = (undefined8 *)param_1[5];
422: puVar4 = (undefined *)*puVar9;
423: *puVar9 = puVar4 + 1;
424: *puVar4 = 2;
425: lVar5 = puVar9[1];
426: puVar9[1] = lVar5 + -1;
427: if (lVar5 + -1 != 0) {
428: return;
429: }
430: goto LAB_00113355;
431: }
432: puVar9 = (undefined8 *)param_1[5];
433: puVar4 = (undefined *)*puVar9;
434: *puVar9 = puVar4 + 1;
435: *puVar4 = 0;
436: }
437: lVar5 = puVar9[1];
438: puVar9[1] = lVar5 + -1;
439: if (lVar5 + -1 != 0) {
440: return;
441: }
442: LAB_00113355:
443: iVar8 = (*(code *)puVar9[3])(param_1);
444: if (iVar8 != 0) {
445: return;
446: }
447: ppcVar6 = (code **)*param_1;
448: *(undefined4 *)(ppcVar6 + 5) = 0x18;
449: /* WARNING: Could not recover jumptable at 0x00113379. Too many branches */
450: /* WARNING: Treating indirect jump as call */
451: (**ppcVar6)(param_1);
452: return;
453: }
454: 
