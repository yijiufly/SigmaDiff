1: 
2: uint FUN_00125c50(code **param_1,uint param_2)
3: 
4: {
5: int iVar1;
6: code *pcVar2;
7: code *pcVar3;
8: code *pcVar4;
9: code *pcVar5;
10: code **ppcVar6;
11: long lVar7;
12: bool bVar8;
13: int iVar9;
14: uint uVar10;
15: int iVar11;
16: uint uVar12;
17: code *pcVar13;
18: long lVar14;
19: uint uVar15;
20: undefined8 *puVar16;
21: int iVar17;
22: uint uVar18;
23: undefined **ppuVar19;
24: code *pcVar20;
25: int iVar21;
26: undefined8 *puVar22;
27: uint uVar23;
28: long lVar24;
29: long lVar25;
30: uint uVar26;
31: int iVar27;
32: long lVar28;
33: long lVar29;
34: long in_FS_OFFSET;
35: uint uStack144;
36: code *pcStack128;
37: int iStack116;
38: undefined *puStack80;
39: undefined uStack65;
40: long lStack64;
41: 
42: pcVar2 = param_1[0x45];
43: pcVar3 = param_1[0x46];
44: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
45: pcVar4 = param_1[0x44];
46: pcVar5 = param_1[0x4c];
47: if ((*(int *)((long)param_1 + 0x6c) != 0) && (*(int *)((long)param_1 + 0x74) != 0)) {
48: ppcVar6 = (code **)*param_1;
49: *(undefined4 *)(ppcVar6 + 5) = 0x2f;
50: (**ppcVar6)();
51: }
52: iVar21 = *(int *)((long)param_1 + 0x24);
53: if (iVar21 != 0xcd) {
54: ppcVar6 = (code **)*param_1;
55: *(undefined4 *)(ppcVar6 + 5) = 0x14;
56: *(int *)((long)ppcVar6 + 0x2c) = iVar21;
57: (**ppcVar6)();
58: }
59: uVar23 = *(uint *)(param_1 + 0x15);
60: uVar12 = *(uint *)((long)param_1 + 0x8c);
61: if (uVar12 <= uVar23 + param_2) {
62: *(uint *)(param_1 + 0x15) = uVar12;
63: (**(code **)(param_1[0x48] + 0x18))(param_1);
64: *(undefined4 *)(param_1[0x48] + 0x24) = 1;
65: uVar18 = uVar12 - uVar23;
66: goto LAB_00125d0c;
67: }
68: uVar18 = 0;
69: if (param_2 == 0) goto LAB_00125d0c;
70: iVar21 = *(int *)((long)param_1 + 0x19c);
71: iVar17 = *(int *)(param_1 + 0x34);
72: uVar10 = iVar17 * iVar21;
73: uVar15 = (uVar10 - uVar23 % uVar10) % uVar10;
74: pcStack128 = param_1[0x4c];
75: uVar26 = param_2 - uVar15;
76: uVar18 = param_2;
77: if (*(int *)(pcStack128 + 0x10) == 0) {
78: if (param_2 < uVar15) {
79: FUN_00125a60(param_1,param_2);
80: goto LAB_00125d0c;
81: }
82: iVar11 = uVar23 + uVar15;
83: *(int *)(param_1 + 0x15) = iVar11;
84: *(undefined8 *)(pcVar2 + 0x60) = 0;
85: if (*(int *)(pcVar4 + 0x7c) == 0) {
86: *(int *)(pcVar5 + 0xb8) = iVar21;
87: *(uint *)(pcVar5 + 0xbc) = uVar12 - iVar11;
88: }
89: uStack144 = (uVar26 / uVar10) * uVar10;
90: iStack116 = (int)((ulong)uVar26 % (ulong)uVar10);
91: if (*(int *)(param_1[0x48] + 0x20) == 0) goto LAB_00125ff1;
92: *(uint *)(param_1 + 0x15) = iVar11 + uStack144;
93: *(uint *)(param_1 + 0x17) = *(int *)(param_1 + 0x17) + uStack144 / uVar10;
94: FUN_00125a60(param_1,(ulong)uVar26 % (ulong)uVar10,(ulong)uStack144 % (ulong)uVar10);
95: }
96: else {
97: if (param_2 < uVar15 + 1) {
98: LAB_00126254:
99: puStack80 = &uStack65;
100: pcVar2 = param_1[0x44];
101: uStack65 = 0;
102: pcVar3 = param_1[0x4d];
103: if (pcVar3 == (code *)0x0) {
104: lVar29 = 0;
105: ppuVar19 = (undefined **)0x0;
106: }
107: else {
108: lVar29 = *(long *)(pcVar3 + 8);
109: ppuVar19 = (undefined **)0x0;
110: if (lVar29 != 0) {
111: ppuVar19 = &puStack80;
112: *(code **)(pcVar3 + 8) = FUN_00125620;
113: }
114: }
115: pcVar3 = param_1[0x4e];
116: lVar25 = 0;
117: if ((pcVar3 != (code *)0x0) && (lVar25 = *(long *)(pcVar3 + 8), lVar25 != 0)) {
118: *(code **)(pcVar3 + 8) = FUN_00125630;
119: }
120: if ((*(int *)(pcVar2 + 0x7c) != 0) && (iVar21 == 2)) {
121: ppuVar19 = (undefined **)(pcStack128 + 0x40);
122: }
123: uVar18 = 0;
124: do {
125: uVar18 = uVar18 + 1;
126: FUN_00125990(param_1,ppuVar19,1);
127: } while (param_2 != uVar18);
128: if (lVar29 != 0) {
129: *(long *)(param_1[0x4d] + 8) = lVar29;
130: }
131: if (lVar25 != 0) {
132: *(long *)(param_1[0x4e] + 8) = lVar25;
133: }
134: goto LAB_00125d0c;
135: }
136: if ((uVar15 < 2) && (*(int *)(pcVar2 + 0x60) != 0)) {
137: if (uVar26 < uVar10 + 1) goto LAB_00126254;
138: uVar23 = uVar23 + uVar10;
139: uVar26 = uVar26 - uVar10;
140: }
141: iVar11 = uVar23 + uVar15;
142: *(int *)(param_1 + 0x15) = iVar11;
143: iVar1 = *(int *)(pcVar2 + 0x84);
144: if ((iVar1 == 0) || ((iVar1 == 1 && (2 < uVar15)))) {
145: pcVar20 = param_1[0x26];
146: if (0 < *(int *)(param_1 + 7)) {
147: lVar29 = *(long *)(param_1[0x45] + 0x68);
148: lVar25 = *(long *)(param_1[0x45] + 0x70);
149: lVar14 = 0;
150: pcVar13 = pcVar20 + ((ulong)(*(int *)(param_1 + 7) - 1) * 3 + 3) * 0x20;
151: do {
152: lVar7 = *(long *)(lVar29 + lVar14);
153: iVar9 = (*(int *)(pcVar20 + 0xc) * *(int *)(pcVar20 + 0x24)) / iVar17;
154: if (0 < iVar9) {
155: iVar27 = (iVar17 + 1) * iVar9;
156: lVar28 = (long)iVar27;
157: puVar16 = (undefined8 *)(lVar7 + lVar28 * 8);
158: puVar22 = (undefined8 *)(lVar28 * 8 + *(long *)(lVar25 + lVar14));
159: lVar24 = (iVar9 + iVar27) - lVar28;
160: do {
161: puVar16[-iVar9 - lVar28] = *puVar16;
162: puVar22[-iVar9 - lVar28] = *puVar22;
163: puVar16[lVar24] = puVar16[-lVar28];
164: puVar16 = puVar16 + 1;
165: puVar22[lVar24] = puVar22[-lVar28];
166: puVar22 = puVar22 + 1;
167: } while (puVar16 != (undefined8 *)(lVar7 + 8 + ((ulong)(iVar9 - 1) + lVar28) * 8));
168: }
169: pcVar20 = pcVar20 + 0x60;
170: lVar14 = lVar14 + 8;
171: } while (pcVar20 != pcVar13);
172: }
173: }
174: *(undefined8 *)(pcVar2 + 0x60) = 0;
175: *(undefined4 *)(pcVar2 + 0x7c) = 0;
176: if (*(int *)(pcVar4 + 0x7c) == 0) {
177: *(uint *)(pcVar5 + 0xbc) = uVar12 - iVar11;
178: *(int *)(pcVar5 + 0xb8) = iVar21;
179: }
180: uStack144 = ((uVar26 - 1) / uVar10) * uVar10;
181: iStack116 = uVar26 - uStack144;
182: if (*(int *)(param_1[0x48] + 0x20) == 0) {
183: LAB_00125ff1:
184: uVar23 = uVar10;
185: if (uStack144 != 0) {
186: do {
187: iVar21 = *(int *)(pcVar3 + 0x30);
188: if (0 < iVar21) {
189: uVar12 = *(uint *)(param_1 + 0x3b);
190: iVar17 = 0;
191: do {
192: if (uVar12 == 0) {
193: iVar17 = iVar17 + 1;
194: if (iVar21 <= iVar17) break;
195: }
196: else {
197: uVar15 = 0;
198: do {
199: pcVar20 = param_1[0x4a];
200: if (*(int *)(pcVar20 + 0x10) == 0) {
201: *(undefined4 *)(param_1[0x44] + 0x70) = *(undefined4 *)(param_1 + 0x16);
202: }
203: uVar15 = uVar15 + 1;
204: (**(code **)(pcVar20 + 8))();
205: uVar12 = *(uint *)(param_1 + 0x3b);
206: } while (uVar15 < uVar12);
207: iVar21 = *(int *)(pcVar3 + 0x30);
208: }
209: iVar17 = iVar17 + 1;
210: } while (iVar17 < iVar21);
211: }
212: *(int *)(param_1 + 0x17) = *(int *)(param_1 + 0x17) + 1;
213: uVar12 = *(int *)(param_1 + 0x16) + 1;
214: *(uint *)(param_1 + 0x16) = uVar12;
215: if (uVar12 < *(uint *)((long)param_1 + 0x1a4)) {
216: pcVar20 = param_1[0x46];
217: if (*(int *)(param_1 + 0x36) < 2) {
218: if (uVar12 < *(uint *)((long)param_1 + 0x1a4) - 1) {
219: *(undefined4 *)(pcVar20 + 0x30) = *(undefined4 *)(param_1[0x37] + 0xc);
220: }
221: else {
222: *(undefined4 *)(pcVar20 + 0x30) = *(undefined4 *)(param_1[0x37] + 0x48);
223: }
224: }
225: else {
226: *(undefined4 *)(pcVar20 + 0x30) = 1;
227: }
228: *(undefined8 *)(pcVar20 + 0x28) = 0;
229: }
230: else {
231: (**(code **)(param_1[0x48] + 0x18))();
232: }
233: bVar8 = uVar23 < uStack144;
234: uVar23 = uVar10 + uVar23;
235: } while (bVar8);
236: iVar11 = *(int *)(param_1 + 0x15);
237: pcStack128 = param_1[0x4c];
238: }
239: *(uint *)(param_1 + 0x15) = iVar11 + uStack144;
240: if (*(int *)(pcStack128 + 0x10) == 0) {
241: FUN_00125a60(param_1);
242: }
243: else {
244: pcVar3 = param_1[0x44];
245: *(uint *)(pcVar2 + 0x84) = *(int *)(pcVar2 + 0x84) + uStack144 / uVar10;
246: puStack80 = &uStack65;
247: uStack65 = 0;
248: pcVar2 = param_1[0x4d];
249: if (pcVar2 == (code *)0x0) {
250: lVar29 = 0;
251: ppuVar19 = (undefined **)0x0;
252: }
253: else {
254: lVar29 = *(long *)(pcVar2 + 8);
255: ppuVar19 = (undefined **)0x0;
256: if (lVar29 != 0) {
257: ppuVar19 = &puStack80;
258: *(code **)(pcVar2 + 8) = FUN_00125620;
259: }
260: }
261: pcVar2 = param_1[0x4e];
262: lVar25 = 0;
263: if ((pcVar2 != (code *)0x0) && (lVar25 = *(long *)(pcVar2 + 8), lVar25 != 0)) {
264: *(code **)(pcVar2 + 8) = FUN_00125630;
265: }
266: if ((*(int *)(pcVar3 + 0x7c) != 0) && (*(int *)((long)param_1 + 0x19c) == 2)) {
267: ppuVar19 = (undefined **)(pcStack128 + 0x40);
268: }
269: if (iStack116 != 0) {
270: iVar21 = 0;
271: do {
272: iVar21 = iVar21 + 1;
273: FUN_00125990(param_1,ppuVar19,1);
274: } while (iStack116 != iVar21);
275: }
276: if (lVar29 != 0) {
277: *(long *)(param_1[0x4d] + 8) = lVar29;
278: }
279: if (lVar25 != 0) {
280: *(long *)(param_1[0x4e] + 8) = lVar25;
281: }
282: }
283: if (*(int *)(pcVar4 + 0x7c) == 0) {
284: *(int *)(pcVar5 + 0xbc) = *(int *)((long)param_1 + 0x8c) - *(int *)(param_1 + 0x15);
285: }
286: goto LAB_00125d0c;
287: }
288: *(uint *)(param_1 + 0x15) = iVar11 + uStack144;
289: pcVar3 = param_1[0x44];
290: *(uint *)(param_1 + 0x17) = *(int *)(param_1 + 0x17) + uStack144 / uVar10;
291: *(uint *)(pcVar2 + 0x84) = uStack144 / uVar10 + iVar1;
292: puStack80 = &uStack65;
293: uStack65 = 0;
294: pcVar2 = param_1[0x4d];
295: if (pcVar2 == (code *)0x0) {
296: lVar29 = 0;
297: ppuVar19 = (undefined **)0x0;
298: }
299: else {
300: lVar29 = *(long *)(pcVar2 + 8);
301: ppuVar19 = (undefined **)0x0;
302: if (lVar29 != 0) {
303: ppuVar19 = &puStack80;
304: *(code **)(pcVar2 + 8) = FUN_00125620;
305: }
306: }
307: pcVar2 = param_1[0x4e];
308: lVar25 = 0;
309: if ((pcVar2 != (code *)0x0) && (lVar25 = *(long *)(pcVar2 + 8), lVar25 != 0)) {
310: *(code **)(pcVar2 + 8) = FUN_00125630;
311: }
312: if ((*(int *)(pcVar3 + 0x7c) != 0) && (iVar21 == 2)) {
313: ppuVar19 = (undefined **)(pcStack128 + 0x40);
314: }
315: if (iStack116 != 0) {
316: iVar21 = 0;
317: do {
318: iVar21 = iVar21 + 1;
319: FUN_00125990(param_1,ppuVar19,1);
320: } while (iVar21 != iStack116);
321: }
322: if (lVar29 != 0) {
323: *(long *)(param_1[0x4d] + 8) = lVar29;
324: }
325: if (lVar25 != 0) {
326: *(long *)(param_1[0x4e] + 8) = lVar25;
327: }
328: }
329: if (*(int *)(pcVar4 + 0x7c) == 0) {
330: *(int *)(pcVar5 + 0xbc) = *(int *)((long)param_1 + 0x8c) - *(int *)(param_1 + 0x15);
331: }
332: LAB_00125d0c:
333: if (lStack64 != *(long *)(in_FS_OFFSET + 0x28)) {
334: /* WARNING: Subroutine does not return */
335: __stack_chk_fail();
336: }
337: return uVar18;
338: }
339: 
