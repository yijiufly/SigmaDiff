1: 
2: undefined4
3: tjCompress2(long param_1,long param_2,int param_3,int param_4,int param_5,uint param_6,long param_7,
4: undefined8 *param_8,uint param_9,uint param_10,uint param_11)
5: 
6: {
7: bool bVar1;
8: int iVar2;
9: undefined4 uVar3;
10: undefined8 uVar4;
11: undefined8 *puVar5;
12: long *plVar6;
13: undefined4 *puVar7;
14: uint uVar8;
15: uint uVar9;
16: long lVar10;
17: ulong uVar11;
18: uint uVar12;
19: int iVar13;
20: uint uVar14;
21: int iVar15;
22: ulong uVar16;
23: ulong uVar17;
24: int iVar18;
25: int iVar20;
26: int iVar21;
27: undefined auVar19 [16];
28: int iVar22;
29: uint uVar23;
30: undefined4 uStack228;
31: long *plStack224;
32: int iStack168;
33: uint uStack84;
34: 
35: if (param_1 == 0) {
36: puVar5 = (undefined8 *)__tls_get_addr(&PTR_00398fc0);
37: *puVar5 = 0x2064696c61766e49;
38: *(undefined4 *)(puVar5 + 1) = 0x646e6168;
39: *(undefined2 *)((long)puVar5 + 0xc) = 0x656c;
40: *(undefined *)((long)puVar5 + 0xe) = 0;
41: return 0xffffffff;
42: }
43: *(undefined4 *)(param_1 + 0x5f8) = 0;
44: *(undefined4 *)(param_1 + 0x6d0) = 0;
45: *(uint *)(param_1 + 0x5fc) = (int)param_11 >> 0xd & 1;
46: uStack84 = *(uint *)(param_1 + 0x600) & 1;
47: if (uStack84 == 0) {
48: *(undefined *)(param_1 + 0x648) = 0;
49: *(undefined4 *)(param_1 + 0x6d0) = 1;
50: *(undefined8 *)(param_1 + 0x608) = 0x6572706d6f436a74;
51: *(undefined8 *)(param_1 + 0x610) = 0x49203a2928327373;
52: *(undefined8 *)(param_1 + 0x618) = 0x2065636e6174736e;
53: *(undefined8 *)(param_1 + 0x620) = 0x20746f6e20736168;
54: *(undefined8 *)(param_1 + 0x628) = 0x696e69206e656562;
55: *(undefined8 *)(param_1 + 0x630) = 0x64657a696c616974;
56: *(undefined8 *)(param_1 + 0x638) = 0x6d6f6320726f6620;
57: *(undefined8 *)(param_1 + 0x640) = 0x6e6f697373657270;
58: puVar7 = (undefined4 *)
59: __tls_get_addr(0x6d6f6320726f6620,0x696e69206e656562,0x2065636e6174736e,
60: 0x6572706d6f436a74,&PTR_00398fc0);
61: *(undefined *)(puVar7 + 0x10) = 0;
62: *puVar7 = 0x6f436a74;
63: puVar7[1] = 0x6572706d;
64: puVar7[2] = 0x28327373;
65: puVar7[3] = 0x49203a29;
66: puVar7[4] = 0x6174736e;
67: puVar7[5] = 0x2065636e;
68: puVar7[6] = 0x20736168;
69: puVar7[7] = 0x20746f6e;
70: puVar7[8] = 0x6e656562;
71: puVar7[9] = 0x696e6920;
72: puVar7[10] = 0x6c616974;
73: puVar7[0xb] = 0x64657a69;
74: puVar7[0xc] = 0x726f6620;
75: puVar7[0xd] = 0x6d6f6320;
76: puVar7[0xe] = 0x73657270;
77: puVar7[0xf] = 0x6e6f6973;
78: LAB_0014f752:
79: plStack224 = (long *)0x0;
80: uStack228 = 0xffffffff;
81: if (*(int *)(param_1 + 0x24) < 0x65) goto LAB_0014f76d;
82: LAB_0014f7f8:
83: (**(code **)(*(long *)(param_1 + 0x28) + 0x20))(param_1);
84: }
85: else {
86: if ((((((param_2 == 0) || (param_3 < 1)) || (param_4 < 0)) || ((param_5 < 1 || (0xb < param_6)))
87: ) || ((param_7 == 0 || ((param_8 == (undefined8 *)0x0 || (100 < param_10)))))) ||
88: (5 < param_9)) {
89: *(undefined4 *)(param_1 + 0x6d0) = 1;
90: *(undefined8 *)(param_1 + 0x608) = 0x6572706d6f436a74;
91: *(undefined8 *)(param_1 + 0x610) = 0x49203a2928327373;
92: *(undefined8 *)(param_1 + 0x618) = 0x612064696c61766e;
93: *(undefined8 *)(param_1 + 0x620) = 0x746e656d756772;
94: puVar7 = (undefined4 *)__tls_get_addr(0x612064696c61766e,0x6572706d6f436a74,&PTR_00398fc0);
95: *puVar7 = 0x6f436a74;
96: puVar7[1] = 0x6572706d;
97: puVar7[2] = 0x28327373;
98: puVar7[3] = 0x49203a29;
99: puVar7[4] = 0x6c61766e;
100: puVar7[5] = 0x61206469;
101: puVar7[6] = 0x6d756772;
102: puVar7[7] = 0x746e65;
103: goto LAB_0014f752;
104: }
105: iStack168 = param_4;
106: if (param_4 == 0) {
107: iStack168 = param_3 * *(int *)(&DAT_0018fd80 + (long)(int)param_6 * 4);
108: }
109: plStack224 = (long *)malloc((long)param_5 << 3);
110: if (plStack224 == (long *)0x0) {
111: *(undefined8 *)(param_1 + 0x628) = 0x6572756c69616620;
112: *(undefined *)(param_1 + 0x630) = 0;
113: *(undefined8 *)(param_1 + 0x608) = 0x6572706d6f436a74;
114: *(undefined8 *)(param_1 + 0x610) = 0x4d203a2928327373;
115: *(undefined4 *)(param_1 + 0x6d0) = 1;
116: *(undefined8 *)(param_1 + 0x618) = 0x6c612079726f6d65;
117: *(undefined8 *)(param_1 + 0x620) = 0x6e6f697461636f6c;
118: puVar7 = (undefined4 *)__tls_get_addr(0x6c612079726f6d65,0x6572706d6f436a74,&PTR_00398fc0);
119: *(undefined8 *)(puVar7 + 8) = 0x6572756c69616620;
120: *(undefined *)(puVar7 + 10) = 0;
121: *puVar7 = 0x6f436a74;
122: puVar7[1] = 0x6572706d;
123: puVar7[2] = 0x28327373;
124: puVar7[3] = 0x4d203a29;
125: puVar7[4] = 0x726f6d65;
126: puVar7[5] = 0x6c612079;
127: puVar7[6] = 0x61636f6c;
128: puVar7[7] = 0x6e6f6974;
129: goto LAB_0014f752;
130: }
131: uStack228 = 0;
132: iVar2 = _setjmp((__jmp_buf_tag *)(param_1 + 0x528));
133: if (iVar2 == 0) {
134: *(int *)(param_1 + 0x30) = param_3;
135: *(int *)(param_1 + 0x34) = param_5;
136: if ((param_11 & 8) == 0) {
137: if ((param_11 & 0x10) == 0) {
138: if ((param_11 & 0x20) != 0) {
139: putenv("JSIMD_FORCESSE2=1");
140: }
141: }
142: else {
143: putenv("JSIMD_FORCESSE=1");
144: }
145: }
146: else {
147: putenv("JSIMD_FORCEMMX=1");
148: }
149: if ((param_11 & 0x400) != 0) {
150: uStack84 = 0;
151: uVar4 = tjBufSize(param_3,param_5,param_9);
152: *param_8 = uVar4;
153: }
154: FUN_00166fe0(param_1,param_7,param_8);
155: FUN_0014e450(param_1,param_6,param_9);
156: FUN_00103000(param_1,1);
157: if (0 < param_5) {
158: uVar11 = SEXT48(iStack168);
159: param_11 = param_11 & 2;
160: uVar23 = iStack168 >> 0x1f;
161: if (param_11 == 0) {
162: uVar9 = (uint)((ulong)plStack224 >> 3) & 1;
163: if (4 < param_5 - 1U) {
164: if (((ulong)plStack224 >> 3 & 1) != 0) {
165: *plStack224 = param_2;
166: param_11 = 1;
167: }
168: uVar12 = param_5 - uVar9;
169: auVar19 = CONCAT412(param_11 + 3,CONCAT48(param_11 + 2,CONCAT44(param_11 + 1,param_11)))
170: ;
171: uVar8 = 0;
172: plVar6 = plStack224 + uVar9;
173: do {
174: uVar8 = uVar8 + 1;
175: iVar2 = SUB164(auVar19 >> 0x20,0);
176: uVar9 = SUB164(auVar19 >> 0x40,0);
177: iVar18 = SUB164(auVar19 >> 0x60,0);
178: bVar1 = auVar19 < (undefined  [16])0x0;
179: uVar16 = SUB168(CONCAT412(-(uint)(iVar2 < 0),CONCAT48(iVar2,SUB168(auVar19,0))) >>
180: 0x40,0);
181: uVar17 = SUB168(auVar19,0) & 0xffffffff;
182: *plVar6 = ((ulong)-(uint)(SUB164(auVar19,0) < 0) * (uVar11 & 0xffffffff) +
183: uVar17 * uVar23 << 0x20) + uVar17 * (uVar11 & 0xffffffff) + param_2;
184: plVar6[1] = ((uVar16 >> 0x20) * (uVar11 & 0xffffffff) +
185: (uVar16 & 0xffffffff) * (ulong)uVar23 << 0x20) +
186: (uVar16 & 0xffffffff) * (uVar11 & 0xffffffff) + param_2;
187: auVar19 = CONCAT412(iVar18 + 4,
188: CONCAT48(uVar9 + 4,CONCAT44(iVar2 + 4,SUB164(auVar19,0) + 4)));
189: uVar17 = SUB168(CONCAT412(-(uint)bVar1,
190: CONCAT48(iVar18,CONCAT44(-(uint)((int)uVar9 < 0),uVar9))) >>
191: 0x40,0);
192: plVar6[2] = ((ulong)-(uint)((int)uVar9 < 0) * (uVar11 & 0xffffffff) +
193: (ulong)uVar9 * (ulong)uVar23 << 0x20) +
194: (ulong)uVar9 * (uVar11 & 0xffffffff) + param_2;
195: plVar6[3] = ((uVar17 >> 0x20) * (uVar11 & 0xffffffff) +
196: (uVar17 & 0xffffffff) * (ulong)uVar23 << 0x20) +
197: (uVar17 & 0xffffffff) * (uVar11 & 0xffffffff) + param_2;
198: plVar6 = plVar6 + 4;
199: } while (uVar8 < uVar12 >> 2);
200: param_11 = param_11 + (uVar12 & 0xfffffffc);
201: if (uVar12 == (uVar12 & 0xfffffffc)) goto LAB_0014f7c5;
202: }
203: lVar10 = uVar11 * (long)(int)param_11;
204: plStack224[(int)param_11] = param_2 + lVar10;
205: if ((int)(param_11 + 1) < param_5) {
206: lVar10 = lVar10 + uVar11;
207: plStack224[(int)(param_11 + 1)] = param_2 + lVar10;
208: if ((int)(param_11 + 2) < param_5) {
209: lVar10 = lVar10 + uVar11;
210: plStack224[(int)(param_11 + 2)] = param_2 + lVar10;
211: if ((int)(param_11 + 3) < param_5) {
212: lVar10 = lVar10 + uVar11;
213: plStack224[(int)(param_11 + 3)] = param_2 + lVar10;
214: if ((int)(param_11 + 4) < param_5) {
215: plStack224[(int)(param_11 + 4)] = lVar10 + uVar11 + param_2;
216: }
217: }
218: }
219: }
220: }
221: else {
222: uVar9 = (uint)((ulong)plStack224 >> 3) & 1;
223: if (4 < param_5 - 1U) {
224: if (((ulong)plStack224 >> 3 & 1) != 0) {
225: iVar2 = 1;
226: *plStack224 = (long)(int)(param_5 - 1U) * uVar11 + param_2;
227: }
228: uVar12 = param_5 - uVar9;
229: iVar20 = iVar2 + 1;
230: iVar21 = iVar2 + 2;
231: iVar22 = iVar2 + 3;
232: uVar8 = 0;
233: plVar6 = plStack224 + uVar9;
234: iVar18 = iVar2;
235: do {
236: uVar8 = uVar8 + 1;
237: uVar9 = (param_5 - iVar18) - 1;
238: iVar13 = (param_5 - iVar20) + -1;
239: uVar14 = (param_5 - iVar21) - 1;
240: iVar15 = (param_5 - iVar22) + -1;
241: iVar18 = iVar18 + 4;
242: iVar20 = iVar20 + 4;
243: iVar21 = iVar21 + 4;
244: iVar22 = iVar22 + 4;
245: uVar17 = SUB168(CONCAT412(-(uint)(iVar13 < 0),CONCAT48(iVar13,CONCAT44(iVar13,uVar9)))
246: >> 0x40,0);
247: *plVar6 = ((ulong)-(uint)((int)uVar9 < 0) * (uVar11 & 0xffffffff) +
248: (ulong)uVar9 * (ulong)uVar23 << 0x20) +
249: (ulong)uVar9 * (uVar11 & 0xffffffff) + param_2;
250: plVar6[1] = ((uVar17 >> 0x20) * (uVar11 & 0xffffffff) +
251: (uVar17 & 0xffffffff) * (ulong)uVar23 << 0x20) +
252: (uVar17 & 0xffffffff) * (uVar11 & 0xffffffff) + param_2;
253: uVar17 = SUB168(CONCAT412(-(uint)(iVar15 < 0),
254: CONCAT48(iVar15,CONCAT44(-(uint)((int)uVar14 < 0),uVar14)))
255: >> 0x40,0);
256: plVar6[2] = ((ulong)-(uint)((int)uVar14 < 0) * (uVar11 & 0xffffffff) +
257: (ulong)uVar14 * (ulong)uVar23 << 0x20) +
258: (ulong)uVar14 * (uVar11 & 0xffffffff) + param_2;
259: plVar6[3] = ((uVar17 >> 0x20) * (uVar11 & 0xffffffff) +
260: (uVar17 & 0xffffffff) * (ulong)uVar23 << 0x20) +
261: (uVar17 & 0xffffffff) * (uVar11 & 0xffffffff) + param_2;
262: plVar6 = plVar6 + 4;
263: } while (uVar8 < uVar12 >> 2);
264: iVar2 = iVar2 + (uVar12 & 0xfffffffc);
265: if (uVar12 == (uVar12 & 0xfffffffc)) goto LAB_0014f7c5;
266: }
267: plStack224[iVar2] = (long)((param_5 - iVar2) + -1) * uVar11 + param_2;
268: iVar18 = iVar2 + 1;
269: if (iVar18 < param_5) {
270: plStack224[iVar18] = (long)((param_5 - iVar18) + -1) * uVar11 + param_2;
271: iVar18 = iVar2 + 2;
272: if (iVar18 < param_5) {
273: plStack224[iVar18] = (long)((param_5 - iVar18) + -1) * uVar11 + param_2;
274: iVar18 = iVar2 + 3;
275: if (iVar18 < param_5) {
276: plStack224[iVar18] = (long)((param_5 - iVar18) + -1) * uVar11 + param_2;
277: iVar2 = iVar2 + 4;
278: if (iVar2 < param_5) {
279: plStack224[iVar2] = (long)((param_5 - iVar2) + -1) * uVar11 + param_2;
280: }
281: }
282: }
283: }
284: }
285: }
286: LAB_0014f7c5:
287: while( true ) {
288: uVar23 = *(uint *)(param_1 + 0x130);
289: if (*(uint *)(param_1 + 0x34) <= uVar23) break;
290: FUN_00103090(param_1,plStack224 + uVar23,*(uint *)(param_1 + 0x34) - uVar23);
291: }
292: FUN_00102d50(param_1);
293: }
294: else {
295: uStack228 = 0xffffffff;
296: }
297: if (*(int *)(param_1 + 0x24) < 0x65) goto LAB_0014f76d;
298: if (uStack84 != 0) goto LAB_0014f7f8;
299: }
300: thunk_FUN_0011f490(param_1);
301: LAB_0014f76d:
302: free(plStack224);
303: *(undefined4 *)(param_1 + 0x5fc) = 0;
304: uVar3 = 0xffffffff;
305: if (*(int *)(param_1 + 0x5f8) == 0) {
306: uVar3 = uStack228;
307: }
308: return uVar3;
309: }
310: 
