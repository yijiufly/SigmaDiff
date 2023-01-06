1: 
2: undefined8
3: tjDecompressToYUV2(long param_1,long param_2,long param_3,long param_4,ulong param_5,uint param_6,
4: int param_7,int param_8)
5: 
6: {
7: int iVar1;
8: int iVar2;
9: int iVar3;
10: int iVar4;
11: int iVar5;
12: int iVar6;
13: undefined4 *puVar7;
14: undefined8 uVar8;
15: undefined8 *puVar9;
16: int iVar10;
17: uint uVar11;
18: int iVar12;
19: int iVar13;
20: int iVar14;
21: int iVar15;
22: int iVar16;
23: int iVar17;
24: long in_FS_OFFSET;
25: uint uStack84;
26: undefined8 uStack80;
27: long lStack72;
28: long lStack64;
29: long lStack56;
30: long lStack48;
31: 
32: lStack48 = *(long *)(in_FS_OFFSET + 0x28);
33: if (param_1 == 0) {
34: puVar9 = (undefined8 *)__tls_get_addr(&PTR_00398fc0);
35: *puVar9 = 0x2064696c61766e49;
36: *(undefined4 *)(puVar9 + 1) = 0x646e6168;
37: *(undefined2 *)((long)puVar9 + 0xc) = 0x656c;
38: *(undefined *)((long)puVar9 + 0xe) = 0;
39: uVar8 = 0xffffffff;
40: goto LAB_00157bf8;
41: }
42: *(undefined4 *)(param_1 + 0x5f8) = 0;
43: *(undefined4 *)(param_1 + 0x6d0) = 0;
44: *(uint *)(param_1 + 0x5fc) = param_8 >> 0xd & 1;
45: if (((((param_2 == 0) || (param_3 == 0)) ||
46: ((byte)(param_4 == 0 | (byte)((param_5 & 0xffffffff) >> 0x1f)) != 0)) ||
47: (((int)param_6 < 1 || ((param_6 & param_6 - 1) != 0)))) || (param_7 < 0)) {
48: *(undefined4 *)(param_1 + 0x628) = 0x656d7567;
49: *(undefined2 *)(param_1 + 0x62c) = 0x746e;
50: *(undefined *)(param_1 + 0x62e) = 0;
51: *(undefined4 *)(param_1 + 0x6d0) = 1;
52: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
53: *(undefined8 *)(param_1 + 0x610) = 0x55596f5473736572;
54: *(undefined8 *)(param_1 + 0x618) = 0x6e49203a29283256;
55: *(undefined8 *)(param_1 + 0x620) = 0x72612064696c6176;
56: puVar7 = (undefined4 *)__tls_get_addr(0x6e49203a29283256,0x706d6f6365446a74,&PTR_00398fc0);
57: puVar7[8] = 0x656d7567;
58: *(undefined2 *)(puVar7 + 9) = 0x746e;
59: *(undefined *)((long)puVar7 + 0x26) = 0;
60: *puVar7 = 0x65446a74;
61: puVar7[1] = 0x706d6f63;
62: puVar7[2] = 0x73736572;
63: puVar7[3] = 0x55596f54;
64: puVar7[4] = 0x29283256;
65: puVar7[5] = 0x6e49203a;
66: puVar7[6] = 0x696c6176;
67: puVar7[7] = 0x72612064;
68: LAB_00157be4:
69: *(undefined4 *)(param_1 + 0x5fc) = 0;
70: uVar8 = 0xffffffff;
71: }
72: else {
73: iVar4 = _setjmp((__jmp_buf_tag *)(param_1 + 0x528));
74: if (iVar4 != 0) {
75: uVar8 = 0xffffffff;
76: goto LAB_00157bf8;
77: }
78: FUN_00167270(param_1 + 0x208,param_2,param_3);
79: FUN_00125330(param_1 + 0x208,1);
80: if (*(long *)(param_1 + 0x240) == 0x100000001) {
81: iVar4 = 3;
82: }
83: else {
84: iVar4 = FUN_0014e860();
85: if (iVar4 < 0) {
86: *(undefined8 *)(param_1 + 0x648) = 0x67616d6920474550;
87: *(undefined2 *)(param_1 + 0x650) = 0x65;
88: *(undefined4 *)(param_1 + 0x6d0) = 1;
89: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
90: *(undefined8 *)(param_1 + 0x610) = 0x55596f5473736572;
91: *(undefined8 *)(param_1 + 0x618) = 0x6f43203a29283256;
92: *(undefined8 *)(param_1 + 0x620) = 0x20746f6e20646c75;
93: *(undefined8 *)(param_1 + 0x628) = 0x6e696d7265746564;
94: *(undefined8 *)(param_1 + 0x630) = 0x6d61736275732065;
95: *(undefined8 *)(param_1 + 0x638) = 0x797420676e696c70;
96: *(undefined8 *)(param_1 + 0x640) = 0x4a20726f66206570;
97: puVar7 = (undefined4 *)
98: __tls_get_addr(0x797420676e696c70,0x6e696d7265746564,0x6f43203a29283256,
99: 0x706d6f6365446a74,&PTR_00398fc0);
100: *(undefined8 *)(puVar7 + 0x10) = 0x67616d6920474550;
101: *(undefined2 *)(puVar7 + 0x12) = 0x65;
102: *puVar7 = 0x65446a74;
103: puVar7[1] = 0x706d6f63;
104: puVar7[2] = 0x73736572;
105: puVar7[3] = 0x55596f54;
106: puVar7[4] = 0x29283256;
107: puVar7[5] = 0x6f43203a;
108: puVar7[6] = 0x20646c75;
109: puVar7[7] = 0x20746f6e;
110: puVar7[8] = 0x65746564;
111: puVar7[9] = 0x6e696d72;
112: puVar7[10] = 0x75732065;
113: puVar7[0xb] = 0x6d617362;
114: puVar7[0xc] = 0x6e696c70;
115: puVar7[0xd] = 0x79742067;
116: puVar7[0xe] = 0x66206570;
117: puVar7[0xf] = 0x4a20726f;
118: goto LAB_00157be4;
119: }
120: }
121: iVar5 = *(int *)(param_1 + 0x23c);
122: iVar6 = *(int *)(param_1 + 0x238);
123: iVar1 = (int)param_5;
124: if ((int)param_5 == 0) {
125: iVar1 = iVar6;
126: }
127: iVar2 = iVar5;
128: if (param_7 != 0) {
129: iVar2 = param_7;
130: }
131: if ((iVar2 < iVar5 * 2) || (iVar1 < iVar6 * 2)) {
132: iVar10 = iVar5 * 0xf + 7;
133: if (iVar10 < 0) {
134: iVar10 = iVar5 * 0xf + 0xe;
135: }
136: if (iVar10 >> 3 <= iVar2) {
137: iVar10 = iVar6 * 0xf + 7;
138: if (iVar10 < 0) {
139: iVar10 = iVar6 * 0xf + 0xe;
140: }
141: if (iVar10 >> 3 <= iVar1) goto LAB_00157c20;
142: }
143: iVar10 = iVar6 * 7;
144: iVar3 = iVar5 * 7;
145: iVar13 = iVar10 + 6;
146: if (-1 < iVar10 + 3) {
147: iVar13 = iVar10 + 3;
148: }
149: if (iVar13 >> 2 <= iVar1) {
150: iVar13 = iVar3 + 6;
151: if (-1 < iVar3 + 3) {
152: iVar13 = iVar3 + 3;
153: }
154: if (iVar13 >> 2 <= iVar2) goto LAB_00157c20;
155: }
156: iVar14 = iVar6 * 0xd + 7;
157: iVar13 = iVar6 * 0xd + 0xe;
158: if (-1 < iVar14) {
159: iVar13 = iVar14;
160: }
161: if (iVar13 >> 3 <= iVar1) {
162: iVar14 = iVar5 * 0xd + 7;
163: iVar13 = iVar5 * 0xd + 0xe;
164: if (-1 < iVar14) {
165: iVar13 = iVar14;
166: }
167: if (iVar13 >> 3 <= iVar2) goto LAB_00157c20;
168: }
169: iVar13 = iVar6 * 3;
170: iVar14 = iVar5 * 3;
171: if ((iVar1 < (iVar13 + 1) / 2) || (iVar2 < (iVar14 + 1) / 2)) {
172: iVar16 = iVar6 * 0xb + 7;
173: iVar15 = iVar6 * 0xb + 0xe;
174: if (-1 < iVar16) {
175: iVar15 = iVar16;
176: }
177: if (iVar15 >> 3 <= iVar1) {
178: iVar16 = iVar5 * 0xb + 7;
179: iVar15 = iVar5 * 0xb + 0xe;
180: if (-1 < iVar16) {
181: iVar15 = iVar16;
182: }
183: if (iVar15 >> 3 <= iVar2) goto LAB_00157c20;
184: }
185: iVar15 = iVar6 * 5;
186: iVar16 = iVar5 * 5;
187: iVar17 = iVar15 + 6;
188: if (-1 < iVar15 + 3) {
189: iVar17 = iVar15 + 3;
190: }
191: if (iVar17 >> 2 <= iVar1) {
192: iVar17 = iVar16 + 6;
193: if (-1 < iVar16 + 3) {
194: iVar17 = iVar16 + 3;
195: }
196: if (iVar17 >> 2 <= iVar2) goto LAB_00157c20;
197: }
198: iVar12 = iVar6 * 9 + 7;
199: iVar17 = iVar6 * 9 + 0xe;
200: if (-1 < iVar12) {
201: iVar17 = iVar12;
202: }
203: if (iVar17 >> 3 <= iVar1) {
204: iVar12 = iVar5 * 9 + 7;
205: iVar17 = iVar5 * 9 + 0xe;
206: if (-1 < iVar12) {
207: iVar17 = iVar12;
208: }
209: if (iVar17 >> 3 <= iVar2) goto LAB_00157c20;
210: }
211: if ((iVar1 < iVar6) || (iVar2 < iVar5)) {
212: iVar17 = iVar10 + 7;
213: if (iVar10 + 7 < 0) {
214: iVar17 = iVar10 + 0xe;
215: }
216: if (iVar17 >> 3 <= iVar1) {
217: iVar10 = iVar3 + 7;
218: if (iVar3 + 7 < 0) {
219: iVar10 = iVar3 + 0xe;
220: }
221: if (iVar10 >> 3 <= iVar2) goto LAB_00157c20;
222: }
223: iVar10 = iVar13 + 6;
224: if (-1 < iVar13 + 3) {
225: iVar10 = iVar13 + 3;
226: }
227: if (iVar10 >> 2 <= iVar1) {
228: iVar10 = iVar14 + 6;
229: if (-1 < iVar14 + 3) {
230: iVar10 = iVar14 + 3;
231: }
232: if (iVar10 >> 2 <= iVar2) goto LAB_00157c20;
233: }
234: iVar10 = iVar15 + 7;
235: if (iVar15 + 7 < 0) {
236: iVar10 = iVar15 + 0xe;
237: }
238: if (iVar10 >> 3 <= iVar1) {
239: iVar10 = iVar16 + 7;
240: if (iVar16 + 7 < 0) {
241: iVar10 = iVar16 + 0xe;
242: }
243: if (iVar10 >> 3 <= iVar2) goto LAB_00157c20;
244: }
245: if ((iVar1 < (iVar6 + 1) / 2) || (iVar2 < (iVar5 + 1) / 2)) {
246: iVar10 = iVar13 + 7;
247: if (iVar13 + 7 < 0) {
248: iVar10 = iVar13 + 0xe;
249: }
250: if (iVar10 >> 3 <= iVar1) {
251: iVar10 = iVar14 + 7;
252: if (iVar14 + 7 < 0) {
253: iVar10 = iVar14 + 0xe;
254: }
255: if (iVar10 >> 3 <= iVar2) goto LAB_00157c20;
256: }
257: iVar10 = iVar6 + 6;
258: if (-1 < iVar6 + 3) {
259: iVar10 = iVar6 + 3;
260: }
261: if (iVar10 >> 2 <= iVar1) {
262: iVar10 = iVar5 + 6;
263: if (-1 < iVar5 + 3) {
264: iVar10 = iVar5 + 3;
265: }
266: if (iVar10 >> 2 <= iVar2) goto LAB_00157c20;
267: }
268: iVar10 = iVar6 + 7;
269: if (iVar6 + 7 < 0) {
270: iVar10 = iVar6 + 0xe;
271: }
272: if (iVar10 >> 3 <= iVar1) {
273: iVar6 = iVar5 + 7;
274: if (iVar5 + 7 < 0) {
275: iVar6 = iVar5 + 0xe;
276: }
277: if (iVar6 >> 3 <= iVar2) goto LAB_00157c20;
278: }
279: *(undefined4 *)(param_1 + 0x648) = 0x6f69736e;
280: *(undefined2 *)(param_1 + 0x64c) = 0x736e;
281: *(undefined *)(param_1 + 0x64e) = 0;
282: *(undefined4 *)(param_1 + 0x6d0) = 1;
283: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
284: *(undefined8 *)(param_1 + 0x610) = 0x55596f5473736572;
285: *(undefined8 *)(param_1 + 0x618) = 0x6f43203a29283256;
286: *(undefined8 *)(param_1 + 0x620) = 0x20746f6e20646c75;
287: *(undefined8 *)(param_1 + 0x628) = 0x6f6420656c616373;
288: *(undefined8 *)(param_1 + 0x630) = 0x6564206f74206e77;
289: *(undefined8 *)(param_1 + 0x638) = 0x6d69206465726973;
290: *(undefined8 *)(param_1 + 0x640) = 0x656d696420656761;
291: puVar7 = (undefined4 *)
292: __tls_get_addr(0x6d69206465726973,0x6f6420656c616373,0x6f43203a29283256,
293: 0x706d6f6365446a74,&PTR_00398fc0);
294: puVar7[0x10] = 0x6f69736e;
295: *(undefined2 *)(puVar7 + 0x11) = 0x736e;
296: *(undefined *)((long)puVar7 + 0x46) = 0;
297: *puVar7 = 0x65446a74;
298: puVar7[1] = 0x706d6f63;
299: puVar7[2] = 0x73736572;
300: puVar7[3] = 0x55596f54;
301: puVar7[4] = 0x29283256;
302: puVar7[5] = 0x6f43203a;
303: puVar7[6] = 0x20646c75;
304: puVar7[7] = 0x20746f6e;
305: puVar7[8] = 0x6c616373;
306: puVar7[9] = 0x6f642065;
307: puVar7[10] = 0x74206e77;
308: puVar7[0xb] = 0x6564206f;
309: puVar7[0xc] = 0x65726973;
310: puVar7[0xd] = 0x6d692064;
311: puVar7[0xe] = 0x20656761;
312: puVar7[0xf] = 0x656d6964;
313: goto LAB_00157be4;
314: }
315: }
316: }
317: }
318: LAB_00157c20:
319: iVar5 = tjPlaneWidth(0,iVar1,iVar4);
320: iVar6 = tjPlaneHeight(0,iVar2,iVar4);
321: uStack84 = iVar5 + -1 + param_6 & -param_6;
322: lStack72 = param_4;
323: if (iVar4 == 3) {
324: uStack80 = 0;
325: lStack56 = 0;
326: lStack64 = 0;
327: }
328: else {
329: iVar5 = tjPlaneWidth(1,iVar1,iVar4);
330: iVar4 = tjPlaneHeight(1,iVar2,iVar4);
331: uVar11 = iVar5 + -1 + param_6 & -param_6;
332: uStack80 = CONCAT44(uVar11,uVar11);
333: lStack64 = lStack72 + (int)(iVar6 * uStack84);
334: lStack56 = lStack64 + (int)(uVar11 * iVar4);
335: }
336: *(undefined4 *)(param_1 + 0x604) = 1;
337: uVar8 = tjDecompressToYUVPlanes(param_1,param_2,param_3,&lStack72,iVar1,&uStack84,iVar2,param_8)
338: ;
339: }
340: LAB_00157bf8:
341: if (lStack48 == *(long *)(in_FS_OFFSET + 0x28)) {
342: return uVar8;
343: }
344: /* WARNING: Subroutine does not return */
345: __stack_chk_fail();
346: }
347: 
