1: 
2: /* WARNING: Could not reconcile some variable overlaps */
3: 
4: undefined8 FUN_0013b490(long *param_1,long *param_2)
5: 
6: {
7: short *psVar1;
8: short sVar2;
9: byte bVar3;
10: int iVar4;
11: long lVar5;
12: short sVar6;
13: int iVar7;
14: uint uVar8;
15: uint uVar9;
16: int iVar10;
17: undefined8 uVar11;
18: ulong uVar12;
19: undefined8 *puVar13;
20: undefined4 uVar14;
21: ulong uVar15;
22: int *piVar16;
23: int iVar17;
24: long lVar18;
25: long lVar19;
26: int iVar20;
27: uint uVar21;
28: long lVar22;
29: long in_FS_OFFSET;
30: uint uStack408;
31: int iStack392;
32: uint uStack388;
33: undefined8 uStack376;
34: undefined8 uStack368;
35: ulong uStack360;
36: uint uStack352;
37: int aiStack332 [67];
38: long lStack64;
39: 
40: iVar7 = *(int *)(param_1 + 0x2e);
41: iVar4 = *(int *)(param_1 + 0x42);
42: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
43: lVar5 = param_1[0x4a];
44: bVar3 = (byte)*(undefined4 *)(param_1 + 0x43);
45: if (iVar7 == 0) {
46: uVar11 = 1;
47: if (*(int *)(lVar5 + 0x10) != 0) goto LAB_0013b4ff;
48: LAB_0013b53c:
49: uStack388 = 1 << (bVar3 & 0x1f);
50: uStack408 = -1 << (bVar3 & 0x1f);
51: puVar13 = (undefined8 *)param_1[5];
52: iVar20 = *(int *)(lVar5 + 0x28);
53: uVar12 = *(ulong *)(lVar5 + 0x18);
54: uStack376 = *puVar13;
55: uStack368 = puVar13[1];
56: lVar22 = *param_2;
57: uVar15 = (ulong)*(uint *)(lVar5 + 0x20);
58: iVar17 = *(int *)((long)param_1 + 0x20c);
59: iStack392 = 0;
60: if (iVar20 == 0) {
61: LAB_0013b712:
62: uVar14 = (undefined4)uVar15;
63: if (iVar4 < iVar17) {
64: iVar20 = 0;
65: }
66: else {
67: iStack392 = 0;
68: lVar18 = *(long *)(lVar5 + 0x60);
69: do {
70: uVar8 = (uint)uVar15;
71: uVar9 = uStack352;
72: if ((int)(uint)uVar15 < 8) {
73: iVar7 = FUN_00130960();
74: if (iVar7 == 0) goto LAB_0013b9d3;
75: uVar12 = uStack360;
76: uVar8 = uStack352;
77: if (7 < (int)uStack352) goto LAB_0013b759;
78: LAB_0013b93f:
79: uVar8 = FUN_00130b10();
80: if ((int)uVar8 < 0) goto LAB_0013b9d3;
81: iVar7 = (int)uVar8 >> 4;
82: uVar21 = uVar8 & 0xf;
83: uVar12 = uStack360;
84: if ((uVar8 & 0xf) != 0) goto LAB_0013b79b;
85: LAB_0013b972:
86: uVar15 = (ulong)uVar9;
87: if (iVar7 != 0xf) {
88: iVar20 = 1 << ((byte)iVar7 & 0x1f);
89: if (iVar7 != 0) {
90: if (((int)uVar9 < iVar7) &&
91: (iVar10 = FUN_00130960(), uVar12 = uStack360, uVar9 = uStack352, iVar10 == 0))
92: goto LAB_0013b9d3;
93: uVar15 = (ulong)(uVar9 - iVar7);
94: iVar20 = (iVar20 - 1U & (uint)(uVar12 >> ((byte)(uVar9 - iVar7) & 0x3f))) + iVar20;
95: }
96: uVar14 = (undefined4)uVar15;
97: if (iVar20 != 0) goto LAB_0013b598;
98: goto LAB_0013ba45;
99: }
100: }
101: else {
102: LAB_0013b759:
103: uVar21 = *(uint *)(lVar18 + 0x128 + (uVar12 >> ((char)uVar8 - 8U & 0x3f) & 0xff) * 4);
104: if (8 < (int)uVar21 >> 8) goto LAB_0013b93f;
105: uVar9 = uVar8 - ((int)uVar21 >> 8);
106: iVar7 = (int)(uVar21 & 0xff) >> 4;
107: uVar21 = uVar21 & 0xf;
108: if (uVar21 == 0) goto LAB_0013b972;
109: LAB_0013b79b:
110: if (uVar21 != 1) {
111: lVar19 = *param_1;
112: *(undefined4 *)(lVar19 + 0x28) = 0x76;
113: (**(code **)(lVar19 + 8))(param_1,0xffffffff);
114: }
115: if (((int)uVar9 < 1) &&
116: (iVar20 = FUN_00130960(), uVar12 = uStack360, uVar9 = uStack352, iVar20 == 0))
117: goto LAB_0013b9d3;
118: uVar15 = (ulong)(uVar9 - 1);
119: uVar21 = uStack408;
120: if ((uVar12 >> ((byte)(uVar9 - 1) & 0x3f) & 1) != 0) {
121: uVar21 = uStack388;
122: }
123: }
124: lVar19 = (long)iVar17;
125: do {
126: iVar17 = (int)lVar19;
127: psVar1 = (short *)(lVar22 + (long)*(int *)(&DAT_0018f100 + lVar19 * 4) * 2);
128: if (*psVar1 == 0) {
129: iVar7 = iVar7 + -1;
130: if (iVar7 == -1) break;
131: }
132: else {
133: uVar9 = (uint)uVar15;
134: if (((int)(uint)uVar15 < 1) &&
135: (iVar20 = FUN_00130960(), uVar12 = uStack360, uVar9 = uStack352, iVar20 == 0))
136: goto LAB_0013b9d3;
137: uVar15 = (ulong)(uVar9 - 1);
138: if (((uVar12 >> (uVar15 & 0x3f) & 1) != 0) &&
139: (sVar2 = *psVar1, ((int)sVar2 & uStack388) == 0)) {
140: sVar6 = (short)uStack388;
141: if (sVar2 < 0) {
142: sVar6 = (short)uStack408;
143: }
144: *psVar1 = sVar2 + sVar6;
145: }
146: }
147: iVar17 = iVar17 + 1;
148: lVar19 = lVar19 + 1;
149: } while ((int)lVar19 <= iVar4);
150: uVar14 = (undefined4)uVar15;
151: if (uVar21 != 0) {
152: iVar7 = *(int *)(&DAT_0018f100 + (long)iVar17 * 4);
153: *(short *)(lVar22 + (long)iVar7 * 2) = (short)uVar21;
154: aiStack332[(long)iStack392 + 1] = iVar7;
155: iStack392 = iStack392 + 1;
156: }
157: iVar17 = iVar17 + 1;
158: } while (iVar17 <= iVar4);
159: iVar20 = 0;
160: puVar13 = (undefined8 *)param_1[5];
161: iVar7 = *(int *)(param_1 + 0x2e);
162: }
163: }
164: else {
165: LAB_0013b598:
166: uVar14 = (undefined4)uVar15;
167: if (iVar17 <= iVar4) {
168: lVar18 = (long)iVar17;
169: do {
170: psVar1 = (short *)(lVar22 + (long)*(int *)(&DAT_0018f100 + lVar18 * 4) * 2);
171: if (*psVar1 != 0) {
172: uVar9 = (uint)uVar15;
173: if (((int)(uint)uVar15 < 1) &&
174: (iVar7 = FUN_00130960(), uVar12 = uStack360, uVar9 = uStack352, iVar7 == 0))
175: goto LAB_0013b9d3;
176: uVar15 = (ulong)(uVar9 - 1);
177: if (((uVar12 >> (uVar15 & 0x3f) & 1) != 0) &&
178: (sVar2 = *psVar1, (uStack388 & (int)sVar2) == 0)) {
179: if (-1 < sVar2) {
180: uStack408._0_2_ = (short)uStack388;
181: }
182: *psVar1 = sVar2 + (short)uStack408;
183: }
184: }
185: uVar14 = (undefined4)uVar15;
186: lVar18 = lVar18 + 1;
187: } while ((int)lVar18 <= iVar4);
188: }
189: iVar20 = iVar20 + -1;
190: LAB_0013ba45:
191: puVar13 = (undefined8 *)param_1[5];
192: iVar7 = *(int *)(param_1 + 0x2e);
193: }
194: puVar13[1] = uStack368;
195: *puVar13 = uStack376;
196: *(ulong *)(lVar5 + 0x18) = uVar12;
197: *(undefined4 *)(lVar5 + 0x20) = uVar14;
198: *(int *)(lVar5 + 0x28) = iVar20;
199: LAB_0013ba70:
200: uVar11 = 1;
201: if (iVar7 == 0) goto LAB_0013b4ff;
202: }
203: else {
204: if (*(int *)(lVar5 + 0x3c) == 0) {
205: iVar7 = *(int *)(lVar5 + 0x20);
206: lVar22 = param_1[0x49];
207: iVar17 = iVar7 + 7;
208: if (-1 < iVar7) {
209: iVar17 = iVar7;
210: }
211: piVar16 = (int *)(lVar22 + 0x24);
212: *piVar16 = *piVar16 + (iVar17 >> 3);
213: *(undefined4 *)(lVar5 + 0x20) = 0;
214: iVar7 = (**(code **)(lVar22 + 0x10))();
215: if (iVar7 == 0) goto LAB_0013ba13;
216: if (0 < *(int *)(param_1 + 0x36)) {
217: memset((void *)(lVar5 + 0x2c),0,(ulong)(*(int *)(param_1 + 0x36) - 1) * 4 + 4);
218: }
219: iVar17 = *(int *)((long)param_1 + 0x21c);
220: iVar7 = *(int *)(param_1 + 0x2e);
221: *(undefined4 *)(lVar5 + 0x28) = 0;
222: *(int *)(lVar5 + 0x3c) = iVar7;
223: if (iVar17 == 0) {
224: *(undefined4 *)(lVar5 + 0x10) = 0;
225: uStack388 = 1 << (bVar3 & 0x1f);
226: uStack408 = -1 << (bVar3 & 0x1f);
227: puVar13 = (undefined8 *)param_1[5];
228: lVar22 = *param_2;
229: uVar12 = *(ulong *)(lVar5 + 0x18);
230: uStack376 = *puVar13;
231: uStack368 = puVar13[1];
232: uVar15 = (ulong)*(uint *)(lVar5 + 0x20);
233: iVar17 = *(int *)((long)param_1 + 0x20c);
234: goto LAB_0013b712;
235: }
236: if (*(int *)(lVar5 + 0x10) == 0) goto LAB_0013b53c;
237: goto LAB_0013ba70;
238: }
239: if (*(int *)(lVar5 + 0x10) == 0) goto LAB_0013b53c;
240: }
241: *(int *)(lVar5 + 0x3c) = *(int *)(lVar5 + 0x3c) + -1;
242: uVar11 = 1;
243: LAB_0013b4ff:
244: if (lStack64 != *(long *)(in_FS_OFFSET + 0x28)) {
245: /* WARNING: Subroutine does not return */
246: __stack_chk_fail();
247: }
248: return uVar11;
249: LAB_0013b9d3:
250: if (iStack392 != 0) {
251: uVar9 = iStack392 - 1;
252: piVar16 = aiStack332 + (long)(int)uVar9 + 1;
253: do {
254: iVar4 = *piVar16;
255: piVar16 = piVar16 + -1;
256: *(undefined2 *)(lVar22 + (long)iVar4 * 2) = 0;
257: } while (piVar16 != aiStack332 + ((long)(int)uVar9 - (ulong)uVar9));
258: }
259: LAB_0013ba13:
260: uVar11 = 0;
261: goto LAB_0013b4ff;
262: }
263: 
