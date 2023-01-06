1: 
2: undefined8 FUN_00129cc0(code **param_1)
3: 
4: {
5: byte bVar1;
6: byte bVar2;
7: undefined2 uVar3;
8: undefined4 uVar4;
9: byte **ppbVar5;
10: code *pcVar6;
11: code **ppcVar7;
12: int iVar8;
13: int iVar9;
14: undefined8 uVar10;
15: long *plVar11;
16: ulong uVar12;
17: byte *pbVar13;
18: byte *pbVar14;
19: undefined8 *puVar15;
20: undefined8 *puVar16;
21: long lVar17;
22: undefined8 *puVar18;
23: byte *pbVar19;
24: byte *pbVar20;
25: long **pplVar21;
26: uint uVar22;
27: long in_FS_OFFSET;
28: bool bVar23;
29: byte bVar24;
30: long lStack416;
31: byte bStack359;
32: byte bStack358;
33: byte bStack357;
34: byte bStack356;
35: byte bStack355;
36: byte bStack354;
37: byte bStack353;
38: byte bStack352;
39: byte bStack351;
40: byte bStack350;
41: byte bStack349;
42: byte bStack348;
43: byte bStack347;
44: byte bStack346;
45: byte bStack345;
46: undefined uStack344;
47: byte abStack343 [15];
48: undefined uStack328;
49: undefined8 auStack327 [32];
50: long lStack64;
51: 
52: bVar24 = 0;
53: ppbVar5 = (byte **)param_1[5];
54: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
55: pbVar19 = ppbVar5[1];
56: pbVar13 = *ppbVar5;
57: if (pbVar19 == (byte *)0x0) {
58: iVar8 = (*(code *)ppbVar5[3])();
59: if (iVar8 != 0) {
60: pbVar13 = *ppbVar5;
61: pbVar19 = ppbVar5[1];
62: goto LAB_00129cfc;
63: }
64: LAB_0012a078:
65: uVar10 = 0;
66: }
67: else {
68: LAB_00129cfc:
69: bVar1 = *pbVar13;
70: pbVar19 = pbVar19 + -1;
71: if (pbVar19 == (byte *)0x0) {
72: iVar8 = (*(code *)ppbVar5[3])(param_1);
73: if (iVar8 == 0) goto LAB_0012a078;
74: pbVar13 = *ppbVar5;
75: pbVar19 = ppbVar5[1];
76: }
77: else {
78: pbVar13 = pbVar13 + 1;
79: }
80: pbVar19 = pbVar19 + -1;
81: pbVar20 = pbVar13 + 1;
82: lStack416 = (ulong)bVar1 * 0x100 + -2 + (ulong)*pbVar13;
83: if (0x10 < lStack416) {
84: do {
85: if (pbVar19 == (byte *)0x0) {
86: iVar8 = (*(code *)ppbVar5[3])(param_1);
87: if (iVar8 == 0) goto LAB_0012a078;
88: pbVar20 = *ppbVar5;
89: pbVar19 = ppbVar5[1];
90: }
91: bVar1 = *pbVar20;
92: pbVar20 = pbVar20 + 1;
93: pbVar19 = pbVar19 + -1;
94: iVar8 = 0;
95: uVar22 = (uint)bVar1;
96: pcVar6 = *param_1;
97: *(undefined4 *)(pcVar6 + 0x28) = 0x50;
98: *(uint *)(pcVar6 + 0x2c) = uVar22;
99: (**(code **)(*param_1 + 8))(param_1);
100: pbVar13 = &bStack359;
101: do {
102: if (pbVar19 == (byte *)0x0) {
103: iVar9 = (*(code *)ppbVar5[3])(param_1);
104: if (iVar9 == 0) goto LAB_0012a078;
105: pbVar20 = *ppbVar5;
106: pbVar19 = ppbVar5[1];
107: }
108: bVar2 = *pbVar20;
109: pbVar14 = pbVar13 + 1;
110: pbVar19 = pbVar19 + -1;
111: pbVar20 = pbVar20 + 1;
112: *pbVar13 = bVar2;
113: iVar8 = iVar8 + (uint)bVar2;
114: pbVar13 = pbVar14;
115: } while (pbVar14 != abStack343);
116: pcVar6 = *param_1;
117: *(undefined4 *)(pcVar6 + 0x28) = 0x56;
118: *(uint *)(pcVar6 + 0x2c) = (uint)bStack359;
119: *(uint *)(pcVar6 + 0x30) = (uint)bStack358;
120: *(uint *)(pcVar6 + 0x34) = (uint)bStack357;
121: *(uint *)(pcVar6 + 0x38) = (uint)bStack356;
122: *(uint *)(pcVar6 + 0x3c) = (uint)bStack355;
123: *(uint *)(pcVar6 + 0x40) = (uint)bStack354;
124: *(uint *)(pcVar6 + 0x44) = (uint)bStack353;
125: *(uint *)(pcVar6 + 0x48) = (uint)bStack352;
126: (**(code **)(pcVar6 + 8))(param_1);
127: pcVar6 = *param_1;
128: *(undefined4 *)(pcVar6 + 0x28) = 0x56;
129: *(uint *)(pcVar6 + 0x2c) = (uint)bStack351;
130: *(uint *)(pcVar6 + 0x30) = (uint)bStack350;
131: *(uint *)(pcVar6 + 0x34) = (uint)bStack349;
132: *(uint *)(pcVar6 + 0x38) = (uint)bStack348;
133: *(uint *)(pcVar6 + 0x3c) = (uint)bStack347;
134: *(uint *)(pcVar6 + 0x40) = (uint)bStack346;
135: *(uint *)(pcVar6 + 0x44) = (uint)bStack345;
136: *(uint *)(pcVar6 + 0x48) = (uint)(byte)uStack344;
137: (**(code **)(pcVar6 + 8))(param_1);
138: if ((0x100 < iVar8) || (lStack416 + -0x11 < (long)iVar8)) {
139: ppcVar7 = (code **)*param_1;
140: *(undefined4 *)(ppcVar7 + 5) = 8;
141: (**ppcVar7)(param_1);
142: }
143: if (iVar8 != 0) {
144: puVar16 = (undefined8 *)&uStack328;
145: do {
146: if (pbVar19 == (byte *)0x0) {
147: iVar9 = (*(code *)ppbVar5[3])(param_1);
148: if (iVar9 == 0) goto LAB_0012a078;
149: pbVar20 = *ppbVar5;
150: pbVar19 = ppbVar5[1];
151: }
152: bVar2 = *pbVar20;
153: puVar15 = (undefined8 *)((long)puVar16 + 1);
154: pbVar19 = pbVar19 + -1;
155: pbVar20 = pbVar20 + 1;
156: *(byte *)puVar16 = bVar2;
157: puVar16 = puVar15;
158: } while (puVar15 != (undefined8 *)(&uStack328 + (ulong)(iVar8 - 1) + 1));
159: }
160: memset((void *)((long)&uStack328 + (long)iVar8),0,(long)(0x100 - iVar8));
161: lStack416 = (lStack416 + -0x11) - (long)iVar8;
162: if ((bVar1 & 0x10) == 0) {
163: if (bVar1 < 4) {
164: pplVar21 = (long **)(param_1 + (long)(int)uVar22 + 0x1d);
165: }
166: else {
167: pcVar6 = *param_1;
168: *(undefined4 *)(pcVar6 + 0x28) = 0x1e;
169: *(uint *)(pcVar6 + 0x2c) = uVar22;
170: (**(code **)*param_1)(param_1);
171: pplVar21 = (long **)(param_1 + (long)(int)uVar22 + 0x1d);
172: }
173: }
174: else {
175: uVar22 = uVar22 - 0x10;
176: if (3 < uVar22) {
177: pcVar6 = *param_1;
178: *(undefined4 *)(pcVar6 + 0x28) = 0x1e;
179: *(uint *)(pcVar6 + 0x2c) = uVar22;
180: (**(code **)*param_1)(param_1);
181: }
182: pplVar21 = (long **)(param_1 + (long)(int)uVar22 + 0x21);
183: }
184: plVar11 = *pplVar21;
185: if (plVar11 == (long *)0x0) {
186: plVar11 = (long *)FUN_00116780(param_1);
187: *pplVar21 = plVar11;
188: }
189: *plVar11 = (ulong)CONCAT16(bStack353,
190: CONCAT15(bStack354,
191: CONCAT14(bStack355,
192: CONCAT13(bStack356,
193: CONCAT12(bStack357,
194: CONCAT11(bStack358,bStack359)
195: ))))) << 8;
196: plVar11[1] = CONCAT17(bStack345,
197: CONCAT16(bStack346,
198: CONCAT15(bStack347,
199: CONCAT14(bStack348,
200: CONCAT13(bStack349,
201: CONCAT12(bStack350,
202: CONCAT11(bStack351,
203: bStack352)))))))
204: ;
205: *(code *)(plVar11 + 2) = uStack344;
206: plVar11 = *pplVar21;
207: uVar22 = 0x100;
208: iVar8 = 0x100;
209: puVar16 = (undefined8 *)((long)plVar11 + 0x11);
210: bVar23 = ((ulong)puVar16 & 1) != 0;
211: puVar15 = (undefined8 *)&uStack328;
212: if (bVar23) {
213: puVar16 = (undefined8 *)((long)plVar11 + 0x12);
214: *(code *)((long)plVar11 + 0x11) = uStack328;
215: uVar22 = 0xff;
216: iVar8 = 0xff;
217: puVar15 = (undefined8 *)(&uStack328 + 1);
218: }
219: if (((ulong)puVar16 & 2) != 0) {
220: uVar3 = *(undefined2 *)puVar15;
221: puVar15 = (undefined8 *)((long)puVar15 + 2);
222: uVar22 = iVar8 - 2;
223: *(undefined2 *)puVar16 = uVar3;
224: puVar16 = (undefined8 *)((long)puVar16 + 2);
225: }
226: puVar18 = puVar16;
227: if (((ulong)puVar16 & 4) != 0) {
228: uVar4 = *(undefined4 *)puVar15;
229: puVar18 = (undefined8 *)((long)puVar16 + 4);
230: puVar15 = (undefined8 *)((long)puVar15 + 4);
231: uVar22 = uVar22 - 4;
232: *(undefined4 *)puVar16 = uVar4;
233: }
234: lVar17 = 0;
235: uVar12 = (ulong)(uVar22 >> 3);
236: while (uVar12 != 0) {
237: uVar12 = uVar12 - 1;
238: *puVar18 = *puVar15;
239: puVar15 = puVar15 + (ulong)bVar24 * -2 + 1;
240: puVar18 = puVar18 + (ulong)bVar24 * -2 + 1;
241: }
242: if ((uVar22 & 4) != 0) {
243: *(undefined4 *)puVar18 = *(undefined4 *)puVar15;
244: lVar17 = 4;
245: }
246: if ((uVar22 & 2) != 0) {
247: *(undefined2 *)((long)puVar18 + lVar17) = *(undefined2 *)((long)puVar15 + lVar17);
248: lVar17 = lVar17 + 2;
249: }
250: if (bVar23) {
251: *(undefined *)((long)puVar18 + lVar17) = *(undefined *)((long)puVar15 + lVar17);
252: }
253: } while (0x10 < lStack416);
254: }
255: if (lStack416 != 0) {
256: ppcVar7 = (code **)*param_1;
257: *(undefined4 *)(ppcVar7 + 5) = 0xb;
258: (**ppcVar7)(param_1);
259: }
260: *ppbVar5 = pbVar20;
261: ppbVar5[1] = pbVar19;
262: uVar10 = 1;
263: }
264: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
265: return uVar10;
266: }
267: /* WARNING: Subroutine does not return */
268: __stack_chk_fail();
269: }
270: 
