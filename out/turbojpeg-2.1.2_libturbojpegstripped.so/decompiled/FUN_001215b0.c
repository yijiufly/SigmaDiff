1: 
2: undefined8 FUN_001215b0(code **param_1,undefined8 *param_2)
3: 
4: {
5: long *plVar1;
6: short sVar2;
7: short sVar3;
8: undefined4 uVar4;
9: int iVar5;
10: code *pcVar6;
11: undefined8 uVar7;
12: code **ppcVar8;
13: undefined *puVar9;
14: undefined8 *puVar10;
15: int iVar11;
16: long lVar12;
17: long lVar13;
18: ulong uVar14;
19: int iVar15;
20: int iVar16;
21: uint uVar17;
22: uint uVar18;
23: ulong uVar19;
24: long lVar20;
25: short *psVar21;
26: uint uVar22;
27: long in_FS_OFFSET;
28: ulong uStack368;
29: short asStack352 [144];
30: long lStack64;
31: 
32: iVar11 = *(int *)(param_1 + 0x23);
33: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
34: lVar12 = (long)*(int *)((long)param_1 + 0x19c);
35: pcVar6 = param_1[0x3e];
36: iVar5 = (*(int *)(param_1 + 0x34) - *(int *)((long)param_1 + 0x19c)) + 1;
37: uVar4 = *(undefined4 *)(param_1 + 0x35);
38: uVar7 = *(undefined8 *)((long)param_1[5] + 8);
39: *(undefined8 *)(pcVar6 + 0x30) = *(undefined8 *)param_1[5];
40: *(undefined8 *)(pcVar6 + 0x38) = uVar7;
41: if ((iVar11 != 0) && (*(int *)(pcVar6 + 0x80) == 0)) {
42: FUN_00120fe0(pcVar6,*(undefined4 *)(pcVar6 + 0x84));
43: lVar12 = (long)*(int *)((long)param_1 + 0x19c);
44: }
45: (**(code **)(pcVar6 + 0x18))(*param_2,&DAT_0018f100 + lVar12 * 4,iVar5,uVar4);
46: psVar21 = asStack352;
47: if (uStack368 != 0) {
48: if (*(int *)(pcVar6 + 0x6c) != 0) {
49: FUN_00120910(pcVar6);
50: }
51: do {
52: iVar11 = 0;
53: uVar14 = uStack368;
54: while ((uVar14 & 1) == 0) {
55: iVar11 = iVar11 + 1;
56: uVar14 = uVar14 >> 1 | 0x8000000000000000;
57: }
58: psVar21 = psVar21 + iVar11;
59: sVar2 = *psVar21;
60: sVar3 = psVar21[0x40];
61: iVar15 = iVar11;
62: if (iVar11 < 0x10) {
63: LAB_00121710:
64: uVar18 = (uint)(byte)(&DAT_0017cd40)[(int)sVar2];
65: if (10 < (byte)(&DAT_0017cd40)[(int)sVar2]) {
66: LAB_00121724:
67: ppcVar8 = (code **)*param_1;
68: *(undefined4 *)(ppcVar8 + 5) = 6;
69: (**ppcVar8)();
70: }
71: lVar12 = (long)*(int *)(pcVar6 + 0x68);
72: iVar15 = iVar15 * 0x10 + uVar18;
73: if (*(int *)(pcVar6 + 0x28) != 0) goto LAB_00121752;
74: FUN_001207a0(pcVar6,*(undefined4 *)
75: (*(long *)(pcVar6 + lVar12 * 8 + 0x88) + (long)iVar15 * 4),
76: (int)*(char *)(*(long *)(pcVar6 + lVar12 * 8 + 0x88) + 0x400 + (long)iVar15));
77: iVar16 = *(int *)(pcVar6 + 0x48);
78: if (uVar18 == 0) goto LAB_0012176e;
79: LAB_00121780:
80: if (*(int *)(pcVar6 + 0x28) == 0) {
81: uVar22 = iVar16 + uVar18;
82: uVar14 = (~(-1 << ((byte)uVar18 & 0x3f)) & (ulong)(uint)(int)sVar3) <<
83: (0x18U - (char)uVar22 & 0x3f) | *(ulong *)(pcVar6 + 0x40);
84: if (7 < (int)uVar22) {
85: uVar18 = uVar22 - 8;
86: uVar17 = uVar18 & 7;
87: do {
88: while( true ) {
89: uVar19 = uVar14;
90: puVar9 = *(undefined **)(pcVar6 + 0x30);
91: *(undefined **)(pcVar6 + 0x30) = puVar9 + 1;
92: *puVar9 = (char)(uVar19 >> 0x10);
93: plVar1 = (long *)(pcVar6 + 0x38);
94: *plVar1 = *plVar1 + -1;
95: if (*plVar1 == 0) {
96: puVar10 = *(undefined8 **)(*(long *)(pcVar6 + 0x50) + 0x28);
97: iVar15 = (*(code *)puVar10[3])();
98: if (iVar15 == 0) {
99: ppcVar8 = (code **)**(code ***)(pcVar6 + 0x50);
100: *(undefined4 *)(ppcVar8 + 5) = 0x18;
101: (**ppcVar8)();
102: }
103: *(undefined8 *)(pcVar6 + 0x30) = *puVar10;
104: *(undefined8 *)(pcVar6 + 0x38) = puVar10[1];
105: }
106: if (((uint)(uVar19 >> 0x10) & 0xff) == 0xff) break;
107: LAB_001217d8:
108: uVar22 = uVar22 - 8;
109: uVar14 = uVar19 << 8;
110: if (uVar22 == uVar17) goto LAB_00121870;
111: }
112: puVar9 = *(undefined **)(pcVar6 + 0x30);
113: *(undefined **)(pcVar6 + 0x30) = puVar9 + 1;
114: *puVar9 = 0;
115: plVar1 = (long *)(pcVar6 + 0x38);
116: *plVar1 = *plVar1 + -1;
117: if (*plVar1 != 0) goto LAB_001217d8;
118: puVar10 = *(undefined8 **)(*(long *)(pcVar6 + 0x50) + 0x28);
119: iVar15 = (*(code *)puVar10[3])();
120: if (iVar15 == 0) {
121: ppcVar8 = (code **)**(code ***)(pcVar6 + 0x50);
122: *(undefined4 *)(ppcVar8 + 5) = 0x18;
123: (**ppcVar8)();
124: }
125: uVar22 = uVar22 - 8;
126: *(undefined8 *)(pcVar6 + 0x30) = *puVar10;
127: *(undefined8 *)(pcVar6 + 0x38) = puVar10[1];
128: uVar14 = uVar19 << 8;
129: } while (uVar22 != uVar17);
130: LAB_00121870:
131: uVar14 = uVar19 << 8;
132: uVar22 = uVar18 & 7;
133: }
134: *(ulong *)(pcVar6 + 0x40) = uVar14;
135: *(uint *)(pcVar6 + 0x48) = uVar22;
136: }
137: }
138: else {
139: lVar12 = (long)*(int *)(pcVar6 + 0x68);
140: iVar15 = iVar11 + -0x10;
141: if (*(int *)(pcVar6 + 0x28) == 0) {
142: FUN_001207a0(pcVar6,*(undefined4 *)(*(long *)(pcVar6 + lVar12 * 8 + 0x88) + 0x3c0),
143: (int)*(char *)(*(long *)(pcVar6 + lVar12 * 8 + 0x88) + 0x4f0));
144: if (0xf < iVar15) {
145: if (*(int *)(pcVar6 + 0x28) != 0) {
146: lVar20 = *(long *)(pcVar6 + (long)*(int *)(pcVar6 + 0x68) * 8 + 0xa8);
147: lVar13 = *(long *)(lVar20 + 0x780);
148: goto LAB_001216f0;
149: }
150: FUN_001207a0(pcVar6,*(undefined4 *)
151: (*(long *)(pcVar6 + (long)*(int *)(pcVar6 + 0x68) * 8 + 0x88) +
152: 0x3c0),
153: (int)*(char *)(*(long *)(pcVar6 + (long)*(int *)(pcVar6 + 0x68) * 8 + 0x88)
154: + 0x4f0));
155: if (0xf < iVar11 + -0x20) {
156: if (*(int *)(pcVar6 + 0x28) != 0) {
157: lVar20 = *(long *)(pcVar6 + (long)*(int *)(pcVar6 + 0x68) * 8 + 0xa8);
158: goto LAB_00121705;
159: }
160: FUN_001207a0(pcVar6,*(undefined4 *)
161: (*(long *)(pcVar6 + (long)*(int *)(pcVar6 + 0x68) * 8 + 0x88) +
162: 0x3c0),
163: (int)*(char *)(*(long *)(pcVar6 + (long)*(int *)(pcVar6 + 0x68) * 8 +
164: 0x88) + 0x4f0));
165: goto LAB_0012170d;
166: }
167: LAB_00121a60:
168: iVar15 = iVar11 + -0x20;
169: }
170: goto LAB_00121710;
171: }
172: lVar20 = *(long *)(pcVar6 + (long)*(int *)(pcVar6 + 0x68) * 8 + 0xa8);
173: lVar13 = *(long *)(lVar20 + 0x780) + 1;
174: *(long *)(lVar20 + 0x780) = lVar13;
175: if (0xf < iVar15) {
176: LAB_001216f0:
177: *(long *)(lVar20 + 0x780) = lVar13 + 1;
178: if (iVar11 + -0x20 < 0x10) goto LAB_00121a60;
179: LAB_00121705:
180: *(long *)(lVar20 + 0x780) = *(long *)(lVar20 + 0x780) + 1;
181: LAB_0012170d:
182: iVar15 = iVar11 + -0x30;
183: goto LAB_00121710;
184: }
185: uVar18 = (uint)(byte)(&DAT_0017cd40)[(int)sVar2];
186: if (10 < uVar18) goto LAB_00121724;
187: iVar15 = iVar15 * 0x10 + uVar18;
188: LAB_00121752:
189: iVar16 = *(int *)(pcVar6 + 0x48);
190: plVar1 = (long *)(*(long *)(pcVar6 + lVar12 * 8 + 0xa8) + (long)iVar15 * 8);
191: *plVar1 = *plVar1 + 1;
192: if (uVar18 == 0) {
193: LAB_0012176e:
194: uVar18 = 0;
195: ppcVar8 = (code **)**(code ***)(pcVar6 + 0x50);
196: *(undefined4 *)(ppcVar8 + 5) = 0x28;
197: (**ppcVar8)();
198: goto LAB_00121780;
199: }
200: }
201: psVar21 = psVar21 + 1;
202: uStack368 = (uStack368 >> ((byte)iVar11 & 0x3f)) >> 1;
203: } while (uStack368 != 0);
204: }
205: if ((psVar21 < asStack352 + iVar5) &&
206: (iVar5 = *(int *)(pcVar6 + 0x6c), *(int *)(pcVar6 + 0x6c) = iVar5 + 1, iVar5 + 1 == 0x7fff)) {
207: FUN_00120910(pcVar6);
208: }
209: puVar10 = (undefined8 *)param_1[5];
210: *puVar10 = *(undefined8 *)(pcVar6 + 0x30);
211: puVar10[1] = *(undefined8 *)(pcVar6 + 0x38);
212: iVar5 = *(int *)(param_1 + 0x23);
213: if (iVar5 != 0) {
214: iVar11 = *(int *)(pcVar6 + 0x80);
215: if (*(int *)(pcVar6 + 0x80) == 0) {
216: *(uint *)(pcVar6 + 0x84) = *(int *)(pcVar6 + 0x84) + 1U & 7;
217: iVar11 = iVar5;
218: }
219: *(int *)(pcVar6 + 0x80) = iVar11 + -1;
220: }
221: if (lStack64 != *(long *)(in_FS_OFFSET + 0x28)) {
222: /* WARNING: Subroutine does not return */
223: __stack_chk_fail();
224: }
225: return 1;
226: }
227: 
