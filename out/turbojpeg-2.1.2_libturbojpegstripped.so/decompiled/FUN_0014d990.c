1: 
2: undefined8 FUN_0014d990(code **param_1,long *param_2)
3: 
4: {
5: short *psVar1;
6: byte bVar2;
7: undefined4 uVar3;
8: int iVar4;
9: code *pcVar5;
10: long lVar6;
11: code *pcVar7;
12: long lVar8;
13: byte **ppbVar9;
14: code **ppcVar10;
15: int iVar11;
16: int iVar12;
17: long lVar13;
18: byte *pbVar14;
19: int iVar15;
20: ulong uVar16;
21: uint uVar17;
22: long lVar18;
23: long lVar19;
24: long lVar20;
25: int *piVar21;
26: int iStack76;
27: short sStack64;
28: short sStack60;
29: 
30: pcVar5 = param_1[0x4a];
31: if (*(int *)(param_1 + 0x2e) != 0) {
32: iVar12 = *(int *)(pcVar5 + 0x4c);
33: if (iVar12 == 0) {
34: FUN_0014c910();
35: iVar12 = *(int *)(pcVar5 + 0x4c);
36: }
37: *(int *)(pcVar5 + 0x4c) = iVar12 + -1;
38: }
39: if (*(int *)(pcVar5 + 0x28) != -1) {
40: uVar3 = *(undefined4 *)(param_1 + 0x43);
41: iVar12 = *(int *)(param_1 + 0x42);
42: lVar6 = *param_2;
43: iVar4 = *(int *)(param_1[0x37] + 0x18);
44: iStack76 = iVar12;
45: if ((0 < iVar12) &&
46: (*(short *)(lVar6 + (long)*(int *)(&DAT_0018f100 + (long)iVar12 * 4) * 2) == 0)) {
47: lVar13 = (long)(int)(iVar12 - 1U);
48: lVar18 = lVar13 - (ulong)(iVar12 - 1U);
49: do {
50: iStack76 = (int)lVar13;
51: if (lVar18 == lVar13) break;
52: lVar8 = lVar13 * 4;
53: lVar13 = lVar13 + -1;
54: } while (*(short *)(lVar6 + (long)*(int *)(&DAT_0018f100 + lVar8) * 2) == 0);
55: }
56: iVar11 = *(int *)((long)param_1 + 0x20c);
57: if (iVar11 <= iVar12) {
58: LAB_0014da87:
59: do {
60: lVar13 = (long)(iVar11 * 3 + -3) + *(long *)(pcVar5 + ((long)iVar4 + 0x1a) * 8);
61: if ((iStack76 < iVar11) && (iVar12 = FUN_0014cee0(param_1,lVar13), iVar12 != 0)) {
62: return 1;
63: }
64: piVar21 = (int *)(&DAT_0018f100 + (long)iVar11 * 4);
65: iVar12 = iVar11;
66: while( true ) {
67: psVar1 = (short *)(lVar6 + (long)*piVar21 * 2);
68: sStack64 = (short)(-1 << ((byte)uVar3 & 0x1f));
69: sStack60 = (short)(1 << ((byte)uVar3 & 0x1f));
70: if (*psVar1 != 0) break;
71: pcVar7 = param_1[0x4a];
72: lVar18 = *(long *)(pcVar7 + 0x20);
73: iVar11 = *(int *)(pcVar7 + 0x28);
74: joined_r0x0014daf0:
75: if (lVar18 < 0x8000) {
76: do {
77: iVar11 = iVar11 + -1;
78: *(int *)(pcVar7 + 0x28) = iVar11;
79: if (iVar11 < 0) {
80: uVar16 = 0;
81: if (*(int *)((long)param_1 + 0x21c) == 0) {
82: ppbVar9 = (byte **)param_1[5];
83: pbVar14 = ppbVar9[1];
84: if (pbVar14 == (byte *)0x0) {
85: iVar11 = (*(code *)ppbVar9[3])();
86: if (iVar11 == 0) {
87: ppcVar10 = (code **)*param_1;
88: *(undefined4 *)(ppcVar10 + 5) = 0x18;
89: (**ppcVar10)();
90: }
91: pbVar14 = ppbVar9[1];
92: }
93: ppbVar9[1] = pbVar14 + -1;
94: pbVar14 = *ppbVar9;
95: *ppbVar9 = pbVar14 + 1;
96: bVar2 = *pbVar14;
97: if (bVar2 == 0xff) {
98: do {
99: ppbVar9 = (byte **)param_1[5];
100: pbVar14 = ppbVar9[1];
101: if (pbVar14 == (byte *)0x0) {
102: iVar11 = (*(code *)ppbVar9[3])();
103: if (iVar11 == 0) {
104: ppcVar10 = (code **)*param_1;
105: *(undefined4 *)(ppcVar10 + 5) = 0x18;
106: (**ppcVar10)();
107: }
108: pbVar14 = ppbVar9[1];
109: }
110: ppbVar9[1] = pbVar14 + -1;
111: pbVar14 = *ppbVar9;
112: *ppbVar9 = pbVar14 + 1;
113: bVar2 = *pbVar14;
114: } while (bVar2 == 0xff);
115: if (bVar2 == 0) {
116: iVar11 = *(int *)(pcVar7 + 0x28);
117: uVar16 = 0xff;
118: }
119: else {
120: *(uint *)((long)param_1 + 0x21c) = (uint)bVar2;
121: iVar11 = *(int *)(pcVar7 + 0x28);
122: uVar16 = 0;
123: }
124: }
125: else {
126: uVar16 = (ulong)bVar2;
127: iVar11 = *(int *)(pcVar7 + 0x28);
128: }
129: }
130: iVar15 = iVar11 + 8;
131: *(ulong *)(pcVar7 + 0x18) = *(long *)(pcVar7 + 0x18) << 8 | uVar16;
132: *(int *)(pcVar7 + 0x28) = iVar15;
133: if (-1 < iVar15) goto code_r0x0014db41;
134: iVar11 = iVar11 + 9;
135: *(int *)(pcVar7 + 0x28) = iVar11;
136: if (iVar11 == 0) {
137: *(undefined8 *)(pcVar7 + 0x20) = 0x10000;
138: lVar18 = 0x10000;
139: break;
140: }
141: lVar18 = *(long *)(pcVar7 + 0x20);
142: }
143: lVar18 = lVar18 * 2;
144: *(long *)(pcVar7 + 0x20) = lVar18;
145: if (0x7fff < lVar18) break;
146: } while( true );
147: }
148: bVar2 = *(byte *)(lVar13 + 1);
149: lVar8 = *(long *)(&DAT_0018f280 + (ulong)(bVar2 & 0x7f) * 8);
150: lVar19 = lVar8 >> 0x10;
151: lVar18 = lVar18 - lVar19;
152: *(long *)(pcVar7 + 0x20) = lVar18;
153: lVar20 = lVar18 << ((byte)iVar11 & 0x3f);
154: uVar17 = (uint)bVar2;
155: if (*(long *)(pcVar7 + 0x18) < lVar20) {
156: if (lVar18 < 0x8000) goto joined_r0x0014dd14;
157: }
158: else {
159: *(long *)(pcVar7 + 0x20) = lVar19;
160: *(long *)(pcVar7 + 0x18) = *(long *)(pcVar7 + 0x18) - lVar20;
161: joined_r0x0014dd14:
162: if (lVar18 < lVar19) {
163: *(byte *)(lVar13 + 1) = (byte)lVar8 ^ bVar2 & 0x80;
164: uVar17 = bVar2 - 0x80 & 0xff;
165: }
166: else {
167: *(byte *)(lVar13 + 1) = (byte)((ulong)lVar8 >> 8) ^ bVar2 & 0x80;
168: }
169: }
170: if ((int)uVar17 >> 7 != 0) {
171: iVar11 = FUN_0014cee0(param_1,pcVar5 + 0x150);
172: if (iVar11 == 0) {
173: sStack64 = sStack60;
174: }
175: *psVar1 = sStack64;
176: goto LAB_0014dd61;
177: }
178: iVar12 = iVar12 + 1;
179: lVar13 = lVar13 + 3;
180: piVar21 = piVar21 + 1;
181: if (*(int *)(param_1 + 0x42) < iVar12) {
182: pcVar7 = *param_1;
183: *(undefined4 *)(pcVar7 + 0x28) = 0x7e;
184: (**(code **)(pcVar7 + 8))(param_1,0xffffffff);
185: *(undefined4 *)(pcVar5 + 0x28) = 0xffffffff;
186: return 1;
187: }
188: }
189: iVar11 = iVar12 + 1;
190: iVar15 = FUN_0014cee0(param_1);
191: if (iVar15 == 0) {
192: LAB_0014dd61:
193: iVar11 = iVar12 + 1;
194: if (*(int *)(param_1 + 0x42) < iVar11) {
195: return 1;
196: }
197: goto LAB_0014da87;
198: }
199: if (-1 < *psVar1) {
200: sStack64 = sStack60;
201: }
202: iVar12 = *(int *)(param_1 + 0x42);
203: *psVar1 = sStack64 + *psVar1;
204: } while (iVar11 <= iVar12);
205: }
206: }
207: return 1;
208: code_r0x0014db41:
209: lVar18 = *(long *)(pcVar7 + 0x20) * 2;
210: *(long *)(pcVar7 + 0x20) = lVar18;
211: iVar11 = iVar15;
212: goto joined_r0x0014daf0;
213: }
214: 
