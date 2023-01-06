1: 
2: undefined8 FUN_00130700(long *param_1,long *param_2)
3: 
4: {
5: int *piVar1;
6: short *psVar2;
7: short sVar3;
8: int iVar4;
9: undefined4 uVar5;
10: undefined4 uVar6;
11: long lVar7;
12: long lVar8;
13: long lVar9;
14: int iVar10;
15: uint uVar11;
16: ulong uVar12;
17: undefined8 *puVar13;
18: uint uVar14;
19: uint uVar15;
20: ulong uVar16;
21: int iVar17;
22: long lVar18;
23: uint uVar19;
24: uint uVar20;
25: int iVar21;
26: short sStack388;
27: int iStack368;
28: int iStack364;
29: undefined8 uStack360;
30: undefined8 uStack352;
31: ulong uStack344;
32: uint uStack336;
33: long *plStack328;
34: int aiStack312 [66];
35: 
36: iVar4 = *(int *)(param_1 + 0x42);
37: lVar7 = param_1[0x4a];
38: uVar5 = *(undefined4 *)(param_1 + 0x43);
39: if ((*(int *)(param_1 + 0x2e) == 0) || (*(int *)(lVar7 + 0x3c) != 0)) {
40: iVar17 = *(int *)(lVar7 + 0x10);
41: LAB_00130752:
42: if (iVar17 != 0) goto LAB_00130979;
43: }
44: else {
45: iVar17 = *(int *)(lVar7 + 0x20);
46: lVar8 = param_1[0x49];
47: if (iVar17 < 0) {
48: iVar17 = iVar17 + 7;
49: }
50: piVar1 = (int *)(lVar8 + 0x24);
51: *piVar1 = *piVar1 + (iVar17 >> 3);
52: *(undefined4 *)(lVar7 + 0x20) = 0;
53: iVar17 = (**(code **)(lVar8 + 0x10))();
54: if (iVar17 == 0) {
55: return 0;
56: }
57: if (0 < *(int *)(param_1 + 0x36)) {
58: memset((void *)(lVar7 + 0x2c),0,(long)*(int *)(param_1 + 0x36) * 4);
59: }
60: uVar6 = *(undefined4 *)(param_1 + 0x2e);
61: iVar17 = *(int *)((long)param_1 + 0x21c);
62: *(undefined4 *)(lVar7 + 0x28) = 0;
63: *(undefined4 *)(lVar7 + 0x3c) = uVar6;
64: if (iVar17 != 0) {
65: iVar17 = *(int *)(lVar7 + 0x10);
66: goto LAB_00130752;
67: }
68: *(undefined4 *)(lVar7 + 0x10) = 0;
69: }
70: uVar20 = 1 << ((byte)uVar5 & 0x1f);
71: uVar15 = -1 << ((byte)uVar5 & 0x1f);
72: lVar8 = *param_2;
73: puVar13 = (undefined8 *)param_1[5];
74: iStack364 = *(int *)(lVar7 + 0x28);
75: lVar9 = *(long *)(lVar7 + 0x60);
76: uStack360 = *puVar13;
77: uStack352 = puVar13[1];
78: uVar12 = *(ulong *)(lVar7 + 0x18);
79: uVar14 = *(uint *)(lVar7 + 0x20);
80: uVar16 = (ulong)uVar14;
81: iVar17 = *(int *)((long)param_1 + 0x20c);
82: sStack388 = (short)uVar15;
83: plStack328 = param_1;
84: if (iStack364 == 0) {
85: if (iVar17 <= iVar4) {
86: iStack368 = 0;
87: do {
88: uVar14 = (uint)uVar16;
89: if ((int)(uint)uVar16 < 8) {
90: iVar21 = FUN_00125d30(&uStack360,uVar12);
91: if (iVar21 == 0) goto LAB_00130c44;
92: uVar12 = uStack344;
93: uVar14 = uStack336;
94: if (7 < (int)uStack336) goto LAB_001307e9;
95: LAB_00130ab2:
96: uVar11 = FUN_00125ea0(&uStack360,uVar12);
97: if ((int)uVar11 < 0) goto LAB_00130c44;
98: iVar21 = (int)uVar11 >> 4;
99: uVar19 = uVar11 & 0xf;
100: uVar12 = uStack344;
101: uVar14 = uStack336;
102: if ((uVar11 & 0xf) != 0) goto LAB_00130830;
103: LAB_00130ae7:
104: uVar16 = (ulong)uVar14;
105: if (iVar21 != 0xf) {
106: iStack364 = 1 << ((byte)iVar21 & 0x1f);
107: if (iVar21 != 0) {
108: if (((int)uVar14 < iVar21) &&
109: (iVar10 = FUN_00125d30(&uStack360,uVar12), uVar12 = uStack344, uVar14 = uStack336,
110: iVar10 == 0)) goto LAB_00130c44;
111: uVar16 = (ulong)(uVar14 - iVar21);
112: iStack364 = iStack364 +
113: (iStack364 - 1U & (uint)(uVar12 >> ((byte)(uVar14 - iVar21) & 0x3f)));
114: }
115: uVar14 = (uint)uVar16;
116: if (iStack364 != 0) goto LAB_0013099c;
117: break;
118: }
119: }
120: else {
121: LAB_001307e9:
122: uVar19 = *(uint *)(lVar9 + 0x128 + (uVar12 >> ((char)uVar14 - 8U & 0x3f) & 0xff) * 4);
123: if (8 < (int)uVar19 >> 8) goto LAB_00130ab2;
124: uVar14 = uVar14 - ((int)uVar19 >> 8);
125: iVar21 = (int)(uVar19 & 0xff) >> 4;
126: uVar19 = uVar19 & 0xf;
127: if (uVar19 == 0) goto LAB_00130ae7;
128: LAB_00130830:
129: if (uVar19 != 1) {
130: lVar18 = *param_1;
131: *(undefined4 *)(lVar18 + 0x28) = 0x76;
132: (**(code **)(lVar18 + 8))(param_1,0xffffffff);
133: }
134: if (((int)uVar14 < 1) &&
135: (iVar10 = FUN_00125d30(&uStack360,uVar12), uVar12 = uStack344, uVar14 = uStack336,
136: iVar10 == 0)) goto LAB_00130c44;
137: uVar16 = (ulong)(uVar14 - 1);
138: uVar19 = uVar15;
139: if ((uVar12 >> ((byte)(uVar14 - 1) & 0x3f) & 1) != 0) {
140: uVar19 = uVar20;
141: }
142: }
143: do {
144: psVar2 = (short *)(lVar8 + (long)*(int *)(&DAT_0018b460 + (long)iVar17 * 4) * 2);
145: if (*psVar2 == 0) {
146: iVar21 = iVar21 + -1;
147: if (iVar21 == -1) break;
148: }
149: else {
150: uVar14 = (uint)uVar16;
151: if (((int)(uint)uVar16 < 1) &&
152: (iVar10 = FUN_00125d30(&uStack360), uVar12 = uStack344, uVar14 = uStack336,
153: iVar10 == 0)) goto LAB_00130c44;
154: uVar16 = (ulong)(uVar14 - 1);
155: if (((uVar12 >> (uVar16 & 0x3f) & 1) != 0) &&
156: (sVar3 = *psVar2, ((int)sVar3 & uVar20) == 0)) {
157: if (sVar3 < 0) {
158: *psVar2 = sVar3 + sStack388;
159: }
160: else {
161: *psVar2 = sVar3 + (short)uVar20;
162: }
163: }
164: }
165: iVar17 = iVar17 + 1;
166: } while (iVar17 <= iVar4);
167: uVar14 = (uint)uVar16;
168: if (uVar19 != 0) {
169: iVar21 = *(int *)(&DAT_0018b460 + (long)iVar17 * 4);
170: *(short *)(lVar8 + (long)iVar21 * 2) = (short)uVar19;
171: lVar18 = (long)iStack368;
172: iStack368 = iStack368 + 1;
173: aiStack312[lVar18] = iVar21;
174: }
175: iVar17 = iVar17 + 1;
176: } while (iVar17 <= iVar4);
177: goto LAB_0013094c;
178: }
179: }
180: else {
181: iStack368 = 0;
182: LAB_0013099c:
183: uVar14 = (uint)uVar16;
184: if (iVar17 <= iVar4) {
185: do {
186: psVar2 = (short *)(lVar8 + (long)*(int *)(&DAT_0018b460 + (long)iVar17 * 4) * 2);
187: if (*psVar2 != 0) {
188: uVar15 = (uint)uVar16;
189: if (((int)(uint)uVar16 < 1) &&
190: (iVar21 = FUN_00125d30(&uStack360), uVar12 = uStack344, uVar15 = uStack336, iVar21 == 0
191: )) {
192: LAB_00130c44:
193: while (iStack368 != 0) {
194: iStack368 = iStack368 + -1;
195: *(undefined2 *)(lVar8 + (long)aiStack312[iStack368] * 2) = 0;
196: }
197: return 0;
198: }
199: uVar16 = (ulong)(uVar15 - 1);
200: if (((uVar12 >> (uVar16 & 0x3f) & 1) != 0) &&
201: (sVar3 = *psVar2, ((int)sVar3 & uVar20) == 0)) {
202: if (sVar3 < 0) {
203: *psVar2 = sVar3 + sStack388;
204: }
205: else {
206: *psVar2 = sVar3 + (short)uVar20;
207: }
208: }
209: }
210: uVar14 = (uint)uVar16;
211: iVar17 = iVar17 + 1;
212: } while (iVar17 <= iVar4);
213: }
214: iStack364 = iStack364 + -1;
215: LAB_0013094c:
216: puVar13 = (undefined8 *)param_1[5];
217: }
218: puVar13[1] = uStack352;
219: *puVar13 = uStack360;
220: *(ulong *)(lVar7 + 0x18) = uVar12;
221: *(uint *)(lVar7 + 0x20) = uVar14;
222: *(int *)(lVar7 + 0x28) = iStack364;
223: LAB_00130979:
224: *(int *)(lVar7 + 0x3c) = *(int *)(lVar7 + 0x3c) + -1;
225: return 1;
226: }
227: 
