1: 
2: void FUN_00124000(code **param_1)
3: 
4: {
5: code *pcVar1;
6: long *plVar2;
7: code **ppcVar3;
8: code *pcVar4;
9: uint uVar5;
10: undefined4 uVar6;
11: int iVar7;
12: code **ppcVar8;
13: code *pcVar9;
14: undefined8 *puVar10;
15: ulong uVar11;
16: uint uVar12;
17: code *pcVar13;
18: long lVar14;
19: long lVar15;
20: ulong uVar16;
21: ulong uVar17;
22: ulong uVar18;
23: ulong uVar19;
24: 
25: ppcVar8 = (code **)(**(code **)param_1[1])(param_1,1,0x38);
26: uVar12 = *(uint *)((long)param_1 + 0x3c);
27: param_1[0x4d] = (code *)ppcVar8;
28: *ppcVar8 = FUN_00123fd0;
29: switch(uVar12) {
30: default:
31: if (*(int *)(param_1 + 7) < 1) {
32: LAB_00124056:
33: ppcVar3 = (code **)*param_1;
34: *(undefined4 *)(ppcVar3 + 5) = 10;
35: (**ppcVar3)(param_1);
36: uVar12 = *(uint *)((long)param_1 + 0x3c);
37: }
38: break;
39: case 1:
40: uVar12 = 1;
41: if (*(int *)(param_1 + 7) != 1) goto LAB_00124056;
42: break;
43: case 2:
44: case 3:
45: if (*(int *)(param_1 + 7) != 3) goto LAB_00124056;
46: uVar5 = *(uint *)(param_1 + 8);
47: if (uVar5 < 0x11) goto code_r0x00124070;
48: goto LAB_001240a0;
49: case 4:
50: case 5:
51: if (*(int *)(param_1 + 7) != 4) goto LAB_00124056;
52: }
53: uVar5 = *(uint *)(param_1 + 8);
54: if (uVar5 < 0x11) {
55: code_r0x00124070:
56: uVar16 = (ulong)uVar5;
57: switch(&DAT_00189670 + *(int *)(&DAT_00189670 + uVar16 * 4)) {
58: case (undefined *)0x1240a0:
59: goto LAB_001240a0;
60: case (undefined *)0x1240f8:
61: *(undefined4 *)(param_1 + 0x12) = 3;
62: if (*(int *)(param_1 + 0xe) == 0) {
63: if (uVar12 == 3) {
64: iVar7 = FUN_00167d50();
65: if (iVar7 == 0) {
66: ppcVar8[1] = FUN_00122950;
67: FUN_00120610(param_1);
68: }
69: else {
70: ppcVar8[1] = FUN_00167fd0;
71: }
72: goto LAB_001240b7;
73: }
74: if (uVar12 == 1) {
75: ppcVar8[1] = FUN_00123980;
76: goto LAB_001240b7;
77: }
78: if (uVar12 == 2) {
79: ppcVar8[1] = FUN_001230c0;
80: goto LAB_001240b7;
81: }
82: }
83: else {
84: if (uVar12 == 3) {
85: ppcVar8[1] = FUN_00122ca0;
86: FUN_00120610(param_1);
87: goto LAB_001240b7;
88: }
89: if (uVar12 == 1) {
90: ppcVar8[1] = FUN_00123e00;
91: goto LAB_001240b7;
92: }
93: if (uVar12 == 2) {
94: ppcVar8[1] = FUN_00123700;
95: goto LAB_001240b7;
96: }
97: }
98: break;
99: case (undefined *)0x124138:
100: *(undefined4 *)(param_1 + 0x12) = 4;
101: if (uVar12 == 5) {
102: ppcVar8[1] = FUN_00122810;
103: FUN_00120610(param_1);
104: goto LAB_001240b7;
105: }
106: if (uVar12 != 4) break;
107: goto LAB_00124154;
108: case (undefined *)0x124168:
109: iVar7 = *(int *)(&UNK_001896e0 + uVar16 * 4);
110: *(int *)(param_1 + 0x12) = iVar7;
111: if (uVar12 == 3) {
112: iVar7 = FUN_00167cf0();
113: if (iVar7 == 0) {
114: ppcVar8[1] = FUN_00120710;
115: FUN_00120610(param_1);
116: }
117: else {
118: ppcVar8[1] = FUN_00167f00;
119: }
120: goto LAB_001240b7;
121: }
122: if (uVar12 == 1) {
123: ppcVar8[1] = FUN_00121000;
124: goto LAB_001240b7;
125: }
126: if (uVar12 == 2) {
127: if ((((*(int *)(&UNK_00189800 + uVar16 * 4) != 0) ||
128: (*(int *)(&UNK_001897a0 + uVar16 * 4) != 1)) ||
129: (*(int *)(&UNK_00189740 + uVar16 * 4) != 2)) || (iVar7 != 3)) {
130: ppcVar8[1] = FUN_00121ef0;
131: goto LAB_001240b7;
132: }
133: goto LAB_00124154;
134: }
135: break;
136: case (undefined *)0x1241d0:
137: *(undefined4 *)(param_1 + 0x12) = 1;
138: if ((uVar12 & 0xfffffffd) == 1) {
139: iVar7 = *(int *)(param_1 + 7);
140: ppcVar8[1] = FUN_00123fe0;
141: if (1 < iVar7) {
142: pcVar1 = param_1[0x26] + 0x60;
143: pcVar4 = pcVar1;
144: pcVar13 = param_1[0x26];
145: while (pcVar9 = pcVar4, *(undefined4 *)(pcVar13 + 0x90) = 0,
146: pcVar9 != pcVar1 + (ulong)(iVar7 - 2) * 0x60) {
147: pcVar4 = pcVar9 + 0x60;
148: pcVar13 = pcVar9;
149: }
150: }
151: goto LAB_001240b7;
152: }
153: if (uVar12 == 2) {
154: ppcVar8[1] = FUN_00120c70;
155: pcVar1 = param_1[0x4d];
156: puVar10 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x1800);
157: *(undefined8 **)(pcVar1 + 0x30) = puVar10;
158: lVar14 = (long)puVar10 << 0x3c;
159: if (lVar14 < 0) {
160: *puVar10 = 0;
161: puVar10[0x100] = 0;
162: puVar10[0x200] = 0x8000;
163: }
164: uVar17 = (ulong)(lVar14 < 0);
165: uVar18 = (lVar14 >> 0x3f) + 0x100;
166: lVar14 = (lVar14 >> 0x3f) * -8;
167: lVar15 = 0;
168: uVar11 = 0;
169: uVar16 = uVar17;
170: uVar19 = uVar17 + 1;
171: do {
172: uVar11 = uVar11 + 1;
173: plVar2 = (long *)((long)puVar10 + lVar15 + lVar14);
174: *plVar2 = (uVar16 & 0xffffffff) * 0x4c8b + ((uVar16 >> 0x20) * 0x4c8b << 0x20);
175: plVar2[1] = (uVar19 & 0xffffffff) * 0x4c8b + ((uVar19 >> 0x20) * 0x4c8b << 0x20);
176: plVar2 = (long *)((long)puVar10 + lVar15 + lVar14 + 0x800);
177: *plVar2 = (uVar16 & 0xffffffff) * 0x9646 + ((uVar16 >> 0x20) * 0x9646 << 0x20);
178: plVar2[1] = (uVar19 & 0xffffffff) * 0x9646 + ((uVar19 >> 0x20) * 0x9646 << 0x20);
179: plVar2 = (long *)((long)puVar10 + lVar15 + lVar14 + 0x1000);
180: *plVar2 = uVar16 * 0x1d2f + 0x8000;
181: plVar2[1] = uVar19 * 0x1d2f + 0x8000;
182: lVar15 = lVar15 + 0x10;
183: uVar16 = uVar16 + 2;
184: uVar19 = uVar19 + 2;
185: } while (uVar11 < uVar18 >> 1);
186: lVar14 = uVar17 + (uVar18 & 0xfffffffffffffffe);
187: if (uVar18 != (uVar18 & 0xfffffffffffffffe)) {
188: puVar10[lVar14] = lVar14 * 0x4c8b;
189: puVar10[lVar14 + 0x100] = lVar14 * 0x9646;
190: puVar10[lVar14 + 0x200] = lVar14 * 0x1d2f + 0x8000;
191: }
192: goto LAB_001240b7;
193: }
194: }
195: }
196: else {
197: LAB_001240a0:
198: if (uVar5 == uVar12) {
199: *(undefined4 *)(param_1 + 0x12) = *(undefined4 *)(param_1 + 7);
200: LAB_00124154:
201: ppcVar8[1] = FUN_00120d10;
202: goto LAB_001240b7;
203: }
204: }
205: ppcVar8 = (code **)*param_1;
206: *(undefined4 *)(ppcVar8 + 5) = 0x1b;
207: (**ppcVar8)(param_1);
208: LAB_001240b7:
209: uVar6 = 1;
210: if (*(int *)((long)param_1 + 0x6c) == 0) {
211: uVar6 = *(undefined4 *)(param_1 + 0x12);
212: }
213: *(undefined4 *)((long)param_1 + 0x94) = uVar6;
214: return;
215: }
216: 
