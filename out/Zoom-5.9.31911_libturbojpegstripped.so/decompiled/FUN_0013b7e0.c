1: 
2: /* WARNING: Could not reconcile some variable overlaps */
3: 
4: void FUN_0013b7e0(long *param_1)
5: 
6: {
7: int iVar1;
8: long lVar2;
9: int *piVar3;
10: int *piVar4;
11: ulong uVar5;
12: long lVar6;
13: int iVar7;
14: int iVar8;
15: ushort *puVar9;
16: int *piVar10;
17: long lVar11;
18: int *piVar12;
19: int iVar13;
20: long lVar14;
21: char cVar15;
22: long lVar16;
23: long lVar17;
24: ushort *puVar18;
25: int iStack124;
26: long *plStack120;
27: int iStack92;
28: long lStack80;
29: int *piStack72;
30: 
31: lVar2 = param_1[0x4e];
32: iVar1 = *(int *)(lVar2 + 0x28);
33: param_1[0x14] = *(long *)(lVar2 + 0x20);
34: piStack72 = (int *)(**(code **)param_1[1])(param_1,1,(long)iVar1 * 0x28);
35: *piStack72 = 0;
36: piStack72[1] = 0x1f;
37: piStack72[2] = 0;
38: piStack72[3] = 0x3f;
39: piStack72[4] = 0;
40: piStack72[5] = 0x1f;
41: FUN_0013a420(*(undefined4 *)(param_1 + 8),param_1[0x4e],piStack72);
42: iStack92 = 1;
43: if (1 < iVar1) {
44: iStack92 = 1;
45: piVar3 = piStack72;
46: do {
47: piVar12 = piVar3 + 10;
48: if (SBORROW4(iVar1,iStack92 * 2) == iVar1 + iStack92 * -2 < 0) {
49: piVar10 = (int *)0x0;
50: iVar7 = 0;
51: lVar6 = 0;
52: piVar4 = piStack72;
53: do {
54: if ((lVar6 < *(long *)(piVar4 + 8)) && (0 < *(long *)(piVar4 + 6))) {
55: piVar10 = piVar4;
56: lVar6 = *(long *)(piVar4 + 8);
57: }
58: iVar7 = iVar7 + 1;
59: piVar4 = piVar4 + 10;
60: } while (iVar7 < iStack92);
61: }
62: else {
63: piVar10 = (int *)0x0;
64: iVar7 = 0;
65: lVar6 = 0;
66: piVar4 = piStack72;
67: do {
68: lVar16 = *(long *)(piVar4 + 6);
69: lVar14 = lVar6;
70: if (lVar6 <= lVar16) {
71: lVar14 = lVar16;
72: }
73: if (lVar6 < lVar16) {
74: piVar10 = piVar4;
75: }
76: iVar7 = iVar7 + 1;
77: piVar4 = piVar4 + 10;
78: lVar6 = lVar14;
79: } while (iVar7 < iStack92);
80: }
81: if (piVar10 == (int *)0x0) break;
82: uVar5 = (ulong)*(uint *)(param_1 + 8);
83: piVar3[0xb] = piVar10[1];
84: piVar3[0xd] = piVar10[3];
85: piVar3[0xf] = piVar10[5];
86: *piVar12 = *piVar10;
87: piVar3[0xc] = piVar10[2];
88: piVar3[0xe] = piVar10[4];
89: iVar8 = (piVar10[1] - *piVar10) * 8 *
90: *(int *)(&DAT_0018b320 + (long)*(int *)(&DAT_0018b400 + uVar5 * 4) * 4);
91: iVar13 = (piVar10[3] - piVar10[2]) * 4 *
92: *(int *)(&DAT_0018b320 + (long)*(int *)(&DAT_0018b3a0 + uVar5 * 4) * 4);
93: iVar7 = (piVar10[5] - piVar10[4]) * 8 *
94: *(int *)(&DAT_0018b320 + (long)*(int *)(&DAT_0018b340 + uVar5 * 4) * 4);
95: if (*(int *)(&DAT_0018b400 + uVar5 * 4) == 0) {
96: cVar15 = iVar8 <= iVar13;
97: if ((bool)cVar15) {
98: iVar8 = iVar13;
99: }
100: if (iVar7 <= iVar8) {
101: LAB_0013bc0a:
102: if (cVar15 == '\x01') {
103: iVar7 = (piVar10[3] + piVar10[2]) / 2;
104: piVar10[3] = iVar7;
105: piVar3[0xc] = iVar7 + 1;
106: goto LAB_0013b99a;
107: }
108: if (cVar15 != '\x02') goto LAB_0013bbef;
109: }
110: iVar7 = (piVar10[5] + piVar10[4]) / 2;
111: piVar10[5] = iVar7;
112: piVar3[0xe] = iVar7 + 1;
113: }
114: else {
115: cVar15 = '\x02';
116: if (iVar7 <= iVar13) {
117: cVar15 = '\x01';
118: iVar7 = iVar13;
119: }
120: if (iVar8 <= iVar7) goto LAB_0013bc0a;
121: LAB_0013bbef:
122: iVar7 = (*piVar10 + piVar10[1]) / 2;
123: piVar10[1] = iVar7;
124: *piVar12 = iVar7 + 1;
125: }
126: LAB_0013b99a:
127: iStack92 = iStack92 + 1;
128: FUN_0013a420(*(undefined4 *)(param_1 + 8),param_1[0x4e]);
129: FUN_0013a420(*(undefined4 *)(param_1 + 8),param_1[0x4e],piVar12);
130: piVar3 = piVar12;
131: } while (iStack92 != iVar1);
132: }
133: lStack80 = 0;
134: do {
135: iVar1 = piStack72[2];
136: iVar7 = piStack72[4];
137: iStack124 = *piStack72;
138: if (piStack72[1] < iStack124) {
139: lVar14 = 0;
140: lVar16 = 0;
141: lVar6 = 0;
142: lVar17 = 0;
143: }
144: else {
145: plStack120 = (long *)(*(long *)(param_1[0x4e] + 0x30) + (long)iStack124 * 8);
146: lVar14 = 0;
147: lVar16 = 0;
148: lVar6 = 0;
149: lVar17 = 0;
150: do {
151: if (iVar1 <= piStack72[3]) {
152: puVar18 = (ushort *)(((long)iVar1 * 0x20 + (long)iVar7) * 2 + *plStack120);
153: iVar8 = iVar1;
154: do {
155: if (iVar7 <= piStack72[5]) {
156: puVar9 = puVar18;
157: iVar13 = iVar7;
158: do {
159: uVar5 = (ulong)*puVar9;
160: lVar17 = lVar17 + uVar5;
161: if (uVar5 != 0) {
162: lVar14 = (long)(iVar13 * 8 + 4) * uVar5 + lVar14;
163: lVar6 = uVar5 * (long)(iStack124 * 8 + 4) + lVar6;
164: lVar16 = uVar5 * (long)(iVar8 * 4 + 2) + lVar16;
165: }
166: iVar13 = iVar13 + 1;
167: puVar9 = puVar9 + 1;
168: } while (iVar13 != piStack72[5] + 1);
169: }
170: iVar8 = iVar8 + 1;
171: puVar18 = puVar18 + 0x20;
172: } while (iVar8 != piStack72[3] + 1);
173: }
174: iStack124 = iStack124 + 1;
175: plStack120 = plStack120 + 1;
176: } while (iStack124 != piStack72[1] + 1);
177: lVar11 = lVar17 >> 1;
178: lVar6 = lVar6 + lVar11;
179: lVar16 = lVar16 + lVar11;
180: lVar14 = lVar14 + lVar11;
181: }
182: piStack72 = piStack72 + 10;
183: *(char *)(*(long *)param_1[0x14] + lStack80) = (char)(lVar6 / lVar17);
184: *(char *)(*(long *)(param_1[0x14] + 8) + lStack80) = (char)(lVar16 / lVar17);
185: *(char *)(*(long *)(param_1[0x14] + 0x10) + lStack80) = (char)(lVar14 / lVar17);
186: lStack80._0_4_ = (int)(lStack80 + 1);
187: lStack80 = lStack80 + 1;
188: } while ((int)lStack80 < iStack92);
189: lVar6 = *param_1;
190: *(int *)((long)param_1 + 0x9c) = iStack92;
191: *(undefined4 *)(lVar6 + 0x28) = 0x60;
192: *(int *)(lVar6 + 0x2c) = iStack92;
193: (**(code **)(*param_1 + 8))(param_1,1,lVar14 % lVar17);
194: *(undefined4 *)(lVar2 + 0x38) = 1;
195: return;
196: }
197: 
