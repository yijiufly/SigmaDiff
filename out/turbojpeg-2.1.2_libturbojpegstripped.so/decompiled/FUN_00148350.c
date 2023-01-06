1: 
2: void FUN_00148350(long *param_1)
3: 
4: {
5: int iVar1;
6: undefined4 uVar2;
7: long lVar3;
8: undefined8 *puVar4;
9: int iVar5;
10: undefined8 *puVar6;
11: int iVar7;
12: ushort *puVar8;
13: long lVar9;
14: undefined8 *puVar10;
15: ulong uVar11;
16: undefined8 *puVar12;
17: int iVar13;
18: long lVar14;
19: long lVar15;
20: long lVar16;
21: long lVar17;
22: ushort *puVar18;
23: int iVar19;
24: long *plStack152;
25: int iStack136;
26: undefined8 *puStack96;
27: long lStack88;
28: int iStack76;
29: 
30: lVar3 = param_1[0x4e];
31: param_1[0x14] = *(long *)(lVar3 + 0x20);
32: iVar1 = *(int *)(lVar3 + 0x28);
33: puStack96 = (undefined8 *)(**(code **)param_1[1])(param_1,1,(long)iVar1 * 0x28);
34: lVar9 = param_1[0x4e];
35: uVar2 = *(undefined4 *)(param_1 + 8);
36: *puStack96 = 0x1f00000000;
37: puStack96[1] = 0x3f00000000;
38: *(undefined4 *)(puStack96 + 2) = 0;
39: *(undefined4 *)((long)puStack96 + 0x14) = 0x1f;
40: FUN_00146ad0(0x1f00000000,uVar2,lVar9,puStack96);
41: if (iVar1 < 2) {
42: iStack76 = 1;
43: }
44: else {
45: iStack76 = 1;
46: puVar4 = puStack96;
47: do {
48: puVar12 = puVar4 + 5;
49: puVar10 = (undefined8 *)0x0;
50: if (iVar1 < iStack76 * 2) {
51: lVar9 = 0;
52: puVar6 = puStack96;
53: do {
54: if (lVar9 < (long)puVar6[3]) {
55: lVar9 = puVar6[3];
56: puVar10 = puVar6;
57: }
58: puVar6 = puVar6 + 5;
59: } while (puVar6 != puVar12);
60: }
61: else {
62: lVar9 = 0;
63: puVar6 = puStack96;
64: do {
65: if ((lVar9 < (long)puVar6[4]) && (0 < (long)puVar6[3])) {
66: puVar10 = puVar6;
67: lVar9 = puVar6[4];
68: }
69: puVar6 = puVar6 + 5;
70: } while (puVar6 != puVar12);
71: }
72: if (puVar10 == (undefined8 *)0x0) break;
73: uVar11 = (ulong)*(uint *)(param_1 + 8);
74: *(undefined4 *)((long)puVar4 + 0x2c) = *(undefined4 *)((long)puVar10 + 4);
75: iVar5 = *(int *)(&DAT_0018f020 + uVar11 * 4);
76: *(undefined4 *)((long)puVar4 + 0x34) = *(undefined4 *)((long)puVar10 + 0xc);
77: *(undefined4 *)((long)puVar4 + 0x3c) = *(undefined4 *)((long)puVar10 + 0x14);
78: *(undefined4 *)puVar12 = *(undefined4 *)puVar10;
79: *(undefined4 *)(puVar4 + 6) = *(undefined4 *)(puVar10 + 1);
80: *(undefined4 *)(puVar4 + 7) = *(undefined4 *)(puVar10 + 2);
81: iVar7 = (*(int *)((long)puVar10 + 4) - *(int *)puVar10) * 8 *
82: *(int *)(&DAT_0018efa0 + (long)*(int *)(&DAT_0018f080 + uVar11 * 4) * 4);
83: iVar5 = (*(int *)((long)puVar10 + 0xc) - *(int *)(puVar10 + 1)) * 4 *
84: *(int *)(&DAT_0018efa0 + (long)iVar5 * 4);
85: iVar13 = (*(int *)((long)puVar10 + 0x14) - *(int *)(puVar10 + 2)) * 8 *
86: *(int *)(&DAT_0018efa0 + (long)*(int *)(&DAT_0018efc0 + uVar11 * 4) * 4);
87: if (*(int *)(&DAT_0018f080 + uVar11 * 4) == 0) {
88: if (iVar5 < iVar7) {
89: if (iVar13 <= iVar7) goto LAB_0014879b;
90: }
91: else {
92: if (iVar13 <= iVar5) {
93: LAB_001484e8:
94: iVar5 = (*(int *)((long)puVar10 + 0xc) + *(int *)(puVar10 + 1)) / 2;
95: *(int *)((long)puVar10 + 0xc) = iVar5;
96: *(int *)(puVar4 + 6) = iVar5 + 1;
97: goto LAB_00148502;
98: }
99: }
100: LAB_001487bf:
101: iVar5 = (*(int *)((long)puVar10 + 0x14) + *(int *)(puVar10 + 2)) / 2;
102: *(int *)((long)puVar10 + 0x14) = iVar5;
103: *(int *)(puVar4 + 7) = iVar5 + 1;
104: }
105: else {
106: if (iVar5 < iVar13) {
107: if (iVar7 <= iVar13) goto LAB_001487bf;
108: }
109: else {
110: if (iVar7 <= iVar5) goto LAB_001484e8;
111: }
112: LAB_0014879b:
113: iVar5 = (*(int *)((long)puVar10 + 4) + *(int *)puVar10) / 2;
114: *(int *)((long)puVar10 + 4) = iVar5;
115: *(int *)puVar12 = iVar5 + 1;
116: }
117: LAB_00148502:
118: iStack76 = iStack76 + 1;
119: FUN_00146ad0(uVar11,param_1[0x4e]);
120: FUN_00146ad0(*(undefined4 *)(param_1 + 8),param_1[0x4e],puVar12);
121: puVar4 = puVar12;
122: } while (iVar1 != iStack76);
123: }
124: lStack88 = 0;
125: do {
126: iVar1 = *(int *)puStack96;
127: iVar5 = *(int *)(puStack96 + 1);
128: iVar7 = *(int *)(puStack96 + 2);
129: if (*(int *)((long)puStack96 + 4) < iVar1) {
130: do {
131: invalidInstructionException();
132: } while( true );
133: }
134: plStack152 = (long *)(*(long *)(param_1[0x4e] + 0x30) + (long)iVar1 * 8);
135: iStack136 = iVar1 * 8 + 4;
136: lVar9 = (long)iVar5 * 0x40 + (long)iVar7 * 2;
137: lVar15 = 0;
138: lVar17 = 0;
139: lVar16 = 0;
140: lVar14 = 0;
141: do {
142: if (iVar5 <= *(int *)((long)puStack96 + 0xc)) {
143: puVar18 = (ushort *)(*plStack152 + lVar9);
144: iVar19 = iVar7 * 2 - (int)puVar18;
145: iVar13 = iVar5 * 4 + 2;
146: do {
147: if (iVar7 <= *(int *)((long)puStack96 + 0x14)) {
148: puVar8 = puVar18;
149: do {
150: uVar11 = (ulong)*puVar8;
151: if (uVar11 != 0) {
152: lVar14 = lVar14 + uVar11;
153: lVar16 = lVar16 + (long)iStack136 * uVar11;
154: lVar15 = lVar15 + (long)iVar13 * uVar11;
155: lVar17 = lVar17 + (long)((iVar19 + 1 + (int)puVar8) * 4) * uVar11;
156: }
157: puVar8 = puVar8 + 1;
158: } while (puVar18 + (ulong)(uint)(*(int *)((long)puStack96 + 0x14) - iVar7) + 1 != puVar8
159: );
160: }
161: puVar18 = puVar18 + 0x20;
162: iVar19 = iVar19 + -0x40;
163: iVar13 = iVar13 + 4;
164: } while ((ushort *)
165: (*plStack152 +
166: (ulong)(uint)(*(int *)((long)puStack96 + 0xc) - iVar5) * 0x40 + 0x40 + lVar9) !=
167: puVar18);
168: }
169: plStack152 = plStack152 + 1;
170: iStack136 = iStack136 + 8;
171: } while ((long *)(*(long *)(param_1[0x4e] + 0x30) + 8 +
172: ((ulong)(uint)(*(int *)((long)puStack96 + 4) - iVar1) + (long)iVar1) * 8) !=
173: plStack152);
174: lVar9 = lVar14 >> 1;
175: puStack96 = puStack96 + 5;
176: *(char *)(*(long *)param_1[0x14] + lStack88) = (char)((lVar9 + lVar16) / lVar14);
177: *(char *)(*(long *)(param_1[0x14] + 8) + lStack88) = (char)((lVar9 + lVar15) / lVar14);
178: *(char *)(*(long *)(param_1[0x14] + 0x10) + lStack88) = (char)((lVar9 + lVar17) / lVar14);
179: lStack88 = lStack88 + 1;
180: } while (lStack88 != (ulong)(iStack76 - 1) + 1);
181: lVar15 = *param_1;
182: *(int *)((long)param_1 + 0x9c) = iStack76;
183: *(int *)(lVar15 + 0x2c) = iStack76;
184: *(undefined4 *)(lVar15 + 0x28) = 0x60;
185: (**(code **)(lVar15 + 8))(param_1,1,(lVar9 + lVar17) % lVar14);
186: *(undefined4 *)(lVar3 + 0x38) = 1;
187: return;
188: }
189: 
