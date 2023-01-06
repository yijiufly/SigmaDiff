1: 
2: undefined8 FUN_00150460(code **param_1,long param_2)
3: 
4: {
5: byte bVar1;
6: int iVar2;
7: uint uVar3;
8: int iVar4;
9: int iVar5;
10: int iVar6;
11: int iVar7;
12: int iVar8;
13: long *plVar9;
14: code *pcVar10;
15: code **ppcVar11;
16: undefined uVar12;
17: byte **ppbVar13;
18: ulong uVar14;
19: undefined *puVar15;
20: size_t sVar16;
21: undefined uVar17;
22: long lVar18;
23: undefined uVar19;
24: byte *pbVar20;
25: byte *pbVar21;
26: byte *pbVar22;
27: undefined *puVar23;
28: undefined *puVar24;
29: double dVar25;
30: double dVar26;
31: double dVar27;
32: double dVar28;
33: double dVar29;
34: 
35: plVar9 = *(long **)(param_2 + 0x38);
36: iVar2 = *(int *)(param_2 + 0x54);
37: if (*(int *)(param_2 + 0x58) == 0) {
38: sVar16 = fread(*(void **)(param_2 + 0x60),1,(ulong)*(uint *)(param_2 + 0x4c),
39: *(FILE **)(param_2 + 0x18));
40: if (sVar16 != *(uint *)(param_2 + 0x4c)) {
41: ppcVar11 = (code **)*param_1;
42: *(undefined4 *)(ppcVar11 + 5) = 0x2b;
43: (**ppcVar11)();
44: }
45: pbVar21 = *(byte **)(param_2 + 0x60);
46: }
47: else {
48: iVar4 = *(int *)(param_2 + 0x48) + -1;
49: pcVar10 = param_1[1];
50: *(int *)(param_2 + 0x48) = iVar4;
51: ppbVar13 = (byte **)(**(code **)(pcVar10 + 0x38))
52: (param_1,*(undefined8 *)(param_2 + 0x40),iVar4,1,0);
53: pbVar21 = *ppbVar13;
54: }
55: puVar24 = (undefined *)**(undefined8 **)(param_2 + 0x20);
56: uVar3 = *(uint *)((long)param_1 + 0x3c);
57: uVar14 = (ulong)uVar3;
58: if (uVar3 == 1) {
59: iVar4 = *(int *)(param_1 + 6);
60: puVar15 = puVar24;
61: if (iVar4 != 0) {
62: do {
63: bVar1 = *pbVar21;
64: if (iVar2 <= (int)(uint)bVar1) {
65: ppcVar11 = (code **)*param_1;
66: *(undefined4 *)(ppcVar11 + 5) = 0x3f1;
67: (**ppcVar11)(param_1);
68: }
69: puVar23 = puVar15 + 1;
70: *puVar15 = *(undefined *)(*plVar9 + (ulong)bVar1);
71: pbVar21 = pbVar21 + 1;
72: puVar15 = puVar23;
73: } while (puVar23 != puVar24 + (ulong)(iVar4 - 1) + 1);
74: }
75: }
76: else {
77: if (uVar3 == 4) {
78: iVar4 = *(int *)(param_1 + 6);
79: if (iVar4 != 0) {
80: pbVar22 = pbVar21;
81: do {
82: pbVar20 = pbVar22 + 1;
83: bVar1 = *pbVar22;
84: if (iVar2 <= (int)(uint)bVar1) {
85: ppcVar11 = (code **)*param_1;
86: *(undefined4 *)(ppcVar11 + 5) = 0x3f1;
87: (**ppcVar11)(param_1);
88: }
89: uVar14 = (ulong)bVar1;
90: dVar27 = 1.0 - (double)(uint)*(byte *)(*plVar9 + uVar14) / 255.0;
91: dVar26 = 1.0 - (double)(uint)*(byte *)(plVar9[1] + uVar14) / 255.0;
92: dVar28 = 1.0 - (double)(uint)*(byte *)(plVar9[2] + uVar14) / 255.0;
93: dVar29 = dVar28;
94: if (((dVar27 < dVar26) || (dVar25 = dVar28, dVar29 = dVar26, dVar26 < dVar28)) &&
95: (dVar25 = dVar29, dVar27 < dVar29)) {
96: dVar25 = dVar27;
97: }
98: if (dVar25 == 1.0) {
99: uVar12 = 0xff;
100: uVar19 = 0xff;
101: uVar17 = uVar12;
102: }
103: else {
104: dVar29 = 1.0 - dVar25;
105: uVar19 = (undefined)(int)((255.0 - ((dVar26 - dVar25) / dVar29) * 255.0) + 0.5);
106: uVar12 = (undefined)(int)((255.0 - ((dVar28 - dVar25) / dVar29) * 255.0) + 0.5);
107: uVar17 = (char)(int)((255.0 - ((dVar27 - dVar25) / dVar29) * 255.0) + 0.5);
108: }
109: puVar24[2] = uVar12;
110: *puVar24 = uVar17;
111: puVar24[1] = uVar19;
112: puVar24[3] = (char)(int)((255.0 - dVar25 * 255.0) + 0.5);
113: pbVar22 = pbVar20;
114: puVar24 = puVar24 + 4;
115: } while (pbVar20 != pbVar21 + (ulong)(iVar4 - 1) + 1);
116: }
117: }
118: else {
119: lVar18 = (long)*(int *)(&DAT_0018c2c0 + uVar14 * 4);
120: iVar4 = *(int *)(&DAT_0018c260 + uVar14 * 4);
121: iVar5 = *(int *)(&DAT_0018c200 + uVar14 * 4);
122: iVar6 = *(int *)(&DAT_0018c140 + uVar14 * 4);
123: iVar7 = *(int *)(&DAT_0018c1a0 + uVar14 * 4);
124: iVar8 = *(int *)(param_1 + 6);
125: if (iVar6 < 0) {
126: if (iVar8 != 0) {
127: pbVar22 = pbVar21;
128: puVar24 = puVar24 + lVar18;
129: do {
130: pbVar20 = pbVar22 + 1;
131: uVar14 = (ulong)*pbVar22;
132: if (iVar2 <= (int)(uint)*pbVar22) {
133: ppcVar11 = (code **)*param_1;
134: *(undefined4 *)(ppcVar11 + 5) = 0x3f1;
135: (**ppcVar11)();
136: }
137: *puVar24 = *(undefined *)(*plVar9 + uVar14);
138: (puVar24 + -lVar18)[iVar4] = *(undefined *)(plVar9[1] + uVar14);
139: (puVar24 + -lVar18)[iVar5] = *(undefined *)(plVar9[2] + uVar14);
140: pbVar22 = pbVar20;
141: puVar24 = puVar24 + iVar7;
142: } while (pbVar20 != pbVar21 + (ulong)(iVar8 - 1) + 1);
143: }
144: }
145: else {
146: if (iVar8 != 0) {
147: pbVar22 = pbVar21;
148: puVar24 = puVar24 + lVar18;
149: do {
150: pbVar20 = pbVar22 + 1;
151: uVar14 = (ulong)*pbVar22;
152: if (iVar2 <= (int)(uint)*pbVar22) {
153: ppcVar11 = (code **)*param_1;
154: *(undefined4 *)(ppcVar11 + 5) = 0x3f1;
155: (**ppcVar11)();
156: }
157: *puVar24 = *(undefined *)(*plVar9 + uVar14);
158: puVar15 = puVar24 + -lVar18;
159: puVar15[iVar4] = *(undefined *)(plVar9[1] + uVar14);
160: puVar15[iVar5] = *(undefined *)(plVar9[2] + uVar14);
161: puVar15[iVar6] = 0xff;
162: pbVar22 = pbVar20;
163: puVar24 = puVar24 + iVar7;
164: } while (pbVar20 != pbVar21 + (ulong)(iVar8 - 1) + 1);
165: }
166: }
167: }
168: }
169: return 1;
170: }
171: 
