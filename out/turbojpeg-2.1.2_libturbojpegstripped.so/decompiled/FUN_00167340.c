1: 
2: undefined8 FUN_00167340(code **param_1,long param_2)
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
13: int iVar9;
14: long *plVar10;
15: code *pcVar11;
16: code **ppcVar12;
17: byte **ppbVar13;
18: size_t sVar14;
19: ulong uVar15;
20: undefined *puVar16;
21: byte *pbVar17;
22: byte *pbVar18;
23: byte *pbVar19;
24: undefined *puVar20;
25: double dVar21;
26: double dVar22;
27: double dVar23;
28: double dVar24;
29: double dVar25;
30: 
31: iVar2 = *(int *)(param_2 + 0x54);
32: plVar10 = *(long **)(param_2 + 0x38);
33: if (*(int *)(param_2 + 0x58) == 0) {
34: sVar14 = fread(*(void **)(param_2 + 0x60),1,(ulong)*(uint *)(param_2 + 0x4c),
35: *(FILE **)(param_2 + 0x18));
36: if (*(uint *)(param_2 + 0x4c) != sVar14) {
37: ppcVar12 = (code **)*param_1;
38: *(undefined4 *)(ppcVar12 + 5) = 0x2b;
39: (**ppcVar12)(param_1);
40: }
41: pbVar17 = *(byte **)(param_2 + 0x60);
42: }
43: else {
44: pcVar11 = param_1[1];
45: *(int *)(param_2 + 0x48) = *(int *)(param_2 + 0x48) + -1;
46: ppbVar13 = (byte **)(**(code **)(pcVar11 + 0x38))();
47: pbVar17 = *ppbVar13;
48: }
49: uVar3 = *(uint *)((long)param_1 + 0x3c);
50: uVar15 = (ulong)uVar3;
51: iVar4 = *(int *)(param_1 + 6);
52: puVar20 = (undefined *)**(undefined8 **)(param_2 + 0x20);
53: if (uVar3 == 1) {
54: if (iVar4 != 0) {
55: pbVar19 = pbVar17;
56: do {
57: pbVar18 = pbVar19 + 1;
58: bVar1 = *pbVar19;
59: if (iVar2 <= (int)(uint)bVar1) {
60: ppcVar12 = (code **)*param_1;
61: *(undefined4 *)(ppcVar12 + 5) = 0x3f1;
62: (**ppcVar12)(param_1);
63: }
64: *puVar20 = *(undefined *)(*plVar10 + (ulong)bVar1);
65: pbVar19 = pbVar18;
66: puVar20 = puVar20 + 1;
67: } while (pbVar18 != pbVar17 + (ulong)(iVar4 - 1) + 1);
68: }
69: }
70: else {
71: if (uVar3 == 4) {
72: if (iVar4 != 0) {
73: pbVar19 = pbVar17;
74: do {
75: while( true ) {
76: pbVar18 = pbVar19 + 1;
77: bVar1 = *pbVar19;
78: if (iVar2 <= (int)(uint)bVar1) {
79: ppcVar12 = (code **)*param_1;
80: *(undefined4 *)(ppcVar12 + 5) = 0x3f1;
81: (**ppcVar12)(param_1);
82: }
83: uVar15 = (ulong)bVar1;
84: dVar24 = 1.0 - (double)(uint)*(byte *)(*plVar10 + uVar15) / 255.0;
85: dVar23 = 1.0 - (double)(uint)*(byte *)(plVar10[1] + uVar15) / 255.0;
86: dVar22 = 1.0 - (double)(uint)*(byte *)(plVar10[2] + uVar15) / 255.0;
87: dVar21 = dVar24;
88: if (dVar23 <= dVar24) {
89: dVar21 = dVar23;
90: }
91: if (dVar22 <= dVar21) {
92: dVar21 = dVar22;
93: }
94: pbVar19 = pbVar18;
95: if (dVar21 == 1.0) break;
96: dVar25 = 1.0 - dVar21;
97: *puVar20 = (char)(int)((255.0 - ((dVar24 - dVar21) / dVar25) * 255.0) + 0.5);
98: puVar20[1] = (char)(int)((255.0 - ((dVar23 - dVar21) / dVar25) * 255.0) + 0.5);
99: puVar20[2] = (char)(int)((255.0 - ((dVar22 - dVar21) / dVar25) * 255.0) + 0.5);
100: puVar20[3] = (char)(int)((255.0 - dVar21 * 255.0) + 0.5);
101: puVar20 = puVar20 + 4;
102: if (pbVar18 == pbVar17 + (ulong)(iVar4 - 1) + 1) {
103: return 1;
104: }
105: }
106: *puVar20 = 0xff;
107: puVar20[1] = 0xff;
108: puVar20[2] = 0xff;
109: puVar20[3] = 0;
110: puVar20 = puVar20 + 4;
111: } while (pbVar18 != pbVar17 + (ulong)(iVar4 - 1) + 1);
112: }
113: }
114: else {
115: iVar5 = *(int *)(&DAT_00190680 + uVar15 * 4);
116: iVar6 = *(int *)(&DAT_00190620 + uVar15 * 4);
117: iVar7 = *(int *)(&DAT_001905c0 + uVar15 * 4);
118: iVar8 = *(int *)(&DAT_00190500 + uVar15 * 4);
119: iVar9 = *(int *)(&DAT_00190560 + uVar15 * 4);
120: if (iVar8 < 0) {
121: if (iVar4 != 0) {
122: puVar20 = puVar20 + iVar5;
123: pbVar19 = pbVar17;
124: do {
125: pbVar18 = pbVar19 + 1;
126: bVar1 = *pbVar19;
127: if (iVar2 <= (int)(uint)bVar1) {
128: ppcVar12 = (code **)*param_1;
129: *(undefined4 *)(ppcVar12 + 5) = 0x3f1;
130: (**ppcVar12)();
131: }
132: uVar15 = (ulong)bVar1;
133: *puVar20 = *(undefined *)(*plVar10 + uVar15);
134: puVar16 = puVar20 + -(long)iVar5;
135: puVar20 = puVar20 + iVar9;
136: puVar16[iVar6] = *(undefined *)(plVar10[1] + uVar15);
137: puVar16[iVar7] = *(undefined *)(plVar10[2] + uVar15);
138: pbVar19 = pbVar18;
139: } while (pbVar18 != pbVar17 + (ulong)(iVar4 - 1) + 1);
140: }
141: }
142: else {
143: if (iVar4 != 0) {
144: puVar20 = puVar20 + iVar5;
145: pbVar19 = pbVar17;
146: do {
147: pbVar18 = pbVar19 + 1;
148: bVar1 = *pbVar19;
149: if (iVar2 <= (int)(uint)bVar1) {
150: ppcVar12 = (code **)*param_1;
151: *(undefined4 *)(ppcVar12 + 5) = 0x3f1;
152: (**ppcVar12)();
153: }
154: uVar15 = (ulong)bVar1;
155: *puVar20 = *(undefined *)(*plVar10 + uVar15);
156: puVar16 = puVar20 + -(long)iVar5;
157: puVar20 = puVar20 + iVar9;
158: puVar16[iVar6] = *(undefined *)(plVar10[1] + uVar15);
159: puVar16[iVar7] = *(undefined *)(plVar10[2] + uVar15);
160: puVar16[iVar8] = 0xff;
161: pbVar19 = pbVar18;
162: } while (pbVar18 != pbVar17 + (ulong)(iVar4 - 1) + 1);
163: }
164: }
165: }
166: }
167: return 1;
168: }
169: 
