1: 
2: undefined8 FUN_00167770(code **param_1,long param_2)
3: 
4: {
5: uint uVar1;
6: int iVar2;
7: int iVar3;
8: int iVar4;
9: int iVar5;
10: int iVar6;
11: code *pcVar7;
12: code **ppcVar8;
13: byte **ppbVar9;
14: ulong uVar10;
15: byte *pbVar11;
16: size_t sVar12;
17: long lVar13;
18: byte *__src;
19: byte *pbVar14;
20: byte *pbVar15;
21: byte *pbVar16;
22: undefined *__dest;
23: double dVar17;
24: double dVar18;
25: double dVar19;
26: double dVar20;
27: double dVar21;
28: 
29: if (*(int *)(param_2 + 0x58) == 0) {
30: sVar12 = fread(*(void **)(param_2 + 0x60),1,(ulong)*(uint *)(param_2 + 0x4c),
31: *(FILE **)(param_2 + 0x18));
32: if (*(uint *)(param_2 + 0x4c) != sVar12) {
33: ppcVar8 = (code **)*param_1;
34: *(undefined4 *)(ppcVar8 + 5) = 0x2b;
35: (**ppcVar8)(param_1);
36: }
37: __src = *(byte **)(param_2 + 0x60);
38: }
39: else {
40: pcVar7 = param_1[1];
41: *(int *)(param_2 + 0x48) = *(int *)(param_2 + 0x48) + -1;
42: ppbVar9 = (byte **)(**(code **)(pcVar7 + 0x38))(param_1,*(undefined8 *)(param_2 + 0x40));
43: __src = *ppbVar9;
44: }
45: __dest = (undefined *)**(undefined8 **)(param_2 + 0x20);
46: uVar1 = *(uint *)((long)param_1 + 0x3c);
47: uVar10 = (ulong)uVar1;
48: if (uVar1 == 8) {
49: memcpy(__dest,__src,(ulong)*(uint *)(param_2 + 0x4c));
50: return 1;
51: }
52: iVar2 = *(int *)(param_1 + 6);
53: if (uVar1 == 4) {
54: if (iVar2 != 0) {
55: pbVar15 = __src;
56: do {
57: while( true ) {
58: pbVar16 = pbVar15 + 3;
59: dVar20 = 1.0 - (double)(uint)pbVar15[2] / 255.0;
60: dVar19 = 1.0 - (double)(uint)pbVar15[1] / 255.0;
61: dVar18 = 1.0 - (double)(uint)*pbVar15 / 255.0;
62: dVar17 = dVar20;
63: if (dVar19 <= dVar20) {
64: dVar17 = dVar19;
65: }
66: if (dVar18 <= dVar17) {
67: dVar17 = dVar18;
68: }
69: pbVar15 = pbVar16;
70: if (dVar17 == 1.0) break;
71: dVar21 = 1.0 - dVar17;
72: *__dest = (char)(int)((255.0 - ((dVar20 - dVar17) / dVar21) * 255.0) + 0.5);
73: __dest[1] = (char)(int)((255.0 - ((dVar19 - dVar17) / dVar21) * 255.0) + 0.5);
74: __dest[2] = (char)(int)((255.0 - ((dVar18 - dVar17) / dVar21) * 255.0) + 0.5);
75: __dest[3] = (char)(int)((255.0 - dVar17 * 255.0) + 0.5);
76: __dest = __dest + 4;
77: if (pbVar16 == __src + (ulong)(iVar2 - 1) * 3 + 3) {
78: return 1;
79: }
80: }
81: *__dest = 0xff;
82: __dest[1] = 0xff;
83: __dest[2] = 0xff;
84: __dest[3] = 0;
85: __dest = __dest + 4;
86: } while (pbVar16 != __src + (ulong)(iVar2 - 1) * 3 + 3);
87: return 1;
88: }
89: }
90: else {
91: iVar3 = *(int *)(&DAT_00190500 + uVar10 * 4);
92: iVar4 = *(int *)(&DAT_00190680 + uVar10 * 4);
93: iVar5 = *(int *)(&DAT_00190620 + uVar10 * 4);
94: iVar6 = *(int *)(&DAT_00190560 + uVar10 * 4);
95: lVar13 = (long)*(int *)(&DAT_001905c0 + uVar10 * 4);
96: if (iVar3 < 0) {
97: if (iVar2 != 0) {
98: pbVar16 = __dest + lVar13;
99: pbVar15 = __src;
100: do {
101: pbVar11 = pbVar15 + 3;
102: *pbVar16 = *pbVar15;
103: pbVar14 = pbVar16 + -lVar13;
104: pbVar16 = pbVar16 + iVar6;
105: pbVar14[iVar5] = pbVar15[1];
106: pbVar14[iVar4] = pbVar15[2];
107: pbVar15 = pbVar11;
108: } while (pbVar11 != __src + (ulong)(iVar2 - 1) * 3 + 3);
109: return 1;
110: }
111: }
112: else {
113: if (iVar2 != 0) {
114: pbVar16 = __dest + lVar13;
115: pbVar15 = __src;
116: do {
117: pbVar14 = pbVar15 + 3;
118: pbVar11 = pbVar16 + -lVar13;
119: *pbVar16 = *pbVar15;
120: pbVar16 = pbVar16 + iVar6;
121: pbVar11[iVar5] = pbVar15[1];
122: pbVar11[iVar4] = pbVar15[2];
123: pbVar11[iVar3] = 0xff;
124: pbVar15 = pbVar14;
125: } while (pbVar14 != __src + (ulong)(iVar2 - 1) * 3 + 3);
126: }
127: }
128: }
129: return 1;
130: }
131: 
