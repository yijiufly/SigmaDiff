1: 
2: undefined8 FUN_00150c00(code **param_1,long param_2)
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
14: byte *__src;
15: byte *pbVar10;
16: size_t sVar11;
17: byte *pbVar12;
18: undefined *__dest;
19: byte *pbVar13;
20: ulong uVar14;
21: byte *pbVar15;
22: undefined uVar16;
23: undefined uVar17;
24: long lVar18;
25: undefined uVar19;
26: double dVar20;
27: double dVar21;
28: double dVar22;
29: double dVar23;
30: double dVar24;
31: 
32: if (*(int *)(param_2 + 0x58) == 0) {
33: sVar11 = fread(*(void **)(param_2 + 0x60),1,(ulong)*(uint *)(param_2 + 0x4c),
34: *(FILE **)(param_2 + 0x18));
35: if (sVar11 != *(uint *)(param_2 + 0x4c)) {
36: ppcVar8 = (code **)*param_1;
37: *(undefined4 *)(ppcVar8 + 5) = 0x2b;
38: (**ppcVar8)();
39: }
40: __src = *(byte **)(param_2 + 0x60);
41: }
42: else {
43: pcVar7 = param_1[1];
44: *(int *)(param_2 + 0x48) = *(int *)(param_2 + 0x48) + -1;
45: ppbVar9 = (byte **)(**(code **)(pcVar7 + 0x38))();
46: __src = *ppbVar9;
47: }
48: __dest = (undefined *)**(void ***)(param_2 + 0x20);
49: uVar1 = *(uint *)((long)param_1 + 0x3c);
50: uVar14 = (ulong)uVar1;
51: if (uVar1 == 8) {
52: memcpy(__dest,__src,(ulong)*(uint *)(param_2 + 0x4c));
53: }
54: else {
55: if (uVar1 == 4) {
56: iVar2 = *(int *)(param_1 + 6);
57: if (iVar2 != 0) {
58: pbVar15 = __src;
59: do {
60: pbVar13 = pbVar15 + 3;
61: dVar22 = 1.0 - (double)(uint)pbVar15[2] / 255.0;
62: dVar21 = 1.0 - (double)(uint)pbVar15[1] / 255.0;
63: dVar23 = 1.0 - (double)(uint)*pbVar15 / 255.0;
64: dVar24 = dVar23;
65: if (((dVar22 < dVar21) || (dVar20 = dVar23, dVar24 = dVar21, dVar21 < dVar23)) &&
66: (dVar20 = dVar24, dVar22 < dVar24)) {
67: dVar20 = dVar22;
68: }
69: if (dVar20 == 1.0) {
70: uVar16 = 0xff;
71: uVar19 = uVar16;
72: uVar17 = uVar16;
73: }
74: else {
75: dVar24 = 1.0 - dVar20;
76: uVar16 = (undefined)(int)((255.0 - ((dVar23 - dVar20) / dVar24) * 255.0) + 0.5);
77: uVar19 = (char)(int)((255.0 - ((dVar22 - dVar20) / dVar24) * 255.0) + 0.5);
78: uVar17 = (char)(int)((255.0 - ((dVar21 - dVar20) / dVar24) * 255.0) + 0.5);
79: }
80: __dest[2] = uVar16;
81: *__dest = uVar19;
82: __dest[1] = uVar17;
83: __dest[3] = (char)(int)((255.0 - dVar20 * 255.0) + 0.5);
84: pbVar15 = pbVar13;
85: __dest = __dest + 4;
86: } while (pbVar13 != __src + (ulong)(iVar2 - 1) * 3 + 3);
87: return 1;
88: }
89: }
90: else {
91: iVar2 = *(int *)(&DAT_0018c2c0 + uVar14 * 4);
92: iVar3 = *(int *)(&DAT_0018c260 + uVar14 * 4);
93: lVar18 = (long)*(int *)(&DAT_0018c200 + uVar14 * 4);
94: iVar4 = *(int *)(&DAT_0018c140 + uVar14 * 4);
95: iVar5 = *(int *)(&DAT_0018c1a0 + uVar14 * 4);
96: if (iVar4 < 0) {
97: iVar4 = *(int *)(param_1 + 6);
98: if (iVar4 != 0) {
99: pbVar13 = __dest + lVar18;
100: pbVar15 = __src;
101: do {
102: pbVar10 = pbVar15 + 3;
103: *pbVar13 = *pbVar15;
104: pbVar12 = pbVar13 + -lVar18;
105: pbVar13 = pbVar13 + iVar5;
106: pbVar12[iVar3] = pbVar15[1];
107: pbVar12[iVar2] = pbVar15[2];
108: pbVar15 = pbVar10;
109: } while (pbVar10 != __src + (ulong)(iVar4 - 1) * 3 + 3);
110: return 1;
111: }
112: }
113: else {
114: iVar6 = *(int *)(param_1 + 6);
115: if (iVar6 != 0) {
116: pbVar15 = __dest + lVar18;
117: pbVar13 = __src;
118: do {
119: pbVar10 = pbVar13 + 3;
120: *pbVar15 = *pbVar13;
121: pbVar12 = pbVar15 + -lVar18;
122: pbVar15 = pbVar15 + iVar5;
123: pbVar12[iVar3] = pbVar13[1];
124: pbVar12[iVar2] = pbVar13[2];
125: pbVar12[iVar4] = 0xff;
126: pbVar13 = pbVar10;
127: } while (__src + (ulong)(iVar6 - 1) * 3 + 3 != pbVar10);
128: }
129: }
130: }
131: }
132: return 1;
133: }
134: 
