1: 
2: undefined8 FUN_00150900(code **param_1,long param_2)
3: 
4: {
5: uint uVar1;
6: int iVar2;
7: int iVar3;
8: code *pcVar4;
9: code **ppcVar5;
10: byte **ppbVar6;
11: size_t sVar7;
12: byte *__src;
13: byte *pbVar8;
14: undefined *__dest;
15: int iVar9;
16: int iVar10;
17: ulong uVar11;
18: byte *pbVar12;
19: undefined uVar13;
20: int iVar14;
21: undefined uVar15;
22: undefined uVar16;
23: long lVar17;
24: double dVar18;
25: double dVar19;
26: double dVar20;
27: double dVar21;
28: double dVar22;
29: 
30: if (*(int *)(param_2 + 0x58) == 0) {
31: sVar7 = fread(*(void **)(param_2 + 0x60),1,(ulong)*(uint *)(param_2 + 0x4c),
32: *(FILE **)(param_2 + 0x18));
33: if (sVar7 != *(uint *)(param_2 + 0x4c)) {
34: ppcVar5 = (code **)*param_1;
35: *(undefined4 *)(ppcVar5 + 5) = 0x2b;
36: (**ppcVar5)();
37: }
38: __src = *(byte **)(param_2 + 0x60);
39: }
40: else {
41: pcVar4 = param_1[1];
42: *(int *)(param_2 + 0x48) = *(int *)(param_2 + 0x48) + -1;
43: ppbVar6 = (byte **)(**(code **)(pcVar4 + 0x38))();
44: __src = *ppbVar6;
45: }
46: __dest = (undefined *)**(void ***)(param_2 + 0x20);
47: uVar1 = *(uint *)((long)param_1 + 0x3c);
48: uVar11 = (ulong)uVar1;
49: if ((uVar1 & 0xfffffffb) != 9) {
50: if (uVar1 == 4) {
51: iVar9 = *(int *)(param_1 + 6);
52: if (iVar9 != 0) {
53: do {
54: dVar20 = 1.0 - (double)(uint)__src[2] / 255.0;
55: dVar19 = 1.0 - (double)(uint)__src[1] / 255.0;
56: dVar21 = 1.0 - (double)(uint)*__src / 255.0;
57: dVar22 = dVar21;
58: if (((dVar20 < dVar19) || (dVar18 = dVar21, dVar22 = dVar19, dVar19 < dVar21)) &&
59: (dVar18 = dVar22, dVar20 < dVar22)) {
60: dVar18 = dVar20;
61: }
62: if (dVar18 == 1.0) {
63: uVar13 = 0xff;
64: uVar16 = uVar13;
65: uVar15 = uVar13;
66: }
67: else {
68: dVar22 = 1.0 - dVar18;
69: uVar13 = (undefined)(int)((255.0 - ((dVar21 - dVar18) / dVar22) * 255.0) + 0.5);
70: uVar16 = (char)(int)((255.0 - ((dVar20 - dVar18) / dVar22) * 255.0) + 0.5);
71: uVar15 = (char)(int)((255.0 - ((dVar19 - dVar18) / dVar22) * 255.0) + 0.5);
72: }
73: __dest[2] = uVar13;
74: *__dest = uVar16;
75: __src = __src + 4;
76: __dest[1] = uVar15;
77: __dest[3] = (char)(int)((255.0 - dVar18 * 255.0) + 0.5);
78: iVar9 = iVar9 + -1;
79: __dest = __dest + 4;
80: } while (iVar9 != 0);
81: return 1;
82: }
83: }
84: else {
85: iVar9 = *(int *)(&DAT_0018c2c0 + uVar11 * 4);
86: iVar2 = *(int *)(&DAT_0018c260 + uVar11 * 4);
87: lVar17 = (long)*(int *)(&DAT_0018c200 + uVar11 * 4);
88: iVar10 = *(int *)(&DAT_0018c140 + uVar11 * 4);
89: iVar3 = *(int *)(&DAT_0018c1a0 + uVar11 * 4);
90: if (iVar10 < 0) {
91: iVar10 = *(int *)(param_1 + 6);
92: if (iVar10 != 0) {
93: pbVar12 = __dest + lVar17;
94: do {
95: *pbVar12 = *__src;
96: pbVar8 = pbVar12 + -lVar17;
97: pbVar12 = pbVar12 + iVar3;
98: pbVar8[iVar2] = __src[1];
99: iVar10 = iVar10 + -1;
100: pbVar8[iVar9] = __src[2];
101: __src = __src + 4;
102: } while (iVar10 != 0);
103: return 1;
104: }
105: }
106: else {
107: iVar14 = *(int *)(param_1 + 6);
108: if (iVar14 != 0) {
109: pbVar12 = __dest + lVar17;
110: do {
111: *pbVar12 = *__src;
112: pbVar8 = pbVar12 + -lVar17;
113: pbVar12 = pbVar12 + iVar3;
114: pbVar8[iVar2] = __src[1];
115: iVar14 = iVar14 + -1;
116: pbVar8[iVar9] = __src[2];
117: pbVar8[iVar10] = __src[3];
118: __src = __src + 4;
119: } while (iVar14 != 0);
120: }
121: }
122: }
123: return 1;
124: }
125: memcpy(__dest,__src,(ulong)*(uint *)(param_2 + 0x4c));
126: return 1;
127: }
128: 
