1: 
2: undefined8 FUN_00167a80(code **param_1,long param_2)
3: 
4: {
5: uint uVar1;
6: int iVar2;
7: int iVar3;
8: int iVar4;
9: int iVar5;
10: int iVar6;
11: code *pcVar7;
12: undefined *__dest;
13: code **ppcVar8;
14: byte **ppbVar9;
15: ulong uVar10;
16: byte *pbVar11;
17: size_t sVar12;
18: long lVar13;
19: byte *pbVar14;
20: byte *__src;
21: byte *pbVar15;
22: byte *pbVar16;
23: undefined *puVar17;
24: undefined *puVar18;
25: double dVar19;
26: double dVar20;
27: double dVar21;
28: double dVar22;
29: double dVar23;
30: 
31: if (*(int *)(param_2 + 0x58) == 0) {
32: sVar12 = fread(*(void **)(param_2 + 0x60),1,(ulong)*(uint *)(param_2 + 0x4c),
33: *(FILE **)(param_2 + 0x18));
34: if (*(uint *)(param_2 + 0x4c) != sVar12) {
35: ppcVar8 = (code **)*param_1;
36: *(undefined4 *)(ppcVar8 + 5) = 0x2b;
37: (**ppcVar8)(param_1);
38: }
39: __src = *(byte **)(param_2 + 0x60);
40: }
41: else {
42: iVar2 = *(int *)(param_2 + 0x48) + -1;
43: pcVar7 = param_1[1];
44: *(int *)(param_2 + 0x48) = iVar2;
45: ppbVar9 = (byte **)(**(code **)(pcVar7 + 0x38))(param_1,*(undefined8 *)(param_2 + 0x40),iVar2,1)
46: ;
47: __src = *ppbVar9;
48: }
49: __dest = (undefined *)**(undefined8 **)(param_2 + 0x20);
50: uVar1 = *(uint *)((long)param_1 + 0x3c);
51: uVar10 = (ulong)uVar1;
52: if ((uVar1 & 0xfffffffb) == 9) {
53: memcpy(__dest,__src,(ulong)*(uint *)(param_2 + 0x4c));
54: return 1;
55: }
56: iVar2 = *(int *)(param_1 + 6);
57: if (uVar1 == 4) {
58: if (iVar2 != 0) {
59: puVar17 = __dest;
60: do {
61: while( true ) {
62: dVar22 = 1.0 - (double)(uint)__src[2] / 255.0;
63: dVar21 = 1.0 - (double)(uint)__src[1] / 255.0;
64: dVar20 = 1.0 - (double)(uint)*__src / 255.0;
65: dVar19 = dVar22;
66: if (dVar21 <= dVar22) {
67: dVar19 = dVar21;
68: }
69: if (dVar20 <= dVar19) {
70: dVar19 = dVar20;
71: }
72: if (dVar19 == 1.0) break;
73: puVar18 = puVar17 + 4;
74: __src = __src + 4;
75: dVar23 = 1.0 - dVar19;
76: *puVar17 = (char)(int)((255.0 - ((dVar22 - dVar19) / dVar23) * 255.0) + 0.5);
77: puVar17[1] = (char)(int)((255.0 - ((dVar21 - dVar19) / dVar23) * 255.0) + 0.5);
78: puVar17[2] = (char)(int)((255.0 - ((dVar20 - dVar19) / dVar23) * 255.0) + 0.5);
79: puVar17[3] = (char)(int)((255.0 - dVar19 * 255.0) + 0.5);
80: puVar17 = puVar18;
81: if (puVar18 == __dest + (ulong)(iVar2 - 1) * 4 + 4) {
82: return 1;
83: }
84: }
85: *puVar17 = 0xff;
86: puVar17[1] = 0xff;
87: puVar18 = puVar17 + 4;
88: puVar17[2] = 0xff;
89: puVar17[3] = 0;
90: __src = __src + 4;
91: puVar17 = puVar18;
92: } while (puVar18 != __dest + (ulong)(iVar2 - 1) * 4 + 4);
93: return 1;
94: }
95: }
96: else {
97: iVar3 = *(int *)(&DAT_00190500 + uVar10 * 4);
98: iVar4 = *(int *)(&DAT_00190680 + uVar10 * 4);
99: iVar5 = *(int *)(&DAT_00190620 + uVar10 * 4);
100: iVar6 = *(int *)(&DAT_00190560 + uVar10 * 4);
101: lVar13 = (long)*(int *)(&DAT_001905c0 + uVar10 * 4);
102: if (iVar3 < 0) {
103: if (iVar2 != 0) {
104: pbVar16 = __dest + lVar13;
105: pbVar15 = __src;
106: do {
107: pbVar11 = pbVar15 + 4;
108: *pbVar16 = *pbVar15;
109: pbVar14 = pbVar16 + -lVar13;
110: pbVar16 = pbVar16 + iVar6;
111: pbVar14[iVar5] = pbVar15[1];
112: pbVar14[iVar4] = pbVar15[2];
113: pbVar15 = pbVar11;
114: } while (pbVar11 != __src + (ulong)(iVar2 - 1) * 4 + 4);
115: return 1;
116: }
117: }
118: else {
119: if (iVar2 != 0) {
120: pbVar16 = __dest + lVar13;
121: pbVar15 = __src;
122: do {
123: pbVar14 = pbVar15 + 4;
124: pbVar11 = pbVar16 + -lVar13;
125: *pbVar16 = *pbVar15;
126: pbVar16 = pbVar16 + iVar6;
127: pbVar11[iVar5] = pbVar15[1];
128: pbVar11[iVar4] = pbVar15[2];
129: pbVar11[iVar3] = pbVar15[3];
130: pbVar15 = pbVar14;
131: } while (pbVar14 != __src + (ulong)(iVar2 - 1) * 4 + 4);
132: }
133: }
134: }
135: return 1;
136: }
137: 
