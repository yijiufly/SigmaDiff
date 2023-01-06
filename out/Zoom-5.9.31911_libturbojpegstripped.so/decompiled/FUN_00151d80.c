1: 
2: undefined8 FUN_00151d80(code **param_1,long param_2)
3: 
4: {
5: byte *pbVar1;
6: int iVar2;
7: int iVar3;
8: long lVar4;
9: code **ppcVar5;
10: byte *pbVar6;
11: size_t sVar7;
12: undefined *puVar8;
13: byte *pbVar9;
14: undefined uVar10;
15: undefined uVar11;
16: undefined uVar12;
17: double dVar13;
18: double dVar14;
19: double dVar15;
20: double dVar16;
21: double dVar17;
22: 
23: lVar4 = *(long *)(param_2 + 0x48);
24: iVar2 = *(int *)(param_2 + 0x50);
25: sVar7 = fread(*(void **)(param_2 + 0x30),1,*(size_t *)(param_2 + 0x40),*(FILE **)(param_2 + 0x18))
26: ;
27: if (sVar7 != *(size_t *)(param_2 + 0x40)) {
28: ppcVar5 = (code **)*param_1;
29: *(undefined4 *)(ppcVar5 + 5) = 0x2b;
30: (**ppcVar5)();
31: }
32: pbVar6 = *(byte **)(param_2 + 0x30);
33: iVar3 = *(int *)(param_1 + 6);
34: if (iVar2 == 0xff) {
35: if (iVar3 != 0) {
36: puVar8 = (undefined *)**(long **)(param_2 + 0x20);
37: pbVar9 = pbVar6;
38: do {
39: pbVar1 = pbVar9 + 3;
40: dVar15 = 1.0 - (double)(uint)*pbVar9 / 255.0;
41: dVar14 = 1.0 - (double)(uint)pbVar9[1] / 255.0;
42: dVar16 = 1.0 - (double)(uint)pbVar9[2] / 255.0;
43: dVar17 = dVar16;
44: if (((dVar15 < dVar14) || (dVar13 = dVar16, dVar17 = dVar14, dVar14 < dVar16)) &&
45: (dVar13 = dVar17, dVar15 < dVar17)) {
46: dVar13 = dVar15;
47: }
48: if (dVar13 == 1.0) {
49: uVar10 = 0xff;
50: uVar12 = uVar10;
51: uVar11 = uVar10;
52: }
53: else {
54: dVar17 = 1.0 - dVar13;
55: uVar10 = (undefined)(int)((255.0 - ((dVar16 - dVar13) / dVar17) * 255.0) + 0.5);
56: uVar12 = (char)(int)((255.0 - ((dVar15 - dVar13) / dVar17) * 255.0) + 0.5);
57: uVar11 = (char)(int)((255.0 - ((dVar14 - dVar13) / dVar17) * 255.0) + 0.5);
58: }
59: puVar8[2] = uVar10;
60: *puVar8 = uVar12;
61: puVar8[1] = uVar11;
62: puVar8[3] = (char)(int)((255.0 - dVar13 * 255.0) + 0.5);
63: puVar8 = puVar8 + 4;
64: pbVar9 = pbVar1;
65: } while (pbVar1 != pbVar6 + (ulong)(iVar3 - 1) * 3 + 3);
66: return 1;
67: }
68: }
69: else {
70: if (iVar3 != 0) {
71: puVar8 = (undefined *)**(long **)(param_2 + 0x20);
72: pbVar9 = pbVar6;
73: do {
74: pbVar1 = pbVar9 + 3;
75: dVar15 = 1.0 - (double)(uint)*(byte *)(lVar4 + (ulong)*pbVar9) / 255.0;
76: dVar14 = 1.0 - (double)(uint)*(byte *)(lVar4 + (ulong)pbVar9[1]) / 255.0;
77: dVar16 = 1.0 - (double)(uint)*(byte *)(lVar4 + (ulong)pbVar9[2]) / 255.0;
78: dVar17 = dVar16;
79: if (((dVar15 < dVar14) || (dVar13 = dVar16, dVar17 = dVar14, dVar14 < dVar16)) &&
80: (dVar13 = dVar17, dVar15 < dVar17)) {
81: dVar13 = dVar15;
82: }
83: if (dVar13 == 1.0) {
84: uVar10 = 0xff;
85: uVar12 = uVar10;
86: uVar11 = uVar10;
87: }
88: else {
89: dVar17 = 1.0 - dVar13;
90: uVar10 = (undefined)(int)((255.0 - ((dVar16 - dVar13) / dVar17) * 255.0) + 0.5);
91: uVar12 = (char)(int)((255.0 - ((dVar15 - dVar13) / dVar17) * 255.0) + 0.5);
92: uVar11 = (char)(int)((255.0 - ((dVar14 - dVar13) / dVar17) * 255.0) + 0.5);
93: }
94: puVar8[2] = uVar10;
95: *puVar8 = uVar12;
96: puVar8[1] = uVar11;
97: puVar8[3] = (char)(int)((255.0 - dVar13 * 255.0) + 0.5);
98: puVar8 = puVar8 + 4;
99: pbVar9 = pbVar1;
100: } while (pbVar6 + (ulong)(iVar3 - 1) * 3 + 3 != pbVar1);
101: }
102: }
103: return 1;
104: }
105: 
