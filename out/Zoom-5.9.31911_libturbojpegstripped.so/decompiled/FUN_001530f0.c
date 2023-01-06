1: 
2: undefined8 FUN_001530f0(long param_1,long param_2)
3: 
4: {
5: byte bVar1;
6: int iVar2;
7: int iVar3;
8: undefined8 uVar4;
9: long lVar5;
10: undefined *puVar6;
11: undefined uVar7;
12: byte bVar8;
13: uint uVar9;
14: uint uVar10;
15: undefined *puVar11;
16: undefined *puVar12;
17: undefined uVar13;
18: undefined uVar14;
19: double dVar15;
20: double dVar16;
21: double dVar17;
22: double dVar18;
23: double dVar19;
24: 
25: iVar2 = *(int *)(param_2 + 0x50);
26: uVar4 = *(undefined8 *)(param_2 + 0x18);
27: lVar5 = *(long *)(param_2 + 0x48);
28: puVar6 = (undefined *)**(long **)(param_2 + 0x20);
29: iVar3 = *(int *)(param_1 + 0x30);
30: if (iVar2 == 0xff) {
31: if (iVar3 != 0) {
32: puVar12 = puVar6;
33: do {
34: uVar9 = FUN_00152a10(param_1,uVar4,0xff);
35: uVar10 = FUN_00152a10(param_1,uVar4,0xff);
36: bVar8 = FUN_00152a10(param_1,uVar4,0xff);
37: dVar17 = 1.0 - (double)(uVar9 & 0xff) / 255.0;
38: dVar16 = 1.0 - (double)(uVar10 & 0xff) / 255.0;
39: dVar18 = 1.0 - (double)(uint)bVar8 / 255.0;
40: dVar19 = dVar18;
41: if (((dVar17 < dVar16) || (dVar15 = dVar18, dVar19 = dVar16, dVar16 < dVar18)) &&
42: (dVar15 = dVar19, dVar17 < dVar19)) {
43: dVar15 = dVar17;
44: }
45: if (dVar15 == 1.0) {
46: uVar7 = 0xff;
47: uVar14 = uVar7;
48: uVar13 = uVar7;
49: }
50: else {
51: dVar19 = 1.0 - dVar15;
52: uVar7 = (undefined)(int)((255.0 - ((dVar18 - dVar15) / dVar19) * 255.0) + 0.5);
53: uVar14 = (char)(int)((255.0 - ((dVar17 - dVar15) / dVar19) * 255.0) + 0.5);
54: uVar13 = (char)(int)((255.0 - ((dVar16 - dVar15) / dVar19) * 255.0) + 0.5);
55: }
56: puVar12[2] = uVar7;
57: *puVar12 = uVar14;
58: puVar11 = puVar12 + 4;
59: puVar12[1] = uVar13;
60: puVar12[3] = (char)(int)((255.0 - dVar15 * 255.0) + 0.5);
61: puVar12 = puVar11;
62: } while (puVar11 != puVar6 + (ulong)(iVar3 - 1) * 4 + 4);
63: }
64: }
65: else {
66: if (iVar3 != 0) {
67: puVar12 = puVar6;
68: do {
69: uVar9 = FUN_00152a10(param_1,uVar4,iVar2);
70: bVar8 = *(byte *)(lVar5 + (ulong)uVar9);
71: uVar9 = FUN_00152a10(param_1,uVar4,iVar2);
72: bVar1 = *(byte *)(lVar5 + (ulong)uVar9);
73: uVar9 = FUN_00152a10(param_1,uVar4,iVar2);
74: dVar17 = 1.0 - (double)(uint)bVar8 / 255.0;
75: dVar16 = 1.0 - (double)(uint)bVar1 / 255.0;
76: dVar18 = 1.0 - (double)(uint)*(byte *)(lVar5 + (ulong)uVar9) / 255.0;
77: dVar19 = dVar18;
78: if (((dVar17 < dVar16) || (dVar15 = dVar18, dVar19 = dVar16, dVar16 < dVar18)) &&
79: (dVar15 = dVar19, dVar17 < dVar19)) {
80: dVar15 = dVar17;
81: }
82: if (dVar15 == 1.0) {
83: uVar7 = 0xff;
84: uVar14 = uVar7;
85: uVar13 = uVar7;
86: }
87: else {
88: dVar19 = 1.0 - dVar15;
89: uVar7 = (undefined)(int)((255.0 - ((dVar18 - dVar15) / dVar19) * 255.0) + 0.5);
90: uVar14 = (char)(int)((255.0 - ((dVar17 - dVar15) / dVar19) * 255.0) + 0.5);
91: uVar13 = (char)(int)((255.0 - ((dVar16 - dVar15) / dVar19) * 255.0) + 0.5);
92: }
93: puVar12[2] = uVar7;
94: *puVar12 = uVar14;
95: puVar11 = puVar12 + 4;
96: puVar12[1] = uVar13;
97: puVar12[3] = (char)(int)((255.0 - dVar15 * 255.0) + 0.5);
98: puVar12 = puVar11;
99: } while (puVar11 != puVar6 + (ulong)(iVar3 - 1) * 4 + 4);
100: }
101: }
102: return 1;
103: }
104: 
