1: 
2: void FUN_00144f70(long param_1)
3: 
4: {
5: undefined8 *puVar1;
6: long lVar2;
7: int iVar3;
8: long lVar4;
9: ulong uVar5;
10: undefined *puVar6;
11: undefined *puVar7;
12: int iVar8;
13: int iVar9;
14: long lVar10;
15: undefined8 uVar11;
16: ulong uVar12;
17: undefined *puVar13;
18: int iVar14;
19: undefined *puVar15;
20: long lVar16;
21: bool bVar17;
22: 
23: bVar17 = *(int *)(param_1 + 0x70) == 1;
24: lVar2 = *(long *)(param_1 + 0x270);
25: uVar11 = 0x100;
26: if (bVar17) {
27: uVar11 = 0x2fe;
28: }
29: iVar8 = 0;
30: if (bVar17) {
31: iVar8 = 0x1fe;
32: }
33: *(uint *)(lVar2 + 0x38) = (uint)bVar17;
34: lVar4 = (**(code **)(*(long *)(param_1 + 8) + 0x10))(param_1,1,uVar11);
35: iVar3 = *(int *)(param_1 + 0x90);
36: *(long *)(lVar2 + 0x30) = lVar4;
37: if (iVar3 < 1) {
38: return;
39: }
40: iVar3 = *(int *)(lVar2 + 0x28);
41: lVar16 = 0;
42: do {
43: iVar9 = *(int *)(lVar2 + 0x3c + lVar16 * 4);
44: iVar3 = iVar3 / iVar9;
45: puVar1 = (undefined8 *)(lVar4 + lVar16 * 8);
46: puVar15 = (undefined *)*puVar1;
47: if (iVar8 != 0) {
48: puVar15 = puVar15 + 0xff;
49: *puVar1 = puVar15;
50: }
51: iVar9 = iVar9 + -1;
52: lVar4 = 0;
53: iVar14 = 0;
54: uVar12 = ((long)iVar9 + 0xff) / (long)(iVar9 * 2) & 0xffffffff;
55: do {
56: if ((int)uVar12 < (int)lVar4) {
57: iVar14 = iVar14 + 1;
58: lVar10 = ((long)(iVar14 * 2) + 1) * 0xff + (long)iVar9;
59: while( true ) {
60: uVar5 = lVar10 / (long)(iVar9 * 2);
61: uVar12 = uVar5 & 0xffffffff;
62: if ((int)lVar4 <= (int)uVar5) break;
63: iVar14 = iVar14 + 1;
64: lVar10 = lVar10 + 0x1fe;
65: }
66: }
67: puVar15[lVar4] = (char)iVar3 * (char)iVar14;
68: lVar4 = lVar4 + 1;
69: } while (lVar4 != 0x100);
70: if (iVar8 == 0) {
71: iVar9 = (int)lVar16 + 1;
72: if (*(int *)(param_1 + 0x90) == iVar9 || *(int *)(param_1 + 0x90) < iVar9) {
73: return;
74: }
75: }
76: else {
77: puVar6 = puVar15 + -1;
78: puVar13 = puVar15 + 0x100;
79: do {
80: puVar7 = puVar6 + -1;
81: *puVar6 = *puVar15;
82: *puVar13 = puVar15[0xff];
83: puVar6 = puVar7;
84: puVar13 = puVar13 + 1;
85: } while (puVar15 + -0x100 != puVar7);
86: iVar9 = (int)lVar16 + 1;
87: if (*(int *)(param_1 + 0x90) == iVar9 || *(int *)(param_1 + 0x90) < iVar9) {
88: return;
89: }
90: }
91: lVar16 = lVar16 + 1;
92: lVar4 = *(long *)(lVar2 + 0x30);
93: } while( true );
94: }
95: 
