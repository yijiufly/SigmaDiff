1: 
2: void FUN_00139170(long param_1)
3: 
4: {
5: undefined4 uVar1;
6: long lVar2;
7: undefined *puVar3;
8: long lVar4;
9: ulong uVar5;
10: ulong uVar6;
11: undefined *puVar7;
12: undefined *puVar8;
13: int iVar9;
14: long lVar10;
15: undefined8 uVar11;
16: ulong uVar12;
17: undefined *puVar13;
18: int iVar14;
19: int iVar15;
20: long lVar16;
21: long lVar17;
22: bool bVar18;
23: int iStack64;
24: int iStack60;
25: 
26: bVar18 = *(int *)(param_1 + 0x70) == 1;
27: lVar2 = *(long *)(param_1 + 0x270);
28: uVar11 = 0x2fe;
29: if (!bVar18) {
30: uVar11 = 0x100;
31: }
32: iVar9 = 0x1fe;
33: if (!bVar18) {
34: iVar9 = 0;
35: }
36: uVar1 = *(undefined4 *)(param_1 + 0x90);
37: *(uint *)(lVar2 + 0x38) = (uint)bVar18;
38: lVar4 = (**(code **)(*(long *)(param_1 + 8) + 0x10))(param_1,1,uVar11,uVar1);
39: iVar14 = *(int *)(param_1 + 0x90);
40: iStack64 = *(int *)(lVar2 + 0x28);
41: *(long *)(lVar2 + 0x30) = lVar4;
42: if (0 < iVar14) {
43: lVar16 = 0;
44: iStack60 = 0;
45: lVar17 = lVar2;
46: while( true ) {
47: iVar14 = *(int *)(lVar17 + 0x3c);
48: uVar5 = (long)iStack64 / (long)iVar14 & 0xffffffff;
49: iStack64 = (int)uVar5;
50: if (iVar9 != 0) {
51: *(long *)(lVar4 + lVar16) = *(long *)(lVar4 + lVar16) + 0xff;
52: lVar4 = *(long *)(lVar2 + 0x30);
53: }
54: iVar14 = iVar14 + -1;
55: puVar3 = *(undefined **)(lVar4 + lVar16);
56: lVar4 = 0;
57: iVar15 = 0;
58: uVar12 = ((long)iVar14 + 0xff) / (long)(iVar14 * 2) & 0xffffffff;
59: do {
60: if ((int)uVar12 < (int)lVar4) {
61: lVar10 = (long)iVar14 + 0xff + ((long)iVar15 + 1) * 0x1fe;
62: do {
63: iVar15 = iVar15 + 1;
64: uVar6 = lVar10 / (long)(iVar14 * 2);
65: uVar12 = uVar6 & 0xffffffff;
66: lVar10 = lVar10 + 0x1fe;
67: } while ((int)uVar6 < (int)lVar4);
68: }
69: puVar3[lVar4] = (char)uVar5 * (char)iVar15;
70: lVar4 = lVar4 + 1;
71: } while (lVar4 != 0x100);
72: if (iVar9 != 0) {
73: puVar7 = puVar3 + -1;
74: puVar13 = puVar3 + 0x100;
75: do {
76: puVar8 = puVar7 + -1;
77: *puVar7 = *puVar3;
78: *puVar13 = puVar3[0xff];
79: puVar7 = puVar8;
80: puVar13 = puVar13 + 1;
81: } while (puVar8 != puVar3 + -0x100);
82: }
83: iStack60 = iStack60 + 1;
84: lVar17 = lVar17 + 4;
85: lVar16 = lVar16 + 8;
86: if (*(int *)(param_1 + 0x90) == iStack60 || *(int *)(param_1 + 0x90) < iStack60) break;
87: lVar4 = *(long *)(lVar2 + 0x30);
88: }
89: }
90: return;
91: }
92: 
