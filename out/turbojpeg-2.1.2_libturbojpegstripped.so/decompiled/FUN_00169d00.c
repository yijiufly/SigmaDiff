1: 
2: undefined8 FUN_00169d00(long param_1,long param_2)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: int iVar3;
8: int iVar4;
9: int iVar5;
10: undefined8 uVar6;
11: long lVar7;
12: long lVar8;
13: undefined uVar9;
14: uint uVar10;
15: ulong uVar11;
16: long lVar12;
17: undefined *puVar13;
18: undefined *puVar14;
19: long lVar15;
20: int iVar16;
21: 
22: uVar11 = (ulong)*(uint *)(param_1 + 0x3c);
23: iVar1 = *(int *)(param_2 + 0x50);
24: uVar6 = *(undefined8 *)(param_2 + 0x18);
25: iVar16 = *(int *)(param_1 + 0x30);
26: iVar2 = *(int *)(&DAT_00190860 + uVar11 * 4);
27: iVar3 = *(int *)(&DAT_00190800 + uVar11 * 4);
28: iVar4 = *(int *)(&DAT_001907a0 + uVar11 * 4);
29: lVar15 = (long)iVar4;
30: iVar5 = *(int *)(&DAT_001906e0 + uVar11 * 4);
31: lVar12 = (long)*(int *)(&DAT_00190740 + uVar11 * 4);
32: lVar7 = **(long **)(param_2 + 0x20);
33: if (iVar1 == 0xff) {
34: if (iVar5 < 0) {
35: if (iVar16 != 0) {
36: puVar14 = (undefined *)(lVar7 + iVar2);
37: do {
38: uVar9 = FUN_00169820(param_1,uVar6,0xff);
39: *puVar14 = uVar9;
40: uVar9 = FUN_00169820(param_1,uVar6,0xff);
41: puVar13 = puVar14 + -(long)iVar2;
42: puVar13[iVar3] = uVar9;
43: uVar9 = FUN_00169820(param_1,uVar6,0xff);
44: puVar14 = puVar14 + lVar12;
45: iVar16 = iVar16 + -1;
46: puVar13[iVar4] = uVar9;
47: } while (iVar16 != 0);
48: }
49: }
50: else {
51: if (iVar16 != 0) {
52: puVar14 = (undefined *)(lVar7 + iVar2);
53: do {
54: uVar9 = FUN_00169820(param_1,uVar6,0xff);
55: *puVar14 = uVar9;
56: uVar9 = FUN_00169820(param_1,uVar6,0xff);
57: puVar13 = puVar14 + -(long)iVar2;
58: puVar13[iVar3] = uVar9;
59: uVar9 = FUN_00169820(param_1,uVar6,0xff);
60: puVar14 = puVar14 + lVar12;
61: iVar16 = iVar16 + -1;
62: puVar13[lVar15] = uVar9;
63: puVar13[iVar5] = 0xff;
64: } while (iVar16 != 0);
65: }
66: }
67: }
68: else {
69: lVar8 = *(long *)(param_2 + 0x48);
70: if (iVar5 < 0) {
71: if (iVar16 != 0) {
72: puVar14 = (undefined *)(lVar7 + iVar2);
73: do {
74: uVar10 = FUN_00169820(param_1,uVar6,iVar1);
75: *puVar14 = *(undefined *)(lVar8 + (ulong)uVar10);
76: uVar10 = FUN_00169820(param_1,uVar6,iVar1);
77: puVar13 = puVar14 + -(long)iVar2;
78: puVar13[iVar3] = *(undefined *)(lVar8 + (ulong)uVar10);
79: uVar10 = FUN_00169820(param_1,uVar6,iVar1);
80: puVar14 = puVar14 + lVar12;
81: iVar16 = iVar16 + -1;
82: puVar13[lVar15] = *(undefined *)(lVar8 + (ulong)uVar10);
83: } while (iVar16 != 0);
84: }
85: }
86: else {
87: if (iVar16 != 0) {
88: puVar14 = (undefined *)(lVar7 + iVar2);
89: do {
90: uVar10 = FUN_00169820(param_1,uVar6,iVar1);
91: *puVar14 = *(undefined *)(lVar8 + (ulong)uVar10);
92: uVar10 = FUN_00169820(param_1,uVar6,iVar1);
93: puVar13 = puVar14 + -(long)iVar2;
94: puVar13[iVar3] = *(undefined *)(lVar8 + (ulong)uVar10);
95: uVar10 = FUN_00169820(param_1,uVar6,iVar1);
96: puVar14 = puVar14 + lVar12;
97: iVar16 = iVar16 + -1;
98: puVar13[lVar15] = *(undefined *)(lVar8 + (ulong)uVar10);
99: puVar13[iVar5] = 0xff;
100: } while (iVar16 != 0);
101: }
102: }
103: }
104: return 1;
105: }
106: 
