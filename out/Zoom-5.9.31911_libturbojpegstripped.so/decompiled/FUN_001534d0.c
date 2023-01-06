1: 
2: undefined8 FUN_001534d0(long param_1,long param_2)
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
17: long lVar13;
18: int iVar14;
19: undefined *puVar15;
20: undefined *puVar16;
21: 
22: uVar11 = (ulong)*(uint *)(param_1 + 0x3c);
23: iVar14 = *(int *)(param_2 + 0x50);
24: uVar6 = *(undefined8 *)(param_2 + 0x18);
25: lVar7 = *(long *)(param_2 + 0x48);
26: iVar1 = *(int *)(&DAT_0018c4a0 + uVar11 * 4);
27: lVar13 = (long)iVar1;
28: lVar12 = (long)*(int *)(&DAT_0018c380 + uVar11 * 4);
29: iVar2 = *(int *)(&DAT_0018c440 + uVar11 * 4);
30: iVar3 = *(int *)(&DAT_0018c3e0 + uVar11 * 4);
31: iVar4 = *(int *)(&DAT_0018c320 + uVar11 * 4);
32: lVar8 = **(long **)(param_2 + 0x20);
33: if (iVar14 == 0xff) {
34: if (iVar4 < 0) {
35: iVar14 = *(int *)(param_1 + 0x30);
36: if (iVar14 != 0) {
37: puVar15 = (undefined *)(lVar8 + iVar1);
38: do {
39: uVar9 = FUN_00152a10(param_1,uVar6,0xff);
40: *puVar15 = uVar9;
41: uVar9 = FUN_00152a10(param_1,uVar6,0xff);
42: puVar16 = puVar15 + -(long)iVar1;
43: puVar16[iVar2] = uVar9;
44: uVar9 = FUN_00152a10(param_1,uVar6,0xff);
45: puVar15 = puVar15 + lVar12;
46: iVar14 = iVar14 + -1;
47: puVar16[iVar3] = uVar9;
48: } while (iVar14 != 0);
49: }
50: }
51: else {
52: iVar14 = *(int *)(param_1 + 0x30);
53: if (iVar14 != 0) {
54: puVar15 = (undefined *)(lVar8 + lVar13);
55: do {
56: uVar9 = FUN_00152a10(param_1,uVar6,0xff);
57: *puVar15 = uVar9;
58: uVar9 = FUN_00152a10(param_1,uVar6,0xff);
59: puVar16 = puVar15 + -lVar13;
60: puVar16[iVar2] = uVar9;
61: uVar9 = FUN_00152a10(param_1,uVar6,0xff);
62: puVar15 = puVar15 + lVar12;
63: iVar14 = iVar14 + -1;
64: puVar16[iVar3] = uVar9;
65: puVar16[iVar4] = 0xff;
66: } while (iVar14 != 0);
67: }
68: }
69: }
70: else {
71: iVar5 = *(int *)(param_1 + 0x30);
72: if (iVar4 < 0) {
73: if (iVar5 != 0) {
74: puVar15 = (undefined *)(lVar8 + iVar1);
75: do {
76: uVar10 = FUN_00152a10(param_1,uVar6,iVar14);
77: *puVar15 = *(undefined *)(lVar7 + (ulong)uVar10);
78: uVar10 = FUN_00152a10(param_1,uVar6,iVar14);
79: puVar16 = puVar15 + -(long)iVar1;
80: puVar16[iVar2] = *(undefined *)(lVar7 + (ulong)uVar10);
81: uVar10 = FUN_00152a10(param_1,uVar6,iVar14);
82: puVar15 = puVar15 + lVar12;
83: iVar5 = iVar5 + -1;
84: puVar16[iVar3] = *(undefined *)(lVar7 + (ulong)uVar10);
85: } while (iVar5 != 0);
86: }
87: }
88: else {
89: if (iVar5 != 0) {
90: puVar15 = (undefined *)(lVar8 + lVar13);
91: do {
92: uVar10 = FUN_00152a10(param_1,uVar6,iVar14);
93: *puVar15 = *(undefined *)(lVar7 + (ulong)uVar10);
94: uVar10 = FUN_00152a10(param_1,uVar6,iVar14);
95: puVar16 = puVar15 + -lVar13;
96: puVar16[iVar2] = *(undefined *)(lVar7 + (ulong)uVar10);
97: uVar10 = FUN_00152a10(param_1,uVar6,iVar14);
98: puVar15 = puVar15 + lVar12;
99: iVar5 = iVar5 + -1;
100: puVar16[iVar3] = *(undefined *)(lVar7 + (ulong)uVar10);
101: puVar16[iVar4] = 0xff;
102: } while (iVar5 != 0);
103: }
104: }
105: }
106: return 1;
107: }
108: 
