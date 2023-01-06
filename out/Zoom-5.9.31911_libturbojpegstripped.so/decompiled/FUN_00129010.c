1: 
2: void FUN_00129010(code **param_1,int param_2)
3: 
4: {
5: undefined8 *puVar1;
6: int iVar2;
7: code *pcVar3;
8: undefined8 *puVar4;
9: long lVar5;
10: undefined8 uVar6;
11: int iVar7;
12: int iVar8;
13: long lVar9;
14: undefined8 *puVar10;
15: long lVar11;
16: code *pcVar12;
17: undefined8 *puVar13;
18: code *pcVar14;
19: long lVar15;
20: int iVar16;
21: long lVar17;
22: 
23: pcVar3 = param_1[0x45];
24: if (param_2 == 0) {
25: if (*(int *)(param_1[0x4c] + 0x10) == 0) {
26: *(code **)(pcVar3 + 8) = FUN_00128c30;
27: }
28: else {
29: iVar2 = *(int *)(param_1 + 0x34);
30: pcVar14 = param_1[0x26];
31: *(code **)(pcVar3 + 8) = FUN_00128cd0;
32: if (0 < *(int *)(param_1 + 7)) {
33: lVar15 = 0;
34: pcVar12 = pcVar14 + ((ulong)(*(int *)(param_1 + 7) - 1) * 3 + 3) * 0x20;
35: do {
36: lVar9 = 0;
37: iVar8 = (*(int *)(pcVar14 + 0xc) * *(int *)(pcVar14 + 0x24)) / iVar2;
38: puVar4 = *(undefined8 **)(*(long *)(pcVar3 + 0x68) + lVar15);
39: iVar16 = iVar8 * (iVar2 + 2);
40: lVar11 = *(long *)(*(long *)(pcVar3 + 0x70) + lVar15);
41: lVar5 = *(long *)(pcVar3 + lVar15 + 0x10);
42: if (0 < iVar16) {
43: do {
44: uVar6 = *(undefined8 *)(lVar5 + lVar9 * 8);
45: *(undefined8 *)(lVar11 + lVar9 * 8) = uVar6;
46: puVar4[lVar9] = uVar6;
47: lVar9 = lVar9 + 1;
48: } while ((int)lVar9 < iVar16);
49: }
50: iVar7 = iVar8 * 2;
51: if (0 < iVar7) {
52: iVar16 = iVar16 + iVar8 * -4;
53: lVar17 = (long)(iVar7 + iVar16);
54: lVar9 = iVar16 - lVar17;
55: puVar10 = (undefined8 *)(lVar5 + lVar17 * 8);
56: puVar13 = (undefined8 *)(lVar11 + lVar17 * 8);
57: do {
58: puVar13[lVar9] = *puVar10;
59: puVar1 = puVar10 + lVar9;
60: puVar10 = puVar10 + 1;
61: *puVar13 = *puVar1;
62: puVar13 = puVar13 + 1;
63: } while (puVar10 != (undefined8 *)(lVar5 + 8 + ((ulong)(iVar7 - 1) + lVar17) * 8));
64: }
65: if (0 < iVar8) {
66: lVar11 = 0;
67: do {
68: puVar4[-iVar8 + lVar11] = *puVar4;
69: lVar11 = lVar11 + 1;
70: } while ((int)lVar11 < iVar8);
71: }
72: pcVar14 = pcVar14 + 0x60;
73: lVar15 = lVar15 + 8;
74: } while (pcVar14 != pcVar12);
75: }
76: *(undefined4 *)(pcVar3 + 0x78) = 0;
77: *(undefined4 *)(pcVar3 + 0x7c) = 0;
78: *(undefined4 *)(pcVar3 + 0x84) = 0;
79: }
80: *(undefined4 *)(pcVar3 + 0x60) = 0;
81: *(undefined4 *)(pcVar3 + 100) = 0;
82: return;
83: }
84: if (param_2 == 2) {
85: *(code **)(pcVar3 + 8) = FUN_00128fe0;
86: return;
87: }
88: param_1 = (code **)*param_1;
89: *(undefined4 *)(param_1 + 5) = 4;
90: /* WARNING: Could not recover jumptable at 0x0012903d. Too many branches */
91: /* WARNING: Treating indirect jump as call */
92: (**param_1)();
93: return;
94: }
95: 
