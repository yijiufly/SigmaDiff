1: 
2: void FUN_00125740(code **param_1,uint *param_2,uint *param_3)
3: 
4: {
5: code **ppcVar1;
6: code *pcVar2;
7: bool bVar3;
8: bool bVar4;
9: uint uVar5;
10: int iVar6;
11: uint uVar7;
12: uint uVar8;
13: int iVar9;
14: long lVar10;
15: int iVar11;
16: long lVar12;
17: code *pcVar13;
18: 
19: iVar6 = *(int *)((long)param_1 + 0x24);
20: if ((iVar6 != 0xcd) || (*(int *)(param_1 + 0x15) != 0)) {
21: ppcVar1 = (code **)*param_1;
22: *(undefined4 *)(ppcVar1 + 5) = 0x14;
23: *(int *)((long)ppcVar1 + 0x2c) = iVar6;
24: (**ppcVar1)();
25: }
26: if ((param_2 == (uint *)0x0) || (param_3 == (uint *)0x0)) {
27: ppcVar1 = (code **)*param_1;
28: *(undefined4 *)(ppcVar1 + 5) = 0x7c;
29: (**ppcVar1)();
30: }
31: uVar8 = *param_3;
32: if ((uVar8 == 0) || (uVar7 = *(uint *)(param_1 + 0x11), uVar7 < *param_2 + uVar8)) {
33: ppcVar1 = (code **)*param_1;
34: *(undefined4 *)(ppcVar1 + 5) = 0x46;
35: (**ppcVar1)();
36: uVar8 = *param_3;
37: uVar7 = *(uint *)(param_1 + 0x11);
38: }
39: if (uVar8 != uVar7) {
40: uVar8 = *(uint *)(param_1 + 0x34);
41: if ((*(int *)(param_1 + 0x36) != 1) || (*(int *)(param_1 + 7) != 1)) {
42: uVar8 = uVar8 * *(int *)(param_1 + 0x33);
43: }
44: uVar7 = *param_2;
45: pcVar13 = param_1[0x44];
46: uVar5 = (uVar7 / uVar8) * uVar8;
47: lVar10 = (long)(int)uVar8;
48: *param_2 = uVar5;
49: uVar5 = (uVar7 + *param_3) - uVar5;
50: *param_3 = uVar5;
51: *(uint *)(param_1 + 0x11) = uVar5;
52: uVar8 = *param_2;
53: *(int *)(pcVar13 + 0x14) = (int)((long)(ulong)uVar8 / lVar10);
54: iVar6 = FUN_001489d0(uVar5 + *param_2,lVar10,(long)(ulong)uVar8 % lVar10);
55: pcVar13 = param_1[0x26];
56: *(int *)(param_1[0x44] + 0x18) = iVar6 + -1;
57: iVar6 = *(int *)(param_1 + 7);
58: if (0 < iVar6) {
59: iVar11 = 0;
60: bVar4 = false;
61: do {
62: if ((*(int *)(param_1 + 0x36) != 1) || (iVar9 = 1, iVar6 != 1)) {
63: iVar9 = *(int *)(pcVar13 + 8);
64: }
65: iVar6 = *(int *)(pcVar13 + 0x28);
66: uVar8 = FUN_001489d0(*(int *)(pcVar13 + 8) * *(int *)(param_1 + 0x11),
67: (long)*(int *)(param_1 + 0x33));
68: *(uint *)(pcVar13 + 0x28) = uVar8;
69: bVar3 = bVar4;
70: if ((uVar8 < 2) && (bVar3 = true, iVar6 < 2)) {
71: bVar3 = bVar4;
72: }
73: uVar8 = *param_2;
74: lVar12 = (long)iVar11;
75: iVar6 = *(int *)(param_1 + 0x11);
76: iVar11 = iVar11 + 1;
77: pcVar13 = pcVar13 + 0x60;
78: *(int *)(param_1[0x44] + lVar12 * 4 + 0x1c) = (int)((long)(ulong)(iVar9 * uVar8) / lVar10);
79: iVar6 = FUN_001489d0((iVar6 + *param_2) * iVar9,lVar10,(long)(ulong)(iVar9 * uVar8) % lVar10
80: );
81: pcVar2 = param_1[0x44];
82: *(int *)(pcVar2 + lVar12 * 4 + 0x44) = iVar6 + -1;
83: iVar6 = *(int *)(param_1 + 7);
84: bVar4 = bVar3;
85: } while (iVar11 < iVar6);
86: if (bVar3) {
87: *(undefined4 *)(pcVar2 + 0x6c) = 1;
88: FUN_0013d9c0(param_1);
89: *(undefined4 *)(param_1[0x44] + 0x6c) = 0;
90: return;
91: }
92: }
93: }
94: return;
95: }
96: 
