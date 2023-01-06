1: 
2: void FUN_001291c0(code **param_1,int param_2)
3: 
4: {
5: int *piVar1;
6: int *piVar2;
7: code **ppcVar3;
8: code **ppcVar4;
9: long lVar5;
10: long lVar6;
11: code *pcVar7;
12: int iVar8;
13: code *pcVar9;
14: int iVar10;
15: int iVar11;
16: int iVar12;
17: 
18: ppcVar4 = (code **)(**(code **)param_1[1])(param_1,1,0x88);
19: param_1[0x45] = (code *)ppcVar4;
20: *ppcVar4 = FUN_00129010;
21: if (param_2 != 0) {
22: ppcVar3 = (code **)*param_1;
23: *(undefined4 *)(ppcVar3 + 5) = 4;
24: (**ppcVar3)(param_1);
25: }
26: iVar11 = *(int *)(param_1 + 0x34);
27: if (*(int *)(param_1[0x4c] + 0x10) == 0) {
28: iVar8 = *(int *)(param_1 + 7);
29: pcVar9 = param_1[0x26];
30: iVar12 = iVar11;
31: }
32: else {
33: if (iVar11 < 2) {
34: ppcVar3 = (code **)*param_1;
35: *(undefined4 *)(ppcVar3 + 5) = 0x2f;
36: (**ppcVar3)(param_1);
37: iVar11 = *(int *)(param_1 + 0x34);
38: }
39: pcVar7 = param_1[0x45];
40: lVar5 = (**(code **)param_1[1])(param_1,1,(long)(*(int *)(param_1 + 7) * 2) << 3);
41: iVar8 = *(int *)(param_1 + 7);
42: pcVar9 = param_1[0x26];
43: *(long *)(pcVar7 + 0x68) = lVar5;
44: *(long *)(pcVar7 + 0x70) = lVar5 + (long)iVar8 * 8;
45: if (0 < iVar8) {
46: lVar5 = 0;
47: iVar12 = 0;
48: do {
49: piVar1 = (int *)(pcVar9 + 0xc);
50: piVar2 = (int *)(pcVar9 + 0x24);
51: iVar12 = iVar12 + 1;
52: pcVar9 = pcVar9 + 0x60;
53: iVar8 = (*piVar1 * *piVar2) / *(int *)(param_1 + 0x34);
54: iVar10 = (iVar11 + 4) * iVar8;
55: lVar6 = (**(code **)param_1[1])(param_1,1,(long)(iVar10 * 2) << 3);
56: lVar6 = lVar6 + (long)iVar8 * 8;
57: *(long *)(*(long *)(pcVar7 + 0x68) + lVar5) = lVar6;
58: *(long *)(*(long *)(pcVar7 + 0x70) + lVar5) = lVar6 + (long)iVar10 * 8;
59: iVar8 = *(int *)(param_1 + 7);
60: lVar5 = lVar5 + 8;
61: } while (iVar12 < iVar8);
62: pcVar9 = param_1[0x26];
63: }
64: iVar11 = *(int *)(param_1 + 0x34) + 2;
65: iVar12 = *(int *)(param_1 + 0x34);
66: }
67: iVar10 = 0;
68: if (0 < iVar8) {
69: while( true ) {
70: iVar10 = iVar10 + 1;
71: pcVar7 = (code *)(**(code **)(param_1[1] + 0x10))
72: (param_1,1,*(int *)(pcVar9 + 0x24) * *(int *)(pcVar9 + 0x1c),
73: ((*(int *)(pcVar9 + 0xc) * *(int *)(pcVar9 + 0x24)) / iVar12) *
74: iVar11);
75: ppcVar4[2] = pcVar7;
76: if (*(int *)(param_1 + 7) == iVar10 || *(int *)(param_1 + 7) < iVar10) break;
77: iVar12 = *(int *)(param_1 + 0x34);
78: pcVar9 = pcVar9 + 0x60;
79: ppcVar4 = ppcVar4 + 1;
80: }
81: }
82: return;
83: }
84: 
