1: 
2: undefined8 FUN_00108530(code **param_1,long param_2)
3: 
4: {
5: short sVar1;
6: code *pcVar2;
7: long *plVar3;
8: long lVar4;
9: short *psVar5;
10: code **ppcVar6;
11: uint uVar7;
12: int iVar8;
13: long lVar9;
14: long lVar10;
15: uint uVar11;
16: int *piVar12;
17: int iVar13;
18: long lStack88;
19: 
20: iVar8 = *(int *)(param_1 + 0x23);
21: pcVar2 = param_1[0x3e];
22: if (iVar8 != 0) {
23: iVar13 = *(int *)(pcVar2 + 0x38);
24: if ((*(int *)(pcVar2 + 0x38) == 0) && (iVar13 = iVar8, 0 < *(int *)((long)param_1 + 0x144))) {
25: memset(pcVar2 + 0x24,0,(long)*(int *)((long)param_1 + 0x144) * 4);
26: }
27: *(int *)(pcVar2 + 0x38) = iVar13 + -1;
28: }
29: if (0 < *(int *)(param_1 + 0x2e)) {
30: lStack88 = 0;
31: do {
32: lVar9 = (long)*(int *)((long)param_1 + lStack88 * 4 + 0x174);
33: plVar3 = *(long **)(pcVar2 + (long)*(int *)(param_1[lVar9 + 0x29] + 0x18) * 8 + 0xa0);
34: lVar4 = *(long *)(pcVar2 + (long)*(int *)(param_1[lVar9 + 0x29] + 0x14) * 8 + 0x80);
35: psVar5 = *(short **)(param_2 + lStack88 * 8);
36: uVar7 = (int)*psVar5 - *(int *)(pcVar2 + lVar9 * 4 + 0x24);
37: uVar11 = (int)uVar7 >> 0x1f;
38: iVar8 = (uVar7 ^ uVar11) - uVar11;
39: if (iVar8 == 0) {
40: lVar10 = 0;
41: }
42: else {
43: iVar13 = 0;
44: do {
45: iVar13 = iVar13 + 1;
46: iVar8 = iVar8 >> 1;
47: } while (iVar8 != 0);
48: if (iVar13 < 0xc) {
49: lVar10 = (long)iVar13 << 3;
50: }
51: else {
52: ppcVar6 = (code **)*param_1;
53: *(undefined4 *)(ppcVar6 + 5) = 6;
54: (**ppcVar6)();
55: lVar10 = (long)iVar13 << 3;
56: }
57: }
58: *(long *)(lVar4 + lVar10) = *(long *)(lVar4 + lVar10) + 1;
59: uVar7 = 0;
60: piVar12 = (int *)&UNK_0018b464;
61: do {
62: sVar1 = psVar5[*piVar12];
63: if (sVar1 == 0) {
64: uVar7 = uVar7 + 1;
65: }
66: else {
67: if (0xf < (int)uVar7) {
68: uVar11 = uVar7 - 0x10;
69: uVar7 = uVar11 & 0xf;
70: plVar3[0xf0] = plVar3[0xf0] + 1 + (ulong)(uVar11 >> 4);
71: }
72: iVar13 = 1;
73: uVar11 = (int)sVar1 >> 0x1f;
74: iVar8 = (int)(((int)sVar1 ^ uVar11) - uVar11) >> 1;
75: if (iVar8 != 0) {
76: do {
77: iVar13 = iVar13 + 1;
78: iVar8 = iVar8 >> 1;
79: } while (iVar8 != 0);
80: if (10 < iVar13) {
81: ppcVar6 = (code **)*param_1;
82: *(undefined4 *)(ppcVar6 + 5) = 6;
83: (**ppcVar6)();
84: }
85: }
86: plVar3[(int)(iVar13 + uVar7 * 0x10)] = plVar3[(int)(iVar13 + uVar7 * 0x10)] + 1;
87: uVar7 = 0;
88: }
89: piVar12 = piVar12 + 1;
90: } while (piVar12 != (int *)&UNK_0018b560);
91: if (uVar7 != 0) {
92: *plVar3 = *plVar3 + 1;
93: }
94: *(int *)(pcVar2 + lVar9 * 4 + 0x24) = (int)**(short **)(param_2 + lStack88 * 8);
95: iVar8 = (int)lStack88 + 1;
96: lStack88 = lStack88 + 1;
97: } while (*(int *)(param_1 + 0x2e) != iVar8 && iVar8 <= *(int *)(param_1 + 0x2e));
98: }
99: return 1;
100: }
101: 
