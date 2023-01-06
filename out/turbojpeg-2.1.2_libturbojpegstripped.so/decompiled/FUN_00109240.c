1: 
2: undefined8 FUN_00109240(code **param_1,long param_2)
3: 
4: {
5: short sVar1;
6: code *pcVar2;
7: short *psVar3;
8: long *plVar4;
9: code **ppcVar5;
10: uint uVar6;
11: int iVar7;
12: long lVar8;
13: int iVar9;
14: int iVar10;
15: uint uVar11;
16: long *plVar12;
17: int *piVar13;
18: long lStack88;
19: 
20: iVar10 = *(int *)(param_1 + 0x23);
21: pcVar2 = param_1[0x3e];
22: if (iVar10 != 0) {
23: iVar7 = *(int *)(pcVar2 + 0x38);
24: if ((*(int *)(pcVar2 + 0x38) == 0) && (iVar7 = iVar10, 0 < *(int *)((long)param_1 + 0x144))) {
25: memset(pcVar2 + 0x24,0,(ulong)(*(int *)((long)param_1 + 0x144) - 1) * 4 + 4);
26: }
27: *(int *)(pcVar2 + 0x38) = iVar7 + -1;
28: }
29: if (0 < *(int *)(param_1 + 0x2e)) {
30: lStack88 = 1;
31: do {
32: lVar8 = (long)*(int *)((long)param_1 + lStack88 * 4 + 0x170);
33: iVar10 = *(int *)(pcVar2 + lVar8 * 4 + 0x24);
34: psVar3 = *(short **)(param_2 + -8 + lStack88 * 8);
35: plVar4 = *(long **)(pcVar2 + (long)*(int *)(param_1[lVar8 + 0x29] + 0x18) * 8 + 0xa0);
36: plVar12 = *(long **)(pcVar2 + (long)*(int *)(param_1[lVar8 + 0x29] + 0x14) * 8 + 0x80);
37: iVar9 = (int)*psVar3;
38: uVar6 = iVar9 - iVar10;
39: uVar11 = (int)uVar6 >> 0x1f;
40: iVar7 = (uVar6 ^ uVar11) - uVar11;
41: if (iVar10 != iVar9) {
42: iVar10 = 0;
43: do {
44: iVar10 = iVar10 + 1;
45: iVar7 = iVar7 >> 1;
46: } while (iVar7 != 0);
47: plVar12 = plVar12 + iVar10;
48: if (0xb < iVar10) {
49: ppcVar5 = (code **)*param_1;
50: *(undefined4 *)(ppcVar5 + 5) = 6;
51: (**ppcVar5)();
52: }
53: }
54: *plVar12 = *plVar12 + 1;
55: uVar6 = 0;
56: piVar13 = (int *)&UNK_0018f104;
57: do {
58: while (sVar1 = psVar3[*piVar13], sVar1 == 0) {
59: piVar13 = piVar13 + 1;
60: uVar6 = uVar6 + 1;
61: if (piVar13 == (int *)&UNK_0018f200) goto LAB_001093e8;
62: }
63: uVar11 = uVar6;
64: if (0xf < (int)uVar6) {
65: uVar11 = uVar6 - 0x10 & 0xf;
66: plVar4[0xf0] = plVar4[0xf0] + 1 + (ulong)(uVar6 - 0x10 >> 4);
67: }
68: iVar7 = 1;
69: uVar6 = (int)sVar1 >> 0x1f;
70: iVar10 = (int)(((int)sVar1 ^ uVar6) - uVar6) >> 1;
71: if (iVar10 != 0) {
72: do {
73: iVar7 = iVar7 + 1;
74: iVar10 = iVar10 >> 1;
75: } while (iVar10 != 0);
76: if (10 < iVar7) {
77: ppcVar5 = (code **)*param_1;
78: *(undefined4 *)(ppcVar5 + 5) = 6;
79: (**ppcVar5)();
80: }
81: }
82: piVar13 = piVar13 + 1;
83: uVar6 = 0;
84: plVar4[(int)(iVar7 + uVar11 * 0x10)] = plVar4[(int)(iVar7 + uVar11 * 0x10)] + 1;
85: } while (piVar13 != (int *)&UNK_0018f200);
86: LAB_001093e8:
87: if (uVar6 != 0) {
88: *plVar4 = *plVar4 + 1;
89: }
90: *(int *)(pcVar2 + lVar8 * 4 + 0x24) = (int)**(short **)(param_2 + -8 + lStack88 * 8);
91: iVar10 = (int)lStack88;
92: lStack88 = lStack88 + 1;
93: } while (*(int *)(param_1 + 0x2e) != iVar10 && iVar10 <= *(int *)(param_1 + 0x2e));
94: }
95: return 1;
96: }
97: 
