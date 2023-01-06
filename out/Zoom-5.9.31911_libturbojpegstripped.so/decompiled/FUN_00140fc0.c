1: 
2: undefined8 FUN_00140fc0(long *param_1,long *param_2)
3: 
4: {
5: short *psVar1;
6: short sVar2;
7: undefined4 uVar3;
8: int iVar4;
9: int iVar5;
10: long lVar6;
11: long lVar7;
12: int iVar8;
13: long lVar9;
14: int iVar10;
15: short sStack72;
16: short sStack68;
17: 
18: lVar6 = param_1[0x4a];
19: if (*(int *)(param_1 + 0x2e) != 0) {
20: iVar8 = *(int *)(lVar6 + 0x4c);
21: if (iVar8 == 0) {
22: FUN_00140730();
23: iVar8 = *(int *)(lVar6 + 0x4c);
24: }
25: *(int *)(lVar6 + 0x4c) = iVar8 + -1;
26: }
27: if (*(int *)(lVar6 + 0x28) != -1) {
28: uVar3 = *(undefined4 *)(param_1 + 0x43);
29: iVar8 = *(int *)(param_1 + 0x42);
30: lVar7 = *param_2;
31: iVar4 = *(int *)(param_1[0x37] + 0x18);
32: iVar5 = iVar8;
33: if (0 < iVar8) {
34: sVar2 = *(short *)(lVar7 + (long)*(int *)(&DAT_0018b460 + (long)iVar8 * 4) * 2);
35: while ((sVar2 == 0 && (iVar5 = iVar5 + -1, iVar5 != 0))) {
36: sVar2 = *(short *)(lVar7 + (long)*(int *)(&DAT_0018b460 + (long)iVar5 * 4) * 2);
37: }
38: }
39: iVar10 = *(int *)((long)param_1 + 0x20c);
40: if (iVar10 <= iVar8) {
41: LAB_001410a8:
42: do {
43: iVar8 = iVar10 * 3 + -3;
44: lVar9 = (long)iVar8 + *(long *)(lVar6 + 0xd0 + (long)iVar4 * 8);
45: if ((iVar5 < iVar10) && (iVar8 = FUN_00140970(param_1,lVar9,(long)iVar4,iVar8), iVar8 != 0))
46: {
47: return 1;
48: }
49: while( true ) {
50: psVar1 = (short *)(lVar7 + (long)*(int *)(&DAT_0018b460 + (long)iVar10 * 4) * 2);
51: sStack68 = (short)(-1 << ((byte)uVar3 & 0x1f));
52: sStack72 = (short)(1 << ((byte)uVar3 & 0x1f));
53: if (*psVar1 != 0) break;
54: iVar8 = FUN_00140970(param_1,lVar9 + 1);
55: if (iVar8 != 0) {
56: iVar8 = FUN_00140970(param_1,lVar6 + 0x150);
57: if (iVar8 == 0) {
58: sStack68 = sStack72;
59: }
60: iVar10 = iVar10 + 1;
61: iVar8 = *(int *)(param_1 + 0x42);
62: *psVar1 = sStack68;
63: if (iVar8 < iVar10) {
64: return 1;
65: }
66: goto LAB_001410a8;
67: }
68: lVar9 = lVar9 + 3;
69: iVar10 = iVar10 + 1;
70: if (*(int *)(param_1 + 0x42) < iVar10) {
71: lVar7 = *param_1;
72: *(undefined4 *)(lVar7 + 0x28) = 0x7e;
73: (**(code **)(lVar7 + 8))(param_1,0xffffffff);
74: *(undefined4 *)(lVar6 + 0x28) = 0xffffffff;
75: return 1;
76: }
77: }
78: iVar8 = FUN_00140970(param_1,lVar9 + 2);
79: if (iVar8 == 0) {
80: LAB_00141144:
81: iVar10 = iVar10 + 1;
82: if (*(int *)(param_1 + 0x42) < iVar10) {
83: return 1;
84: }
85: goto LAB_001410a8;
86: }
87: sVar2 = *psVar1;
88: if (-1 < sVar2) {
89: *psVar1 = sVar2 + sStack72;
90: goto LAB_00141144;
91: }
92: iVar10 = iVar10 + 1;
93: iVar8 = *(int *)(param_1 + 0x42);
94: *psVar1 = sVar2 + sStack68;
95: if (iVar8 < iVar10) {
96: return 1;
97: }
98: } while( true );
99: }
100: }
101: return 1;
102: }
103: 
