1: 
2: undefined8 FUN_0013f6e0(long param_1,long *param_2)
3: 
4: {
5: long lVar1;
6: short sVar2;
7: int iVar3;
8: long lVar4;
9: long lVar5;
10: int iVar6;
11: byte bVar7;
12: int iVar8;
13: uint uVar9;
14: int iVar10;
15: long lVar11;
16: int iStack64;
17: 
18: lVar4 = *(long *)(param_1 + 0x1f0);
19: if (*(int *)(param_1 + 0x118) != 0) {
20: iVar8 = *(int *)(lVar4 + 0x60);
21: if (iVar8 == 0) {
22: FUN_0013ef30();
23: iVar8 = *(int *)(param_1 + 0x118);
24: *(uint *)(lVar4 + 100) = *(int *)(lVar4 + 100) + 1U & 7;
25: }
26: *(int *)(lVar4 + 0x60) = iVar8 + -1;
27: }
28: iVar8 = *(int *)(param_1 + 0x1a0);
29: lVar5 = *param_2;
30: iVar3 = *(int *)(*(long *)(param_1 + 0x148) + 0x18);
31: iVar10 = iVar8;
32: iStack64 = iVar8;
33: if (0 < iVar8) {
34: do {
35: sVar2 = *(short *)(lVar5 + (long)*(int *)(&DAT_0018b460 + (long)iVar10 * 4) * 2);
36: iVar6 = (int)sVar2;
37: bVar7 = (byte)*(undefined4 *)(param_1 + 0x1a8);
38: if (iVar6 < 0) {
39: iVar6 = -iVar6 >> (bVar7 & 0x1f);
40: }
41: else {
42: iVar6 = iVar6 >> (bVar7 & 0x1f);
43: }
44: if (iVar6 != 0) {
45: iStack64 = iVar10;
46: if (0 < iVar10) {
47: while( true ) {
48: iVar6 = (int)sVar2;
49: if (iVar6 < 0) {
50: iVar6 = -iVar6;
51: }
52: if ((iVar6 >> ((byte)*(undefined4 *)(param_1 + 0x1a4) & 0x1f) != 0) ||
53: (iStack64 = iStack64 + -1, iStack64 == 0)) break;
54: sVar2 = *(short *)(lVar5 + (long)*(int *)(&DAT_0018b460 + (long)iStack64 * 4) * 2);
55: }
56: }
57: break;
58: }
59: iVar10 = iVar10 + -1;
60: iStack64 = iVar10;
61: } while (iVar10 != 0);
62: }
63: iVar6 = *(int *)(param_1 + 0x19c);
64: if (iVar6 <= iVar10) {
65: LAB_0013f7f0:
66: lVar11 = (long)(iVar6 * 3 + -3) + *(long *)(lVar4 + 0xe8 + (long)iVar3 * 8);
67: if (iStack64 < iVar6) {
68: FUN_0013e1a0(param_1,lVar11);
69: }
70: do {
71: iVar8 = (int)*(short *)(lVar5 + (long)*(int *)(&DAT_0018b460 + (long)iVar6 * 4) * 2);
72: if (iVar8 < 0) {
73: uVar9 = -iVar8 >> ((byte)*(undefined4 *)(param_1 + 0x1a8) & 0x1f);
74: if (uVar9 != 0) goto code_r0x0013f85c;
75: }
76: else {
77: uVar9 = iVar8 >> ((byte)*(undefined4 *)(param_1 + 0x1a8) & 0x1f);
78: if (uVar9 != 0) {
79: if (uVar9 >> 1 != 0) goto LAB_0013f8f8;
80: FUN_0013dd70(param_1,lVar11 + 1);
81: FUN_0013e1a0(param_1);
82: goto LAB_0013f880;
83: }
84: }
85: lVar1 = lVar11 + 1;
86: lVar11 = lVar11 + 3;
87: iVar6 = iVar6 + 1;
88: FUN_0013e1a0(param_1,lVar1);
89: } while( true );
90: }
91: LAB_0013f894:
92: if (iVar6 <= iVar8) {
93: FUN_0013dd70(param_1,(long)(iVar6 * 3 + -3) + *(long *)(lVar4 + 0xe8 + (long)iVar3 * 8));
94: }
95: return 1;
96: code_r0x0013f85c:
97: if (uVar9 >> 1 == 0) {
98: FUN_0013dd70(param_1,lVar11 + 1);
99: FUN_0013dd70(param_1);
100: }
101: else {
102: LAB_0013f8f8:
103: FUN_0013e5d0(param_1,lVar11 + 2,uVar9 & 1);
104: }
105: LAB_0013f880:
106: iVar6 = iVar6 + 1;
107: if (iVar10 < iVar6) goto code_r0x0013f88d;
108: goto LAB_0013f7f0;
109: code_r0x0013f88d:
110: iVar8 = *(int *)(param_1 + 0x1a0);
111: goto LAB_0013f894;
112: }
113: 
