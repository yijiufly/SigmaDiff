1: 
2: void FUN_0013d550(long param_1,long param_2,byte **param_3,long *param_4)
3: 
4: {
5: byte bVar1;
6: byte bVar2;
7: long lVar3;
8: int iVar4;
9: long lVar5;
10: uint uVar6;
11: ulong uVar7;
12: long *plVar8;
13: long *plVar9;
14: uint uVar10;
15: ulong uVar11;
16: ulong uVar12;
17: ulong uVar13;
18: byte *pbVar14;
19: long *plVar15;
20: ulong uVar16;
21: byte bVar17;
22: 
23: bVar17 = 0;
24: lVar3 = *param_4;
25: bVar1 = *(byte *)(*(long *)(param_1 + 0x260) + 0xe8 + (long)*(int *)(param_2 + 4));
26: bVar2 = *(byte *)(*(long *)(param_1 + 0x260) + 0xf2 + (long)*(int *)(param_2 + 4));
27: uVar6 = (uint)bVar2;
28: if (*(int *)(param_1 + 0x19c) < 1) {
29: return;
30: }
31: uVar12 = (ulong)bVar2;
32: uVar11 = (long)(int)(bVar1 - 1) + 1;
33: uVar10 = (uint)uVar11;
34: uVar13 = uVar12;
35: do {
36: iVar4 = (int)uVar13;
37: plVar8 = *(long **)(lVar3 + uVar12 * -8 + uVar13 * 8);
38: plVar15 = (long *)((ulong)*(uint *)(param_1 + 0x88) + (long)plVar8);
39: if ((plVar8 < plVar15) && (bVar1 != 0)) {
40: uVar16 = uVar11 & 0xffffffff;
41: pbVar14 = *param_3;
42: do {
43: while( true ) {
44: lVar5 = (ulong)*pbVar14 * 0x101010101010101;
45: if (uVar10 < 8) break;
46: *plVar8 = lVar5;
47: *(long *)((long)plVar8 + (uVar16 - 8)) = lVar5;
48: plVar9 = (long *)((long)plVar8 + uVar11);
49: uVar7 = (ulong)(((int)plVar8 - (int)(long *)((ulong)(plVar8 + 1) & 0xfffffffffffffff8)) +
50: uVar10 >> 3);
51: plVar8 = (long *)((ulong)(plVar8 + 1) & 0xfffffffffffffff8);
52: while (uVar7 != 0) {
53: uVar7 = uVar7 - 1;
54: *plVar8 = lVar5;
55: plVar8 = plVar8 + (ulong)bVar17 * -2 + 1;
56: }
57: plVar8 = plVar9;
58: pbVar14 = pbVar14 + 1;
59: if (plVar15 <= plVar9) goto LAB_0013d677;
60: }
61: if ((uVar11 & 4) == 0) {
62: if ((uVar10 != 0) && (*(char *)plVar8 = (char)lVar5, (uVar11 & 2) != 0)) {
63: *(short *)((long)plVar8 + (uVar16 - 2)) = (short)lVar5;
64: }
65: }
66: else {
67: *(int *)plVar8 = (int)lVar5;
68: *(int *)((long)plVar8 + (uVar16 - 4)) = (int)lVar5;
69: }
70: plVar8 = (long *)((long)plVar8 + uVar11);
71: pbVar14 = pbVar14 + 1;
72: } while (plVar8 < plVar15);
73: }
74: LAB_0013d677:
75: if (uVar6 < 2) {
76: param_3 = param_3 + 1;
77: uVar13 = uVar13 + uVar12;
78: if (*(int *)(param_1 + 0x19c) == iVar4 || *(int *)(param_1 + 0x19c) < iVar4) {
79: return;
80: }
81: }
82: else {
83: param_3 = param_3 + 1;
84: FUN_00148a00(lVar3,iVar4 - uVar6,lVar3,(iVar4 - uVar6) + 1,uVar6 - 1,
85: *(undefined4 *)(param_1 + 0x88));
86: uVar13 = uVar13 + uVar12;
87: if (*(int *)(param_1 + 0x19c) <= iVar4) {
88: return;
89: }
90: }
91: } while( true );
92: }
93: 
