1: 
2: undefined8 FUN_0013bae0(long param_1,long param_2)
3: 
4: {
5: int *piVar1;
6: undefined4 uVar2;
7: long lVar3;
8: long lVar4;
9: undefined8 uVar5;
10: ushort *puVar6;
11: int iVar7;
12: undefined8 *puVar8;
13: undefined8 uVar9;
14: int iVar10;
15: uint uVar11;
16: ulong uVar12;
17: long lVar13;
18: ulong uVar14;
19: long in_FS_OFFSET;
20: ulong uStack88;
21: int iStack80;
22: 
23: lVar3 = *(long *)(param_1 + 0x250);
24: uVar2 = *(undefined4 *)(param_1 + 0x218);
25: iVar7 = *(int *)(param_1 + 0x170);
26: lVar4 = *(long *)(in_FS_OFFSET + 0x28);
27: uVar11 = *(uint *)(lVar3 + 0x20);
28: uVar12 = (ulong)uVar11;
29: if ((iVar7 != 0) && (*(int *)(lVar3 + 0x3c) == 0)) {
30: lVar13 = *(long *)(param_1 + 0x248);
31: if ((int)uVar11 < 0) {
32: uVar11 = uVar11 + 7;
33: }
34: piVar1 = (int *)(lVar13 + 0x24);
35: *piVar1 = *piVar1 + ((int)uVar11 >> 3);
36: *(undefined4 *)(lVar3 + 0x20) = 0;
37: iVar7 = (**(code **)(lVar13 + 0x10))();
38: if (iVar7 == 0) {
39: LAB_0013bc20:
40: uVar9 = 0;
41: goto LAB_0013bbf5;
42: }
43: if (0 < *(int *)(param_1 + 0x1b0)) {
44: memset((void *)(lVar3 + 0x2c),0,(ulong)(*(int *)(param_1 + 0x1b0) - 1) * 4 + 4);
45: }
46: iVar10 = *(int *)(param_1 + 0x21c);
47: iVar7 = *(int *)(param_1 + 0x170);
48: *(undefined4 *)(lVar3 + 0x28) = 0;
49: *(int *)(lVar3 + 0x3c) = iVar7;
50: if (iVar10 == 0) {
51: *(undefined4 *)(lVar3 + 0x10) = 0;
52: }
53: uVar12 = (ulong)*(uint *)(lVar3 + 0x20);
54: }
55: uVar11 = (uint)uVar12;
56: puVar8 = *(undefined8 **)(param_1 + 0x28);
57: iVar10 = *(int *)(param_1 + 0x1e0);
58: uVar14 = *(ulong *)(lVar3 + 0x18);
59: uVar9 = *puVar8;
60: uVar5 = puVar8[1];
61: if (0 < iVar10) {
62: lVar13 = 1;
63: do {
64: puVar6 = *(ushort **)(param_2 + -8 + lVar13 * 8);
65: iVar7 = (int)uVar12;
66: if ((int)uVar12 < 1) {
67: iVar7 = FUN_00130960();
68: if (iVar7 == 0) goto LAB_0013bc20;
69: iVar10 = *(int *)(param_1 + 0x1e0);
70: uVar14 = uStack88;
71: iVar7 = iStack80;
72: }
73: uVar11 = iVar7 - 1;
74: uVar12 = (ulong)uVar11;
75: if ((uVar14 >> (uVar12 & 0x3f) & 1) != 0) {
76: *puVar6 = *puVar6 | (ushort)(1 << ((byte)uVar2 & 0x1f));
77: }
78: iVar7 = (int)lVar13;
79: lVar13 = lVar13 + 1;
80: } while (iVar7 < iVar10);
81: puVar8 = *(undefined8 **)(param_1 + 0x28);
82: iVar7 = *(int *)(param_1 + 0x170);
83: }
84: *puVar8 = uVar9;
85: puVar8[1] = uVar5;
86: *(ulong *)(lVar3 + 0x18) = uVar14;
87: *(uint *)(lVar3 + 0x20) = uVar11;
88: uVar9 = 1;
89: if (iVar7 != 0) {
90: *(int *)(lVar3 + 0x3c) = *(int *)(lVar3 + 0x3c) + -1;
91: }
92: LAB_0013bbf5:
93: if (lVar4 == *(long *)(in_FS_OFFSET + 0x28)) {
94: return uVar9;
95: }
96: /* WARNING: Subroutine does not return */
97: __stack_chk_fail();
98: }
99: 
