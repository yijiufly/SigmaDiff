1: 
2: void FUN_00125a60(long param_1,uint param_2)
3: 
4: {
5: int *piVar1;
6: int iVar2;
7: long lVar3;
8: uint uVar4;
9: uint uVar5;
10: undefined **ppuVar6;
11: long lVar7;
12: long lVar8;
13: long in_FS_OFFSET;
14: undefined *puStack80;
15: undefined uStack65;
16: long lStack64;
17: 
18: uVar5 = *(uint *)(param_1 + 0x19c);
19: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
20: lVar3 = *(long *)(param_1 + 0x268);
21: iVar2 = *(int *)(*(long *)(param_1 + 0x220) + 0x7c);
22: if ((iVar2 == 0) || (uVar5 != 2)) {
23: uStack65 = 0;
24: uVar4 = param_2 % uVar5;
25: piVar1 = (int *)(*(long *)(param_1 + 0x228) + 100);
26: *piVar1 = *piVar1 + param_2 / uVar5;
27: puStack80 = &uStack65;
28: *(int *)(param_1 + 0xa8) = *(int *)(param_1 + 0xa8) + (param_2 - uVar4);
29: if (lVar3 == 0) {
30: lVar8 = 0;
31: ppuVar6 = (undefined **)0x0;
32: }
33: else {
34: lVar8 = *(long *)(lVar3 + 8);
35: ppuVar6 = (undefined **)0x0;
36: if (lVar8 != 0) {
37: ppuVar6 = &puStack80;
38: *(code **)(lVar3 + 8) = FUN_00125620;
39: }
40: }
41: lVar3 = *(long *)(param_1 + 0x270);
42: lVar7 = 0;
43: if ((lVar3 != 0) && (lVar7 = *(long *)(lVar3 + 8), lVar7 != 0)) {
44: *(code **)(lVar3 + 8) = FUN_00125630;
45: }
46: if ((uVar5 == 2) && (iVar2 != 0)) {
47: ppuVar6 = (undefined **)(*(long *)(param_1 + 0x260) + 0x40);
48: }
49: if (uVar4 != 0) {
50: uVar5 = 0;
51: do {
52: uVar5 = uVar5 + 1;
53: FUN_00125990(param_1,ppuVar6,1);
54: } while (uVar4 != uVar5);
55: }
56: if (lVar8 != 0) {
57: *(long *)(*(long *)(param_1 + 0x268) + 8) = lVar8;
58: }
59: if (lVar7 != 0) {
60: *(long *)(*(long *)(param_1 + 0x270) + 8) = lVar7;
61: }
62: }
63: else {
64: lVar8 = 0;
65: if ((lVar3 != 0) && (lVar8 = *(long *)(lVar3 + 8), lVar8 != 0)) {
66: *(code **)(lVar3 + 8) = FUN_00125620;
67: }
68: lVar3 = *(long *)(param_1 + 0x270);
69: lVar7 = 0;
70: if ((lVar3 != 0) && (lVar7 = *(long *)(lVar3 + 8), lVar7 != 0)) {
71: *(code **)(lVar3 + 8) = FUN_00125630;
72: }
73: lVar3 = *(long *)(param_1 + 0x260);
74: if (param_2 != 0) {
75: uVar5 = 0;
76: do {
77: uVar5 = uVar5 + 1;
78: FUN_00125990(param_1,lVar3 + 0x40,1);
79: } while (param_2 != uVar5);
80: }
81: if (lVar8 != 0) {
82: *(long *)(*(long *)(param_1 + 0x268) + 8) = lVar8;
83: }
84: if (lVar7 != 0) {
85: *(long *)(*(long *)(param_1 + 0x270) + 8) = lVar7;
86: }
87: }
88: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
89: return;
90: }
91: /* WARNING: Subroutine does not return */
92: __stack_chk_fail();
93: }
94: 
