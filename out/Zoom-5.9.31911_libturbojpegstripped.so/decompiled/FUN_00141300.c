1: 
2: undefined8 FUN_00141300(long *param_1,long *param_2)
3: 
4: {
5: long lVar1;
6: int iVar2;
7: long lVar3;
8: long lVar4;
9: int iVar5;
10: uint uVar6;
11: int iVar7;
12: int iVar8;
13: long lVar9;
14: uint uVar10;
15: 
16: lVar3 = param_1[0x4a];
17: if (*(int *)(param_1 + 0x2e) != 0) {
18: iVar8 = *(int *)(lVar3 + 0x4c);
19: if (iVar8 == 0) {
20: FUN_00140730();
21: iVar8 = *(int *)(lVar3 + 0x4c);
22: }
23: *(int *)(lVar3 + 0x4c) = iVar8 + -1;
24: }
25: if (*(int *)(lVar3 + 0x28) != -1) {
26: lVar4 = *param_2;
27: iVar8 = *(int *)((long)param_1 + 0x20c);
28: iVar2 = *(int *)(param_1[0x37] + 0x18);
29: if (iVar8 <= *(int *)(param_1 + 0x42)) {
30: lVar1 = lVar3 + (long)iVar2 * 8;
31: do {
32: lVar9 = (long)(iVar8 * 3 + -3) + *(long *)(lVar1 + 0xd0);
33: iVar5 = FUN_00140970(param_1,lVar9);
34: if (iVar5 != 0) {
35: return 1;
36: }
37: while (iVar5 = FUN_00140970(param_1,lVar9 + 1), iVar5 == 0) {
38: lVar9 = lVar9 + 3;
39: iVar8 = iVar8 + 1;
40: if (*(int *)(param_1 + 0x42) < iVar8) goto LAB_001414f8;
41: }
42: iVar5 = FUN_00140970(param_1,lVar3 + 0x150);
43: uVar6 = FUN_00140970(param_1,lVar9 + 2);
44: uVar10 = uVar6;
45: if ((uVar6 != 0) && (iVar7 = FUN_00140970(param_1,lVar9 + 2), iVar7 != 0)) {
46: uVar6 = uVar6 * 2;
47: lVar9 = 0xbd;
48: if ((int)(uint)*(byte *)((long)param_1 + (long)iVar2 + 0x160) < iVar8) {
49: lVar9 = 0xd9;
50: }
51: lVar9 = lVar9 + *(long *)(lVar1 + 0xd0);
52: while (iVar7 = FUN_00140970(param_1,lVar9), uVar10 = uVar6, iVar7 != 0) {
53: uVar6 = uVar6 * 2;
54: if (uVar6 == 0x8000) {
55: LAB_001414f8:
56: lVar4 = *param_1;
57: *(undefined4 *)(lVar4 + 0x28) = 0x7e;
58: (**(code **)(lVar4 + 8))(param_1,0xffffffff);
59: *(undefined4 *)(lVar3 + 0x28) = 0xffffffff;
60: return 1;
61: }
62: lVar9 = lVar9 + 1;
63: }
64: }
65: while (uVar10 = (int)uVar10 >> 1, uVar10 != 0) {
66: iVar7 = FUN_00140970(param_1);
67: if (iVar7 != 0) {
68: uVar6 = uVar6 | uVar10;
69: }
70: }
71: iVar7 = -(uVar6 + 1);
72: if (iVar5 == 0) {
73: iVar7 = uVar6 + 1;
74: }
75: lVar9 = (long)iVar8;
76: iVar8 = iVar8 + 1;
77: iVar5 = *(int *)(param_1 + 0x42);
78: *(short *)(lVar4 + (long)*(int *)(&DAT_0018b460 + lVar9 * 4) * 2) =
79: (short)(iVar7 << ((byte)*(undefined4 *)(param_1 + 0x43) & 0x1f));
80: } while (iVar8 <= iVar5);
81: }
82: }
83: return 1;
84: }
85: 
