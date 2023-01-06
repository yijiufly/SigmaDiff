1: 
2: void FUN_00144c40(long param_1,long param_2,long param_3,long *param_4,uint param_5)
3: 
4: {
5: undefined uVar1;
6: short sVar2;
7: short sVar3;
8: short sVar4;
9: short sVar5;
10: long lVar6;
11: long lVar7;
12: long lVar8;
13: int iVar9;
14: long lVar10;
15: long lVar11;
16: uint uVar12;
17: undefined *puVar13;
18: long in_FS_OFFSET;
19: int aiStack120 [8];
20: int aiStack88 [10];
21: long lStack48;
22: 
23: uVar12 = 8;
24: lVar6 = *(long *)(param_1 + 0x1a8);
25: lVar8 = *(long *)(param_2 + 0x58);
26: lStack48 = *(long *)(in_FS_OFFSET + 0x28);
27: lVar7 = 0;
28: do {
29: if (((uVar12 & 0xfffffffb) != 2) && (uVar12 != 4)) {
30: sVar2 = *(short *)(param_3 + 0x10 + lVar7);
31: sVar3 = *(short *)(param_3 + 0x30 + lVar7);
32: sVar4 = *(short *)(param_3 + 0x70 + lVar7);
33: sVar5 = *(short *)(param_3 + 0x50 + lVar7);
34: lVar10 = (long)((int)*(short *)(param_3 + lVar7) * (int)*(short *)(lVar8 + lVar7));
35: if ((sVar2 == 0) && (((sVar3 == 0 && (sVar5 == 0)) && (sVar4 == 0)))) {
36: iVar9 = (int)(lVar10 << 2);
37: *(int *)((long)aiStack120 + lVar7 * 2) = iVar9;
38: *(int *)((long)aiStack88 + lVar7 * 2) = iVar9;
39: }
40: else {
41: lVar10 = lVar10 * 0x8000;
42: lVar11 = (long)((int)*(short *)(lVar8 + 0x10 + lVar7) * (int)sVar2) * 0x73fc +
43: (long)((int)*(short *)(lVar8 + 0x30 + lVar7) * (int)sVar3) * -0x28ba +
44: (long)((int)*(short *)(lVar8 + 0x50 + lVar7) * (int)sVar5) * 0x1b37 +
45: (long)((int)*(short *)(lVar8 + 0x70 + lVar7) * (int)sVar4) * -0x1712;
46: *(int *)((long)aiStack120 + lVar7 * 2) = (int)(lVar10 + 0x1000 + lVar11 >> 0xd);
47: *(int *)((long)aiStack88 + lVar7 * 2) = (int)((lVar10 - lVar11) + 0x1000 >> 0xd);
48: }
49: }
50: lVar7 = lVar7 + 2;
51: uVar12 = uVar12 - 1;
52: } while (lVar7 != 0x10);
53: puVar13 = (undefined *)(*param_4 + (ulong)param_5);
54: if (((aiStack120[1] == 0) && (aiStack120[3] == 0)) &&
55: ((aiStack120[5] == 0 && (aiStack120[7] == 0)))) {
56: uVar1 = *(undefined *)(lVar6 + 0x80 + (ulong)((uint)((long)aiStack120[0] + 0x10 >> 5) & 0x3ff));
57: *puVar13 = uVar1;
58: puVar13[1] = uVar1;
59: }
60: else {
61: lVar8 = (long)aiStack120[5] * 0x1b37 + (long)aiStack120[7] * -0x1712 +
62: (long)aiStack120[3] * -0x28ba + (long)aiStack120[1] * 0x73fc;
63: *puVar13 = *(undefined *)
64: (lVar6 + 0x80 +
65: (ulong)((uint)(lVar8 + 0x80000 + (long)aiStack120[0] * 0x8000 >> 0x14) & 0x3ff));
66: puVar13[1] = *(undefined *)
67: (lVar6 + 0x80 +
68: (ulong)(((int)((long)aiStack120[0] * 0x8000) - (int)lVar8) * 4 + 0x200000U >> 0x16
69: ));
70: }
71: puVar13 = (undefined *)((ulong)param_5 + param_4[1]);
72: if (((aiStack88[1] == 0) && (aiStack88[3] == 0)) && ((aiStack88[5] == 0 && (aiStack88[7] == 0))))
73: {
74: uVar1 = *(undefined *)(lVar6 + 0x80 + (ulong)((uint)((long)aiStack88[0] + 0x10 >> 5) & 0x3ff));
75: *puVar13 = uVar1;
76: puVar13[1] = uVar1;
77: }
78: else {
79: lVar8 = (long)aiStack88[7] * -0x1712 + (long)aiStack88[5] * 0x1b37 +
80: (long)aiStack88[3] * -0x28ba + (long)aiStack88[1] * 0x73fc;
81: *puVar13 = *(undefined *)
82: (lVar6 + 0x80 +
83: (ulong)((uint)((long)aiStack88[0] * 0x8000 + 0x80000 + lVar8 >> 0x14) & 0x3ff));
84: puVar13[1] = *(undefined *)
85: (lVar6 + 0x80 +
86: (ulong)(((int)((long)aiStack88[0] * 0x8000) - (int)lVar8) * 4 + 0x200000U >> 0x16)
87: );
88: }
89: if (lStack48 != *(long *)(in_FS_OFFSET + 0x28)) {
90: /* WARNING: Subroutine does not return */
91: __stack_chk_fail();
92: }
93: return;
94: }
95: 
