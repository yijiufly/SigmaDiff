1: 
2: undefined8 FUN_0012b740(code **param_1)
3: 
4: {
5: ulong uVar1;
6: byte bVar2;
7: byte **ppbVar3;
8: code *pcVar4;
9: code **ppcVar5;
10: int iVar6;
11: byte *pbVar7;
12: long lVar8;
13: undefined8 uVar9;
14: byte *pbVar10;
15: byte *pbVar11;
16: uint uVar12;
17: ulong uVar13;
18: long in_FS_OFFSET;
19: byte abStack88 [4];
20: char cStack84;
21: long lStack64;
22: 
23: ppbVar3 = (byte **)param_1[5];
24: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
25: pbVar10 = ppbVar3[1];
26: pbVar7 = *ppbVar3;
27: if (pbVar10 == (byte *)0x0) {
28: iVar6 = (*(code *)ppbVar3[3])();
29: if (iVar6 != 0) {
30: pbVar7 = *ppbVar3;
31: pbVar10 = ppbVar3[1];
32: goto LAB_0012b775;
33: }
34: LAB_0012b8bc:
35: uVar9 = 0;
36: goto LAB_0012b88a;
37: }
38: LAB_0012b775:
39: bVar2 = *pbVar7;
40: pbVar10 = pbVar10 + -1;
41: if (pbVar10 == (byte *)0x0) {
42: iVar6 = (*(code *)ppbVar3[3])(param_1);
43: if (iVar6 == 0) goto LAB_0012b8bc;
44: pbVar7 = *ppbVar3;
45: pbVar10 = ppbVar3[1];
46: }
47: else {
48: pbVar7 = pbVar7 + 1;
49: }
50: pbVar11 = pbVar7 + 1;
51: pbVar10 = pbVar10 + -1;
52: uVar1 = (ulong)bVar2 * 0x100 + -2 + (ulong)*pbVar7;
53: if ((long)uVar1 < 0xe) {
54: uVar13 = uVar1 & 0xffffffff;
55: if (0 < (long)uVar1) goto LAB_0012b7ac;
56: uVar12 = 0;
57: uVar13 = 0;
58: }
59: else {
60: uVar13 = 0xe;
61: LAB_0012b7ac:
62: uVar12 = (uint)uVar13;
63: lVar8 = 0;
64: pbVar7 = pbVar11;
65: do {
66: if (pbVar10 == (byte *)0x0) {
67: iVar6 = (*(code *)ppbVar3[3])(param_1);
68: if (iVar6 == 0) goto LAB_0012b8bc;
69: pbVar7 = *ppbVar3;
70: pbVar10 = ppbVar3[1];
71: }
72: pbVar11 = pbVar7 + 1;
73: pbVar10 = pbVar10 + -1;
74: abStack88[lVar8] = *pbVar7;
75: lVar8 = lVar8 + 1;
76: pbVar7 = pbVar11;
77: } while ((uint)lVar8 < uVar12);
78: }
79: lVar8 = uVar1 - uVar13;
80: iVar6 = *(int *)((long)param_1 + 0x21c);
81: if (iVar6 == 0xe0) {
82: FUN_001297f0(param_1,abStack88,uVar12,lVar8);
83: }
84: else {
85: if (iVar6 == 0xee) {
86: if ((((uVar12 < 0xc) || (abStack88[0] != 0x41)) || (abStack88[1] != 'd')) ||
87: (((abStack88[2] != 'o' || (abStack88[3] != 'b')) || (cStack84 != 'e')))) {
88: pcVar4 = *param_1;
89: *(undefined4 *)(pcVar4 + 0x28) = 0x4e;
90: *(uint *)(pcVar4 + 0x2c) = uVar12 + (int)lVar8;
91: (**(code **)(*param_1 + 8))(param_1,1);
92: }
93: else {
94: entry(param_1,abStack88);
95: }
96: }
97: else {
98: pcVar4 = *param_1;
99: *(int *)(pcVar4 + 0x2c) = iVar6;
100: ppcVar5 = (code **)*param_1;
101: *(undefined4 *)(pcVar4 + 0x28) = 0x44;
102: (**ppcVar5)(param_1);
103: }
104: }
105: *ppbVar3 = pbVar11;
106: ppbVar3[1] = pbVar10;
107: uVar9 = 1;
108: if (0 < lVar8) {
109: (**(code **)(param_1[5] + 0x20))(param_1,lVar8);
110: }
111: LAB_0012b88a:
112: if (lStack64 != *(long *)(in_FS_OFFSET + 0x28)) {
113: /* WARNING: Subroutine does not return */
114: __stack_chk_fail();
115: }
116: return uVar9;
117: }
118: 
