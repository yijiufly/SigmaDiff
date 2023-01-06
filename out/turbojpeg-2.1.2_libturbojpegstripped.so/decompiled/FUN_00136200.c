1: 
2: undefined8 FUN_00136200(code **param_1)
3: 
4: {
5: byte bVar1;
6: byte **ppbVar2;
7: code **ppcVar3;
8: code *pcVar4;
9: int iVar5;
10: undefined8 uVar6;
11: byte *pbVar7;
12: byte *pbVar8;
13: long lVar9;
14: byte *pbVar10;
15: uint uVar11;
16: ulong uVar12;
17: ulong uVar13;
18: long in_FS_OFFSET;
19: byte abStack78 [4];
20: char cStack74;
21: long lStack64;
22: 
23: ppbVar2 = (byte **)param_1[5];
24: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
25: pbVar8 = ppbVar2[1];
26: if (pbVar8 == (byte *)0x0) {
27: iVar5 = (*(code *)ppbVar2[3])();
28: if (iVar5 != 0) {
29: pbVar7 = *ppbVar2;
30: pbVar8 = ppbVar2[1];
31: goto LAB_00136245;
32: }
33: LAB_00136300:
34: uVar6 = 0;
35: goto LAB_00136302;
36: }
37: pbVar7 = *ppbVar2;
38: LAB_00136245:
39: pbVar8 = pbVar8 + -1;
40: bVar1 = *pbVar7;
41: if (pbVar8 == (byte *)0x0) {
42: iVar5 = (*(code *)ppbVar2[3])(param_1);
43: if (iVar5 == 0) goto LAB_00136300;
44: pbVar7 = *ppbVar2;
45: pbVar8 = ppbVar2[1];
46: }
47: else {
48: pbVar7 = pbVar7 + 1;
49: }
50: pbVar10 = pbVar7 + 1;
51: pbVar8 = pbVar8 + -1;
52: uVar13 = (ulong)bVar1 * 0x100 + -2 + (ulong)*pbVar7;
53: if ((long)uVar13 < 0xe) {
54: uVar12 = uVar13 & 0xffffffff;
55: if (0 < (long)uVar13) goto LAB_0013632e;
56: iVar5 = *(int *)((long)param_1 + 0x21c);
57: if (iVar5 == 0xe0) {
58: uVar12 = 0;
59: goto LAB_001363f0;
60: }
61: if (iVar5 != 0xee) goto LAB_001362b6;
62: uVar11 = 0;
63: LAB_001363a6:
64: pcVar4 = *param_1;
65: *(undefined4 *)(pcVar4 + 0x28) = 0x4e;
66: *(uint *)(pcVar4 + 0x2c) = uVar11 + (int)uVar13;
67: (**(code **)(pcVar4 + 8))(param_1,1);
68: }
69: else {
70: uVar12 = 0xe;
71: LAB_0013632e:
72: uVar11 = (uint)uVar12;
73: lVar9 = 0;
74: pbVar7 = pbVar10;
75: do {
76: if (pbVar8 == (byte *)0x0) {
77: iVar5 = (*(code *)ppbVar2[3])(param_1);
78: if (iVar5 == 0) goto LAB_00136300;
79: pbVar7 = *ppbVar2;
80: pbVar8 = ppbVar2[1];
81: }
82: pbVar10 = pbVar7 + 1;
83: pbVar8 = pbVar8 + -1;
84: abStack78[lVar9] = *pbVar7;
85: lVar9 = lVar9 + 1;
86: pbVar7 = pbVar10;
87: } while ((uint)lVar9 < uVar11);
88: uVar13 = uVar13 - uVar12;
89: iVar5 = *(int *)((long)param_1 + 0x21c);
90: if (iVar5 == 0xe0) {
91: LAB_001363f0:
92: FUN_00134750(param_1,abStack78,uVar12,uVar13);
93: }
94: else {
95: if (iVar5 == 0xee) {
96: if ((((uVar11 < 0xc) || (abStack78[0] != 0x41)) || (abStack78[1] != 'd')) ||
97: (((abStack78[2] != 'o' || (abStack78[3] != 'b')) || (cStack74 != 'e'))))
98: goto LAB_001363a6;
99: FUN_00136180(param_1,abStack78);
100: }
101: else {
102: LAB_001362b6:
103: ppcVar3 = (code **)*param_1;
104: *(undefined4 *)(ppcVar3 + 5) = 0x44;
105: *(int *)((long)ppcVar3 + 0x2c) = iVar5;
106: (**ppcVar3)(param_1);
107: }
108: }
109: }
110: *ppbVar2 = pbVar10;
111: ppbVar2[1] = pbVar8;
112: if ((long)uVar13 < 1) {
113: uVar6 = 1;
114: }
115: else {
116: (**(code **)(param_1[5] + 0x20))(param_1,uVar13);
117: uVar6 = 1;
118: }
119: LAB_00136302:
120: if (lStack64 != *(long *)(in_FS_OFFSET + 0x28)) {
121: /* WARNING: Subroutine does not return */
122: __stack_chk_fail();
123: }
124: return uVar6;
125: }
126: 
