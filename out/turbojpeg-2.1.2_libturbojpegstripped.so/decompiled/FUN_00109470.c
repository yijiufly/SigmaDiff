1: 
2: undefined8 FUN_00109470(byte **param_1)
3: 
4: {
5: uint uVar1;
6: byte **ppbVar2;
7: byte *__n;
8: byte *pbVar3;
9: undefined8 uVar4;
10: uint uVar5;
11: byte *pbVar6;
12: byte bVar7;
13: uint uVar8;
14: byte *pbVar9;
15: byte *__src;
16: long in_FS_OFFSET;
17: byte abStack568 [520];
18: long lStack48;
19: 
20: __src = abStack568;
21: pbVar6 = abStack568;
22: pbVar3 = param_1[2];
23: lStack48 = *(long *)(in_FS_OFFSET + 0x28);
24: uVar5 = -*(int *)(param_1 + 3) + 0x40;
25: pbVar9 = param_1[1];
26: if ((byte *)0x1ff < pbVar9) {
27: pbVar6 = *param_1;
28: }
29: if (7 < (int)uVar5) {
30: uVar1 = -*(int *)(param_1 + 3) + 0x38;
31: uVar8 = uVar1 & 7;
32: do {
33: while( true ) {
34: uVar5 = uVar5 - 8;
35: pbVar6[1] = 0;
36: bVar7 = (byte)((ulong)pbVar3 >> ((byte)uVar5 & 0x3f));
37: *pbVar6 = bVar7;
38: if (bVar7 == 0xff) break;
39: pbVar6 = pbVar6 + 1;
40: if (uVar8 == uVar5) goto LAB_001094ef;
41: }
42: pbVar6 = pbVar6 + 2;
43: } while (uVar8 != uVar5);
44: LAB_001094ef:
45: uVar5 = uVar1 & 7;
46: }
47: if (uVar5 != 0) {
48: pbVar6[1] = 0;
49: bVar7 = (byte)((long)pbVar3 << (8 - (byte)uVar5 & 0x3f)) | (byte)(0xff >> ((byte)uVar5 & 0x1f));
50: *pbVar6 = bVar7;
51: pbVar6 = pbVar6 + (ulong)(bVar7 == 0xff) + 1;
52: }
53: param_1[2] = (byte *)0x0;
54: *(undefined4 *)(param_1 + 3) = 0x40;
55: if ((byte *)0x1ff < pbVar9) {
56: pbVar3 = *param_1;
57: *param_1 = pbVar6;
58: param_1[1] = param_1[1] + -(long)(pbVar6 + -(long)pbVar3);
59: }
60: else {
61: pbVar6 = pbVar6 + -(long)abStack568;
62: if (pbVar6 != (byte *)0x0) {
63: pbVar3 = param_1[1];
64: pbVar9 = *param_1;
65: do {
66: __n = pbVar3;
67: if (pbVar6 <= pbVar3) {
68: __n = pbVar6;
69: }
70: memcpy(pbVar9,__src,(size_t)__n);
71: __src = __src + (long)__n;
72: pbVar3 = param_1[1] + -(long)__n;
73: pbVar9 = *param_1 + (long)__n;
74: *param_1 = pbVar9;
75: param_1[1] = pbVar3;
76: if (pbVar3 == (byte *)0x0) {
77: ppbVar2 = *(byte ***)(param_1[6] + 0x28);
78: uVar4 = (*(code *)ppbVar2[3])();
79: if ((int)uVar4 == 0) goto LAB_001095ac;
80: pbVar9 = *ppbVar2;
81: pbVar3 = ppbVar2[1];
82: *param_1 = pbVar9;
83: param_1[1] = pbVar3;
84: }
85: pbVar6 = pbVar6 + -(long)__n;
86: } while (pbVar6 != (byte *)0x0);
87: }
88: }
89: uVar4 = 1;
90: LAB_001095ac:
91: if (lStack48 != *(long *)(in_FS_OFFSET + 0x28)) {
92: /* WARNING: Subroutine does not return */
93: __stack_chk_fail();
94: }
95: return uVar4;
96: }
97: 
