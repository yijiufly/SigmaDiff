1: 
2: void FUN_0011b0e0(code **param_1)
3: 
4: {
5: uint uVar1;
6: code *pcVar2;
7: ulong uVar3;
8: byte *__dest;
9: byte *__src;
10: byte **ppbVar4;
11: long lVar5;
12: code **ppcVar6;
13: undefined4 uVar7;
14: undefined8 uVar8;
15: undefined8 uVar9;
16: int iVar10;
17: uint uVar11;
18: byte *pbVar12;
19: byte *pbVar13;
20: byte bVar14;
21: uint uVar15;
22: byte *pbVar16;
23: byte *__n;
24: long in_FS_OFFSET;
25: byte abStack584 [520];
26: long lStack64;
27: 
28: pcVar2 = param_1[0x3e];
29: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
30: uVar7 = *(undefined4 *)(pcVar2 + 0x24);
31: uVar3 = *(ulong *)(pcVar2 + 0x18);
32: pbVar16 = *(byte **)((long)param_1[5] + 8);
33: __dest = *(byte **)param_1[5];
34: uVar11 = -*(int *)(pcVar2 + 0x20) + 0x40;
35: uVar8 = *(undefined8 *)(pcVar2 + 0x28);
36: uVar9 = *(undefined8 *)(pcVar2 + 0x30);
37: pbVar12 = __dest;
38: if (pbVar16 < (byte *)0x200) {
39: pbVar12 = abStack584;
40: }
41: if (7 < (int)uVar11) {
42: uVar1 = -*(int *)(pcVar2 + 0x20) + 0x38;
43: uVar15 = uVar1 & 7;
44: do {
45: while( true ) {
46: uVar11 = uVar11 - 8;
47: pbVar12[1] = 0;
48: bVar14 = (byte)(uVar3 >> ((byte)uVar11 & 0x3f));
49: *pbVar12 = bVar14;
50: if (bVar14 == 0xff) break;
51: pbVar12 = pbVar12 + 1;
52: if (uVar11 == uVar15) goto LAB_0011b18f;
53: }
54: pbVar12 = pbVar12 + 2;
55: } while (uVar11 != uVar15);
56: LAB_0011b18f:
57: uVar11 = uVar1 & 7;
58: }
59: if (uVar11 != 0) {
60: pbVar12[1] = 0;
61: bVar14 = (byte)(uVar3 << (8 - (byte)uVar11 & 0x3f)) | (byte)(0xff >> ((byte)uVar11 & 0x1f));
62: *pbVar12 = bVar14;
63: pbVar12 = pbVar12 + (ulong)(bVar14 == 0xff) + 1;
64: }
65: if (pbVar16 < (byte *)0x200) {
66: __src = abStack584;
67: pbVar13 = pbVar12 + -(long)__src;
68: while (pbVar12 = __dest, pbVar13 != (byte *)0x0) {
69: __n = pbVar13;
70: if (pbVar16 <= pbVar13) {
71: __n = pbVar16;
72: }
73: pbVar12 = __dest + (long)__n;
74: memcpy(__dest,__src,(size_t)__n);
75: __src = __src + (long)__n;
76: pbVar16 = pbVar16 + -(long)__n;
77: if (pbVar16 == (byte *)0x0) {
78: ppbVar4 = (byte **)param_1[5];
79: iVar10 = (*(code *)ppbVar4[3])(param_1);
80: if (iVar10 == 0) {
81: ppcVar6 = (code **)*param_1;
82: *(undefined4 *)(ppcVar6 + 5) = 0x18;
83: (**ppcVar6)(param_1);
84: break;
85: }
86: pbVar12 = *ppbVar4;
87: pbVar16 = ppbVar4[1];
88: }
89: pbVar13 = pbVar13 + -(long)__n;
90: __dest = pbVar12;
91: }
92: }
93: else {
94: pbVar16 = pbVar16 + -(long)(pbVar12 + -(long)__dest);
95: }
96: ppbVar4 = (byte **)param_1[5];
97: *ppbVar4 = pbVar12;
98: ppbVar4[1] = pbVar16;
99: *(undefined4 *)(pcVar2 + 0x18) = 0;
100: *(undefined4 *)(pcVar2 + 0x1c) = 0;
101: *(undefined4 *)(pcVar2 + 0x20) = 0x40;
102: *(undefined4 *)(pcVar2 + 0x24) = uVar7;
103: lVar5 = *(long *)(in_FS_OFFSET + 0x28);
104: *(undefined8 *)(pcVar2 + 0x28) = uVar8;
105: *(undefined8 *)(pcVar2 + 0x30) = uVar9;
106: if (lStack64 == lVar5) {
107: return;
108: }
109: /* WARNING: Subroutine does not return */
110: __stack_chk_fail(uVar8);
111: }
112: 
