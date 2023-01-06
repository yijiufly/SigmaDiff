1: 
2: int FUN_0014cee0(code **param_1,byte *param_2)
3: 
4: {
5: byte bVar1;
6: code *pcVar2;
7: long lVar3;
8: byte **ppbVar4;
9: code **ppcVar5;
10: int iVar6;
11: byte *pbVar7;
12: int iVar8;
13: long lVar9;
14: ulong uVar10;
15: long lVar11;
16: long lVar12;
17: 
18: pcVar2 = param_1[0x4a];
19: lVar9 = *(long *)(pcVar2 + 0x20);
20: iVar8 = *(int *)(pcVar2 + 0x28);
21: joined_r0x0014cf02:
22: if (lVar9 < 0x8000) {
23: do {
24: iVar8 = iVar8 + -1;
25: *(int *)(pcVar2 + 0x28) = iVar8;
26: if (iVar8 < 0) {
27: uVar10 = 0;
28: if (*(int *)((long)param_1 + 0x21c) == 0) {
29: ppbVar4 = (byte **)param_1[5];
30: pbVar7 = ppbVar4[1];
31: if (pbVar7 == (byte *)0x0) {
32: iVar8 = (*(code *)ppbVar4[3])(param_1);
33: if (iVar8 == 0) {
34: ppcVar5 = (code **)*param_1;
35: *(undefined4 *)(ppcVar5 + 5) = 0x18;
36: (**ppcVar5)(param_1);
37: }
38: pbVar7 = ppbVar4[1];
39: }
40: ppbVar4[1] = pbVar7 + -1;
41: pbVar7 = *ppbVar4;
42: *ppbVar4 = pbVar7 + 1;
43: bVar1 = *pbVar7;
44: if (bVar1 == 0xff) {
45: do {
46: ppbVar4 = (byte **)param_1[5];
47: pbVar7 = ppbVar4[1];
48: if (pbVar7 == (byte *)0x0) {
49: iVar8 = (*(code *)ppbVar4[3])(param_1);
50: if (iVar8 == 0) {
51: ppcVar5 = (code **)*param_1;
52: *(undefined4 *)(ppcVar5 + 5) = 0x18;
53: (**ppcVar5)(param_1);
54: }
55: pbVar7 = ppbVar4[1];
56: }
57: ppbVar4[1] = pbVar7 + -1;
58: pbVar7 = *ppbVar4;
59: *ppbVar4 = pbVar7 + 1;
60: bVar1 = *pbVar7;
61: } while (bVar1 == 0xff);
62: if (bVar1 == 0) {
63: iVar8 = *(int *)(pcVar2 + 0x28);
64: uVar10 = 0xff;
65: }
66: else {
67: *(uint *)((long)param_1 + 0x21c) = (uint)bVar1;
68: iVar8 = *(int *)(pcVar2 + 0x28);
69: uVar10 = 0;
70: }
71: }
72: else {
73: uVar10 = (ulong)bVar1;
74: iVar8 = *(int *)(pcVar2 + 0x28);
75: }
76: }
77: *(ulong *)(pcVar2 + 0x18) = *(long *)(pcVar2 + 0x18) << 8 | uVar10;
78: iVar6 = iVar8 + 8;
79: *(int *)(pcVar2 + 0x28) = iVar6;
80: if (-1 < iVar6) goto code_r0x0014cf59;
81: iVar8 = iVar8 + 9;
82: *(int *)(pcVar2 + 0x28) = iVar8;
83: if (iVar8 == 0) {
84: *(undefined8 *)(pcVar2 + 0x20) = 0x10000;
85: lVar9 = 0x10000;
86: break;
87: }
88: lVar9 = *(long *)(pcVar2 + 0x20);
89: }
90: lVar9 = lVar9 * 2;
91: *(long *)(pcVar2 + 0x20) = lVar9;
92: if (0x7fff < lVar9) break;
93: } while( true );
94: }
95: bVar1 = *param_2;
96: lVar3 = *(long *)(&DAT_0018f280 + (ulong)(bVar1 & 0x7f) * 8);
97: lVar11 = lVar3 >> 0x10;
98: lVar9 = lVar9 - lVar11;
99: *(long *)(pcVar2 + 0x20) = lVar9;
100: lVar12 = lVar9 << ((byte)iVar8 & 0x3f);
101: if (*(long *)(pcVar2 + 0x18) < lVar12) {
102: if (0x7fff < lVar9) goto LAB_0014cfcf;
103: if (lVar9 < lVar11) goto LAB_0014d0db;
104: }
105: else {
106: *(long *)(pcVar2 + 0x20) = lVar11;
107: *(long *)(pcVar2 + 0x18) = *(long *)(pcVar2 + 0x18) - lVar12;
108: if (lVar11 <= lVar9) {
109: LAB_0014d0db:
110: *param_2 = (byte)lVar3 ^ bVar1 & 0x80;
111: return (int)(bVar1 - 0x80 & 0xff) >> 7;
112: }
113: }
114: *param_2 = bVar1 & 0x80 ^ (byte)((ulong)lVar3 >> 8);
115: LAB_0014cfcf:
116: return (int)(uint)bVar1 >> 7;
117: code_r0x0014cf59:
118: lVar9 = *(long *)(pcVar2 + 0x20) * 2;
119: *(long *)(pcVar2 + 0x20) = lVar9;
120: iVar8 = iVar6;
121: goto joined_r0x0014cf02;
122: }
123: 
