1: 
2: int FUN_00140970(code **param_1,byte *param_2)
3: 
4: {
5: byte bVar1;
6: code *pcVar2;
7: long lVar3;
8: byte **ppbVar4;
9: code **ppcVar5;
10: ulong uVar6;
11: byte *pbVar7;
12: int iVar8;
13: long lVar9;
14: int iVar10;
15: long lVar11;
16: uint uVar12;
17: long lVar13;
18: 
19: pcVar2 = param_1[0x4a];
20: lVar9 = *(long *)(pcVar2 + 0x20);
21: iVar8 = *(int *)(pcVar2 + 0x28);
22: joined_r0x00140995:
23: if (lVar9 < 0x8000) {
24: do {
25: iVar8 = iVar8 + -1;
26: *(int *)(pcVar2 + 0x28) = iVar8;
27: if (iVar8 < 0) {
28: uVar6 = 0;
29: if (*(int *)((long)param_1 + 0x21c) == 0) {
30: ppbVar4 = (byte **)param_1[5];
31: pbVar7 = ppbVar4[1];
32: if (pbVar7 == (byte *)0x0) {
33: iVar8 = (*(code *)ppbVar4[3])(param_1);
34: if (iVar8 == 0) {
35: ppcVar5 = (code **)*param_1;
36: *(undefined4 *)(ppcVar5 + 5) = 0x18;
37: (**ppcVar5)(param_1);
38: pbVar7 = ppbVar4[1];
39: }
40: else {
41: pbVar7 = ppbVar4[1];
42: }
43: }
44: ppbVar4[1] = pbVar7 + -1;
45: pbVar7 = *ppbVar4;
46: *ppbVar4 = pbVar7 + 1;
47: bVar1 = *pbVar7;
48: uVar6 = (ulong)bVar1;
49: if (bVar1 == 0xff) {
50: do {
51: ppbVar4 = (byte **)param_1[5];
52: pbVar7 = ppbVar4[1];
53: if (pbVar7 == (byte *)0x0) {
54: iVar8 = (*(code *)ppbVar4[3])(param_1);
55: if (iVar8 == 0) {
56: ppcVar5 = (code **)*param_1;
57: *(undefined4 *)(ppcVar5 + 5) = 0x18;
58: (**ppcVar5)(param_1);
59: }
60: pbVar7 = ppbVar4[1];
61: }
62: ppbVar4[1] = pbVar7 + -1;
63: pbVar7 = *ppbVar4;
64: *ppbVar4 = pbVar7 + 1;
65: bVar1 = *pbVar7;
66: } while (bVar1 == 0xff);
67: if (bVar1 == 0) {
68: iVar8 = *(int *)(pcVar2 + 0x28);
69: uVar6 = 0xff;
70: }
71: else {
72: *(uint *)((long)param_1 + 0x21c) = (uint)bVar1;
73: iVar8 = *(int *)(pcVar2 + 0x28);
74: uVar6 = 0;
75: }
76: }
77: else {
78: iVar8 = *(int *)(pcVar2 + 0x28);
79: }
80: }
81: iVar10 = iVar8 + 8;
82: *(int *)(pcVar2 + 0x28) = iVar10;
83: uVar6 = *(long *)(pcVar2 + 0x18) << 8 | uVar6;
84: *(ulong *)(pcVar2 + 0x18) = uVar6;
85: if (-1 < iVar10) goto code_r0x001409e9;
86: iVar8 = iVar8 + 9;
87: *(int *)(pcVar2 + 0x28) = iVar8;
88: if (iVar8 == 0) {
89: *(undefined8 *)(pcVar2 + 0x20) = 0x10000;
90: lVar9 = 0x10000;
91: goto LAB_00140a04;
92: }
93: lVar9 = *(long *)(pcVar2 + 0x20);
94: }
95: lVar9 = lVar9 * 2;
96: *(long *)(pcVar2 + 0x20) = lVar9;
97: if (0x7fff < lVar9) break;
98: } while( true );
99: }
100: uVar6 = *(ulong *)(pcVar2 + 0x18);
101: LAB_00140a04:
102: bVar1 = *param_2;
103: uVar12 = (uint)bVar1;
104: lVar3 = *(long *)(&DAT_0018b5e0 + (ulong)(bVar1 & 0x7f) * 8);
105: lVar11 = lVar3 >> 0x10;
106: lVar9 = lVar9 - lVar11;
107: *(long *)(pcVar2 + 0x20) = lVar9;
108: lVar13 = lVar9 << ((byte)iVar8 & 0x3f);
109: if ((long)uVar6 < lVar13) {
110: if (0x7fff < lVar9) goto LAB_00140a61;
111: if (lVar9 < lVar11) goto LAB_00140b36;
112: }
113: else {
114: *(long *)(pcVar2 + 0x20) = lVar11;
115: *(ulong *)(pcVar2 + 0x18) = uVar6 - lVar13;
116: if (lVar11 <= lVar9) {
117: LAB_00140b36:
118: uVar12 = bVar1 - 0x80 & 0xff;
119: *param_2 = bVar1 & 0x80 ^ (byte)lVar3;
120: goto LAB_00140a61;
121: }
122: }
123: *param_2 = bVar1 & 0x80 ^ (byte)((ulong)lVar3 >> 8);
124: LAB_00140a61:
125: return (int)uVar12 >> 7;
126: code_r0x001409e9:
127: lVar9 = *(long *)(pcVar2 + 0x20) * 2;
128: *(long *)(pcVar2 + 0x20) = lVar9;
129: iVar8 = iVar10;
130: goto joined_r0x00140995;
131: }
132: 
