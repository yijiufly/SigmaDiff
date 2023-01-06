1: 
2: undefined8 FUN_0014de30(code **param_1,long param_2)
3: 
4: {
5: code cVar1;
6: byte bVar2;
7: undefined4 uVar3;
8: code *pcVar4;
9: code *pcVar5;
10: long lVar6;
11: ushort *puVar7;
12: byte **ppbVar8;
13: code **ppcVar9;
14: long lVar10;
15: byte *pbVar11;
16: int iVar12;
17: long lVar13;
18: int iVar14;
19: ulong uVar15;
20: long lVar16;
21: long lVar17;
22: ushort uStack60;
23: 
24: pcVar4 = param_1[0x4a];
25: if (*(int *)(param_1 + 0x2e) != 0) {
26: iVar12 = *(int *)(pcVar4 + 0x4c);
27: if (iVar12 == 0) {
28: FUN_0014c910();
29: iVar12 = *(int *)(pcVar4 + 0x4c);
30: }
31: *(int *)(pcVar4 + 0x4c) = iVar12 + -1;
32: }
33: uVar3 = *(undefined4 *)(param_1 + 0x43);
34: if (*(int *)(param_1 + 0x3c) < 1) {
35: return 1;
36: }
37: lVar13 = 1;
38: LAB_0014de98:
39: do {
40: pcVar5 = param_1[0x4a];
41: lVar10 = *(long *)(pcVar5 + 0x20);
42: iVar12 = *(int *)(pcVar5 + 0x28);
43: joined_r0x0014deae:
44: if (lVar10 < 0x8000) {
45: do {
46: iVar12 = iVar12 + -1;
47: *(int *)(pcVar5 + 0x28) = iVar12;
48: if (iVar12 < 0) {
49: uVar15 = 0;
50: if (*(int *)((long)param_1 + 0x21c) == 0) {
51: ppbVar8 = (byte **)param_1[5];
52: pbVar11 = ppbVar8[1];
53: if (pbVar11 == (byte *)0x0) {
54: iVar12 = (*(code *)ppbVar8[3])();
55: if (iVar12 == 0) {
56: ppcVar9 = (code **)*param_1;
57: *(undefined4 *)(ppcVar9 + 5) = 0x18;
58: (**ppcVar9)();
59: }
60: pbVar11 = ppbVar8[1];
61: }
62: ppbVar8[1] = pbVar11 + -1;
63: pbVar11 = *ppbVar8;
64: *ppbVar8 = pbVar11 + 1;
65: bVar2 = *pbVar11;
66: if (bVar2 == 0xff) {
67: do {
68: ppbVar8 = (byte **)param_1[5];
69: pbVar11 = ppbVar8[1];
70: if (pbVar11 == (byte *)0x0) {
71: iVar12 = (*(code *)ppbVar8[3])();
72: if (iVar12 == 0) {
73: ppcVar9 = (code **)*param_1;
74: *(undefined4 *)(ppcVar9 + 5) = 0x18;
75: (**ppcVar9)();
76: }
77: pbVar11 = ppbVar8[1];
78: }
79: ppbVar8[1] = pbVar11 + -1;
80: pbVar11 = *ppbVar8;
81: *ppbVar8 = pbVar11 + 1;
82: bVar2 = *pbVar11;
83: } while (bVar2 == 0xff);
84: if (bVar2 == 0) {
85: iVar12 = *(int *)(pcVar5 + 0x28);
86: uVar15 = 0xff;
87: }
88: else {
89: *(uint *)((long)param_1 + 0x21c) = (uint)bVar2;
90: iVar12 = *(int *)(pcVar5 + 0x28);
91: uVar15 = 0;
92: }
93: }
94: else {
95: uVar15 = (ulong)bVar2;
96: iVar12 = *(int *)(pcVar5 + 0x28);
97: }
98: }
99: iVar14 = iVar12 + 8;
100: *(ulong *)(pcVar5 + 0x18) = *(long *)(pcVar5 + 0x18) << 8 | uVar15;
101: *(int *)(pcVar5 + 0x28) = iVar14;
102: if (-1 < iVar14) goto code_r0x0014df02;
103: iVar12 = iVar12 + 9;
104: *(int *)(pcVar5 + 0x28) = iVar12;
105: if (iVar12 == 0) {
106: *(undefined8 *)(pcVar5 + 0x20) = 0x10000;
107: lVar10 = 0x10000;
108: break;
109: }
110: lVar10 = *(long *)(pcVar5 + 0x20);
111: }
112: lVar10 = lVar10 * 2;
113: *(long *)(pcVar5 + 0x20) = lVar10;
114: if (0x7fff < lVar10) break;
115: } while( true );
116: }
117: cVar1 = pcVar4[0x150];
118: lVar6 = *(long *)(&DAT_0018f280 + (ulong)((byte)cVar1 & 0x7f) * 8);
119: lVar16 = lVar6 >> 0x10;
120: lVar10 = lVar10 - lVar16;
121: *(long *)(pcVar5 + 0x20) = lVar10;
122: lVar17 = lVar10 << ((byte)iVar12 & 0x3f);
123: iVar12 = (int)lVar13;
124: if (lVar17 <= *(long *)(pcVar5 + 0x18)) {
125: *(long *)(pcVar5 + 0x20) = lVar16;
126: *(long *)(pcVar5 + 0x18) = *(long *)(pcVar5 + 0x18) - lVar17;
127: joined_r0x0014e0c4:
128: if (lVar16 <= lVar10) {
129: pcVar4[0x150] = (code)((byte)((ulong)lVar6 >> 8) ^ (byte)cVar1 & 0x80);
130: goto LAB_0014df86;
131: }
132: pcVar4[0x150] = (code)((byte)lVar6 ^ (byte)cVar1 & 0x80);
133: if ((int)((byte)cVar1 - 0x80 & 0xff) >> 7 == 0) goto LAB_0014e0e6;
134: LAB_0014df91:
135: puVar7 = *(ushort **)(param_2 + -8 + lVar13 * 8);
136: uStack60 = (ushort)(1 << ((byte)uVar3 & 0x1f));
137: *puVar7 = *puVar7 | uStack60;
138: lVar13 = lVar13 + 1;
139: if (*(int *)(param_1 + 0x3c) <= iVar12) {
140: return 1;
141: }
142: goto LAB_0014de98;
143: }
144: if (lVar10 < 0x8000) goto joined_r0x0014e0c4;
145: LAB_0014df86:
146: if ((int)(uint)(byte)cVar1 >> 7 != 0) goto LAB_0014df91;
147: LAB_0014e0e6:
148: lVar13 = lVar13 + 1;
149: if (*(int *)(param_1 + 0x3c) == iVar12 || *(int *)(param_1 + 0x3c) < iVar12) {
150: return 1;
151: }
152: } while( true );
153: code_r0x0014df02:
154: lVar10 = *(long *)(pcVar5 + 0x20) * 2;
155: *(long *)(pcVar5 + 0x20) = lVar10;
156: iVar12 = iVar14;
157: goto joined_r0x0014deae;
158: }
159: 
