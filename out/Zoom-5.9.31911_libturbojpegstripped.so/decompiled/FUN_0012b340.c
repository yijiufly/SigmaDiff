1: 
2: undefined4 FUN_0012b340(long *param_1)
3: 
4: {
5: byte bVar1;
6: undefined4 uVar2;
7: long lVar3;
8: byte **ppbVar4;
9: long lVar5;
10: int iVar6;
11: byte *pbVar7;
12: uint uVar8;
13: ulong uVar9;
14: byte *pbVar10;
15: char *pcVar11;
16: uint uVar12;
17: ulong uVar13;
18: byte *pbVar14;
19: undefined8 *puVar15;
20: undefined8 *puVar16;
21: undefined8 *puStack64;
22: 
23: lVar3 = param_1[0x49];
24: ppbVar4 = (byte **)param_1[5];
25: puStack64 = *(undefined8 **)(lVar3 + 0xf8);
26: pbVar14 = *ppbVar4;
27: pbVar10 = ppbVar4[1];
28: if (puStack64 == (undefined8 *)0x0) {
29: if (pbVar10 == (byte *)0x0) {
30: iVar6 = (*(code *)ppbVar4[3])();
31: if (iVar6 == 0) {
32: return 0;
33: }
34: pbVar14 = *ppbVar4;
35: pbVar10 = ppbVar4[1];
36: }
37: bVar1 = *pbVar14;
38: pbVar7 = pbVar14 + 1;
39: pbVar10 = pbVar10 + -1;
40: if (pbVar10 == (byte *)0x0) {
41: iVar6 = (*(code *)ppbVar4[3])(param_1);
42: if (iVar6 == 0) {
43: return 0;
44: }
45: pbVar7 = *ppbVar4;
46: pbVar10 = ppbVar4[1];
47: }
48: pbVar14 = pbVar7 + 1;
49: pbVar10 = pbVar10 + -1;
50: uVar9 = (ulong)bVar1 * 0x100 + -2 + (ulong)*pbVar7;
51: if ((long)uVar9 < 0) {
52: uVar12 = 0;
53: pcVar11 = (char *)0x0;
54: goto LAB_0012b41d;
55: }
56: if (*(int *)((long)param_1 + 0x21c) == 0xfe) {
57: uVar12 = *(uint *)(lVar3 + 0xb0);
58: }
59: else {
60: uVar12 = *(uint *)(lVar3 + 0xb4 + (long)(*(int *)((long)param_1 + 0x21c) + -0xe0) * 4);
61: }
62: uVar13 = (ulong)uVar12;
63: if ((uint)uVar9 < uVar12) {
64: uVar13 = uVar9 & 0xffffffff;
65: }
66: uVar12 = (uint)uVar13;
67: puStack64 = (undefined8 *)(**(code **)(param_1[1] + 8))(param_1,1,uVar13 + 0x20);
68: *puStack64 = 0;
69: uVar2 = *(undefined4 *)((long)param_1 + 0x21c);
70: puVar15 = puStack64 + 4;
71: *(uint *)((long)puStack64 + 0xc) = (uint)uVar9;
72: uVar8 = 0;
73: *(uint *)(puStack64 + 2) = uVar12;
74: puStack64[3] = puVar15;
75: *(char *)(puStack64 + 1) = (char)uVar2;
76: *(undefined8 **)(lVar3 + 0xf8) = puStack64;
77: *(undefined4 *)(lVar3 + 0x100) = 0;
78: }
79: else {
80: uVar8 = *(uint *)(lVar3 + 0x100);
81: uVar12 = *(uint *)(puStack64 + 2);
82: puVar15 = (undefined8 *)((ulong)uVar8 + puStack64[3]);
83: }
84: joined_r0x0012b38f:
85: if (uVar8 < uVar12) {
86: *ppbVar4 = pbVar14;
87: ppbVar4[1] = pbVar10;
88: *(uint *)(lVar3 + 0x100) = uVar8;
89: if (pbVar10 == (byte *)0x0) {
90: iVar6 = (*(code *)ppbVar4[3])(param_1);
91: if (iVar6 == 0) {
92: return 0;
93: }
94: pbVar14 = *ppbVar4;
95: pbVar10 = ppbVar4[1];
96: }
97: if ((pbVar10 != (byte *)0x0) && (pbVar7 = pbVar14, puVar16 = puVar15, uVar8 < uVar12)) {
98: do {
99: pbVar14 = pbVar7 + 1;
100: uVar8 = uVar8 + 1;
101: puVar15 = (undefined8 *)((long)puVar16 + 1);
102: pbVar10 = pbVar10 + -1;
103: *(byte *)puVar16 = *pbVar7;
104: if (uVar12 <= uVar8) break;
105: pbVar7 = pbVar14;
106: puVar16 = puVar15;
107: } while (pbVar10 != (byte *)0x0);
108: }
109: goto joined_r0x0012b38f;
110: }
111: puVar15 = (undefined8 *)param_1[0x32];
112: if ((undefined8 *)param_1[0x32] == (undefined8 *)0x0) {
113: param_1[0x32] = (long)puStack64;
114: }
115: else {
116: do {
117: puVar16 = puVar15;
118: puVar15 = (undefined8 *)*puVar16;
119: } while (puVar15 != (undefined8 *)0x0);
120: *puVar16 = puStack64;
121: }
122: pcVar11 = (char *)puStack64[3];
123: uVar9 = (ulong)(*(int *)((long)puStack64 + 0xc) - uVar12);
124: LAB_0012b41d:
125: *(undefined8 *)(lVar3 + 0xf8) = 0;
126: iVar6 = *(int *)((long)param_1 + 0x21c);
127: if (iVar6 == 0xe0) {
128: FUN_001297f0(param_1,pcVar11,uVar12,uVar9);
129: }
130: else {
131: if (iVar6 == 0xee) {
132: if ((((uVar12 < 0xc) || (*pcVar11 != 'A')) || (pcVar11[1] != 'd')) ||
133: (((pcVar11[2] != 'o' || (pcVar11[3] != 'b')) || (pcVar11[4] != 'e')))) {
134: lVar3 = *param_1;
135: *(uint *)(lVar3 + 0x2c) = uVar12 + (int)uVar9;
136: *(undefined4 *)(lVar3 + 0x28) = 0x4e;
137: (**(code **)(*param_1 + 8))(param_1,1);
138: }
139: else {
140: entry(param_1);
141: }
142: }
143: else {
144: lVar3 = *param_1;
145: *(int *)(lVar3 + 0x2c) = iVar6;
146: lVar5 = *param_1;
147: *(undefined4 *)(lVar3 + 0x28) = 0x5b;
148: *(uint *)(lVar5 + 0x30) = uVar12 + (int)uVar9;
149: (**(code **)(*param_1 + 8))(param_1,1);
150: }
151: }
152: *ppbVar4 = pbVar14;
153: ppbVar4[1] = pbVar10;
154: if (0 < (long)uVar9) {
155: (**(code **)(param_1[5] + 0x20))(param_1,uVar9);
156: }
157: return 1;
158: }
159: 
