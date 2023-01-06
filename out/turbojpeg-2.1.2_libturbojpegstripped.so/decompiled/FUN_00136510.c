1: 
2: undefined8 FUN_00136510(long *param_1)
3: 
4: {
5: byte bVar1;
6: undefined4 uVar2;
7: long lVar3;
8: byte **ppbVar4;
9: int iVar5;
10: byte *pbVar6;
11: ulong uVar7;
12: undefined8 *puVar8;
13: undefined8 *puVar9;
14: byte *pbVar10;
15: uint uVar11;
16: uint uVar12;
17: char *pcVar13;
18: ulong uVar14;
19: byte *pbVar15;
20: uint uVar16;
21: byte bVar17;
22: undefined8 *puStack64;
23: 
24: bVar17 = 0;
25: lVar3 = param_1[0x49];
26: ppbVar4 = (byte **)param_1[5];
27: puStack64 = *(undefined8 **)(lVar3 + 0xf8);
28: pbVar15 = *ppbVar4;
29: pbVar10 = ppbVar4[1];
30: if (puStack64 == (undefined8 *)0x0) {
31: if (pbVar10 == (byte *)0x0) {
32: iVar5 = (*(code *)ppbVar4[3])();
33: if (iVar5 == 0) {
34: return 0;
35: }
36: pbVar15 = *ppbVar4;
37: pbVar10 = ppbVar4[1];
38: }
39: pbVar10 = pbVar10 + -1;
40: bVar1 = *pbVar15;
41: pbVar6 = pbVar15 + 1;
42: if (pbVar10 == (byte *)0x0) {
43: iVar5 = (*(code *)ppbVar4[3])(param_1);
44: if (iVar5 == 0) {
45: return 0;
46: }
47: pbVar6 = *ppbVar4;
48: pbVar10 = ppbVar4[1];
49: }
50: pbVar15 = pbVar6 + 1;
51: pbVar10 = pbVar10 + -1;
52: uVar7 = (ulong)bVar1 * 0x100 + -2 + (ulong)*pbVar6;
53: iVar5 = *(int *)((long)param_1 + 0x21c);
54: if ((long)uVar7 < 0) {
55: uVar16 = 0;
56: pcVar13 = (char *)0x0;
57: goto LAB_00136618;
58: }
59: if (iVar5 == 0xfe) {
60: uVar16 = *(uint *)(lVar3 + 0xb0);
61: }
62: else {
63: uVar16 = *(uint *)(lVar3 + 0xb4 + (long)(iVar5 + -0xe0) * 4);
64: }
65: uVar14 = (ulong)uVar16;
66: if ((uint)uVar7 <= uVar16) {
67: uVar14 = uVar7 & 0xffffffff;
68: }
69: uVar16 = (uint)uVar14;
70: puStack64 = (undefined8 *)(**(code **)(param_1[1] + 8))(param_1,1,uVar14 + 0x20);
71: *puStack64 = 0;
72: uVar2 = *(undefined4 *)((long)param_1 + 0x21c);
73: puVar8 = puStack64 + 4;
74: *(uint *)((long)puStack64 + 0xc) = (uint)uVar7;
75: *(uint *)(puStack64 + 2) = uVar16;
76: uVar7 = 0;
77: puStack64[3] = puVar8;
78: *(char *)(puStack64 + 1) = (char)uVar2;
79: *(undefined8 **)(lVar3 + 0xf8) = puStack64;
80: *(undefined4 *)(lVar3 + 0x100) = 0;
81: }
82: else {
83: uVar7 = (ulong)*(uint *)(lVar3 + 0x100);
84: uVar16 = *(uint *)(puStack64 + 2);
85: puVar8 = (undefined8 *)(uVar7 + puStack64[3]);
86: }
87: uVar11 = (uint)uVar7;
88: while (uVar11 < uVar16) {
89: *ppbVar4 = pbVar15;
90: ppbVar4[1] = pbVar10;
91: uVar12 = (uint)uVar7;
92: *(uint *)(lVar3 + 0x100) = uVar12;
93: if (pbVar10 == (byte *)0x0) {
94: iVar5 = (*(code *)ppbVar4[3])(param_1);
95: if (iVar5 == 0) {
96: return 0;
97: }
98: pbVar15 = *ppbVar4;
99: pbVar10 = ppbVar4[1];
100: }
101: while ((uVar11 = (uint)uVar7, uVar12 < uVar16 && (pbVar10 != (byte *)0x0))) {
102: uVar12 = uVar11 + 1;
103: uVar7 = (ulong)uVar12;
104: *(byte *)puVar8 = *pbVar15;
105: pbVar10 = pbVar10 + -1;
106: pbVar15 = pbVar15 + (ulong)bVar17 * -2 + 1;
107: puVar8 = (undefined8 *)((long)puVar8 + (ulong)bVar17 * -2 + 1);
108: }
109: }
110: puVar8 = (undefined8 *)param_1[0x32];
111: if ((undefined8 *)param_1[0x32] == (undefined8 *)0x0) {
112: param_1[0x32] = (long)puStack64;
113: }
114: else {
115: do {
116: puVar9 = puVar8;
117: puVar8 = (undefined8 *)*puVar9;
118: } while (puVar8 != (undefined8 *)0x0);
119: *puVar9 = puStack64;
120: }
121: pcVar13 = (char *)puStack64[3];
122: uVar7 = (ulong)(*(int *)((long)puStack64 + 0xc) - uVar16);
123: iVar5 = *(int *)((long)param_1 + 0x21c);
124: LAB_00136618:
125: *(undefined8 *)(lVar3 + 0xf8) = 0;
126: if (iVar5 == 0xe0) {
127: FUN_00134750(param_1,pcVar13,uVar16,uVar7);
128: }
129: else {
130: if (iVar5 == 0xee) {
131: if ((((uVar16 < 0xc) || (*pcVar13 != 'A')) || (pcVar13[1] != 'd')) ||
132: (((pcVar13[2] != 'o' || (pcVar13[3] != 'b')) || (pcVar13[4] != 'e')))) {
133: lVar3 = *param_1;
134: *(undefined4 *)(lVar3 + 0x28) = 0x4e;
135: *(uint *)(lVar3 + 0x2c) = uVar16 + (int)uVar7;
136: (**(code **)(lVar3 + 8))(param_1,1);
137: }
138: else {
139: FUN_00136180(param_1);
140: }
141: }
142: else {
143: lVar3 = *param_1;
144: *(undefined4 *)(lVar3 + 0x28) = 0x5b;
145: *(int *)(lVar3 + 0x2c) = iVar5;
146: *(uint *)(lVar3 + 0x30) = uVar16 + (int)uVar7;
147: (**(code **)(lVar3 + 8))(param_1,1);
148: }
149: }
150: *ppbVar4 = pbVar15;
151: ppbVar4[1] = pbVar10;
152: if (0 < (long)uVar7) {
153: (**(code **)(param_1[5] + 0x20))(param_1,uVar7);
154: return 1;
155: }
156: return 1;
157: }
158: 
