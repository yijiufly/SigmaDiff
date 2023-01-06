1: 
2: undefined8 FUN_001691f0(code **param_1,long param_2)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: long lVar3;
8: code **ppcVar4;
9: byte *pbVar5;
10: double dVar6;
11: size_t sVar7;
12: byte *pbVar8;
13: byte *pbVar9;
14: undefined *puVar10;
15: double dVar11;
16: double dVar12;
17: double dVar13;
18: double dVar14;
19: 
20: lVar3 = *(long *)(param_2 + 0x48);
21: iVar1 = *(int *)(param_2 + 0x50);
22: sVar7 = fread(*(void **)(param_2 + 0x30),1,*(size_t *)(param_2 + 0x40),*(FILE **)(param_2 + 0x18))
23: ;
24: if (*(size_t *)(param_2 + 0x40) != sVar7) {
25: ppcVar4 = (code **)*param_1;
26: *(undefined4 *)(ppcVar4 + 5) = 0x2b;
27: (**ppcVar4)(param_1);
28: }
29: iVar2 = *(int *)(param_1 + 6);
30: pbVar5 = *(byte **)(param_2 + 0x30);
31: if (iVar1 == 0xff) {
32: if (iVar2 != 0) {
33: pbVar9 = pbVar5;
34: puVar10 = (undefined *)**(undefined8 **)(param_2 + 0x20);
35: do {
36: while( true ) {
37: pbVar8 = pbVar9 + 3;
38: dVar13 = 1.0 - (double)(uint)*pbVar9 / 255.0;
39: dVar12 = 1.0 - (double)(uint)pbVar9[1] / 255.0;
40: dVar11 = 1.0 - (double)(uint)pbVar9[2] / 255.0;
41: dVar6 = dVar13;
42: if (dVar12 <= dVar13) {
43: dVar6 = dVar12;
44: }
45: if (dVar11 <= dVar6) {
46: dVar6 = dVar11;
47: }
48: pbVar9 = pbVar8;
49: if (dVar6 == 1.0) break;
50: dVar14 = 1.0 - dVar6;
51: *puVar10 = (char)(int)((255.0 - ((dVar13 - dVar6) / dVar14) * 255.0) + 0.5);
52: puVar10[1] = (char)(int)((255.0 - ((dVar12 - dVar6) / dVar14) * 255.0) + 0.5);
53: puVar10[2] = (char)(int)((255.0 - ((dVar11 - dVar6) / dVar14) * 255.0) + 0.5);
54: puVar10[3] = (char)(int)((255.0 - dVar6 * 255.0) + 0.5);
55: puVar10 = puVar10 + 4;
56: if (pbVar5 + (ulong)(iVar2 - 1) * 3 + 3 == pbVar8) {
57: return 1;
58: }
59: }
60: *puVar10 = 0xff;
61: puVar10[1] = 0xff;
62: puVar10[2] = 0xff;
63: puVar10[3] = 0;
64: puVar10 = puVar10 + 4;
65: } while (pbVar5 + (ulong)(iVar2 - 1) * 3 + 3 != pbVar8);
66: return 1;
67: }
68: }
69: else {
70: if (iVar2 != 0) {
71: pbVar9 = pbVar5;
72: puVar10 = (undefined *)**(undefined8 **)(param_2 + 0x20);
73: do {
74: while( true ) {
75: pbVar8 = pbVar9 + 3;
76: dVar13 = 1.0 - (double)(uint)*(byte *)(lVar3 + (ulong)*pbVar9) / 255.0;
77: dVar12 = 1.0 - (double)(uint)*(byte *)(lVar3 + (ulong)pbVar9[1]) / 255.0;
78: dVar11 = 1.0 - (double)(uint)*(byte *)(lVar3 + (ulong)pbVar9[2]) / 255.0;
79: dVar6 = dVar13;
80: if (dVar12 <= dVar13) {
81: dVar6 = dVar12;
82: }
83: if (dVar11 <= dVar6) {
84: dVar6 = dVar11;
85: }
86: pbVar9 = pbVar8;
87: if (dVar6 != 1.0) break;
88: *puVar10 = 0xff;
89: puVar10[1] = 0xff;
90: puVar10[2] = 0xff;
91: puVar10[3] = 0;
92: puVar10 = puVar10 + 4;
93: if (pbVar8 == pbVar5 + (ulong)(iVar2 - 1) * 3 + 3) {
94: return 1;
95: }
96: }
97: dVar14 = 1.0 - dVar6;
98: *puVar10 = (char)(int)((255.0 - ((dVar13 - dVar6) / dVar14) * 255.0) + 0.5);
99: puVar10[1] = (char)(int)((255.0 - ((dVar12 - dVar6) / dVar14) * 255.0) + 0.5);
100: puVar10[2] = (char)(int)((255.0 - ((dVar11 - dVar6) / dVar14) * 255.0) + 0.5);
101: puVar10[3] = (char)(int)((255.0 - dVar6 * 255.0) + 0.5);
102: puVar10 = puVar10 + 4;
103: } while (pbVar8 != pbVar5 + (ulong)(iVar2 - 1) * 3 + 3);
104: }
105: }
106: return 1;
107: }
108: 
