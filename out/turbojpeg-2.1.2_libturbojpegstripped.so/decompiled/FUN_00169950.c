1: 
2: undefined8 FUN_00169950(long param_1,long param_2)
3: 
4: {
5: byte bVar1;
6: int iVar2;
7: int iVar3;
8: undefined8 uVar4;
9: undefined *puVar5;
10: long lVar6;
11: double dVar7;
12: byte bVar8;
13: uint uVar9;
14: uint uVar10;
15: undefined *puVar11;
16: undefined *puVar12;
17: double dVar13;
18: double dVar14;
19: double dVar15;
20: double dVar16;
21: 
22: iVar2 = *(int *)(param_2 + 0x50);
23: uVar4 = *(undefined8 *)(param_2 + 0x18);
24: puVar5 = (undefined *)**(undefined8 **)(param_2 + 0x20);
25: iVar3 = *(int *)(param_1 + 0x30);
26: if (iVar2 == 0xff) {
27: if (iVar3 != 0) {
28: puVar12 = puVar5;
29: do {
30: while( true ) {
31: uVar9 = FUN_00169820(param_1,uVar4,0xff);
32: uVar10 = FUN_00169820(param_1,uVar4,0xff);
33: bVar8 = FUN_00169820(param_1,uVar4,0xff);
34: dVar15 = 1.0 - (double)(uVar9 & 0xff) / 255.0;
35: dVar14 = 1.0 - (double)(uVar10 & 0xff) / 255.0;
36: dVar13 = 1.0 - (double)(uint)bVar8 / 255.0;
37: dVar7 = dVar15;
38: if (dVar14 <= dVar15) {
39: dVar7 = dVar14;
40: }
41: if (dVar13 <= dVar7) {
42: dVar7 = dVar13;
43: }
44: if (dVar7 == 1.0) break;
45: puVar11 = puVar12 + 4;
46: dVar16 = 1.0 - dVar7;
47: *puVar12 = (char)(int)((255.0 - ((dVar15 - dVar7) / dVar16) * 255.0) + 0.5);
48: puVar12[1] = (char)(int)((255.0 - ((dVar14 - dVar7) / dVar16) * 255.0) + 0.5);
49: puVar12[2] = (char)(int)((255.0 - ((dVar13 - dVar7) / dVar16) * 255.0) + 0.5);
50: puVar12[3] = (char)(int)((255.0 - dVar7 * 255.0) + 0.5);
51: puVar12 = puVar11;
52: if (puVar5 + (ulong)(iVar3 - 1) * 4 + 4 == puVar11) {
53: return 1;
54: }
55: }
56: *puVar12 = 0xff;
57: puVar12[1] = 0xff;
58: puVar11 = puVar12 + 4;
59: puVar12[2] = 0xff;
60: puVar12[3] = 0;
61: puVar12 = puVar11;
62: } while (puVar11 != puVar5 + (ulong)(iVar3 - 1) * 4 + 4);
63: }
64: }
65: else {
66: if (iVar3 != 0) {
67: lVar6 = *(long *)(param_2 + 0x48);
68: puVar12 = puVar5;
69: do {
70: while( true ) {
71: uVar9 = FUN_00169820(param_1,uVar4,iVar2);
72: bVar8 = *(byte *)(lVar6 + (ulong)uVar9);
73: uVar9 = FUN_00169820(param_1,uVar4,iVar2);
74: bVar1 = *(byte *)(lVar6 + (ulong)uVar9);
75: uVar9 = FUN_00169820(param_1,uVar4,iVar2);
76: dVar15 = 1.0 - (double)(uint)bVar8 / 255.0;
77: dVar14 = 1.0 - (double)(uint)bVar1 / 255.0;
78: dVar13 = 1.0 - (double)(uint)*(byte *)(lVar6 + (ulong)uVar9) / 255.0;
79: dVar7 = dVar15;
80: if (dVar14 <= dVar15) {
81: dVar7 = dVar14;
82: }
83: if (dVar13 <= dVar7) {
84: dVar7 = dVar13;
85: }
86: if (dVar7 == 1.0) break;
87: puVar11 = puVar12 + 4;
88: dVar16 = 1.0 - dVar7;
89: *puVar12 = (char)(int)((255.0 - ((dVar15 - dVar7) / dVar16) * 255.0) + 0.5);
90: puVar12[1] = (char)(int)((255.0 - ((dVar14 - dVar7) / dVar16) * 255.0) + 0.5);
91: puVar12[2] = (char)(int)((255.0 - ((dVar13 - dVar7) / dVar16) * 255.0) + 0.5);
92: puVar12[3] = (char)(int)((255.0 - dVar7 * 255.0) + 0.5);
93: puVar12 = puVar11;
94: if (puVar11 == puVar5 + (ulong)(iVar3 - 1) * 4 + 4) {
95: return 1;
96: }
97: }
98: *puVar12 = 0xff;
99: puVar12[1] = 0xff;
100: puVar11 = puVar12 + 4;
101: puVar12[2] = 0xff;
102: puVar12[3] = 0;
103: puVar12 = puVar11;
104: } while (puVar11 != puVar5 + (ulong)(iVar3 - 1) * 4 + 4);
105: }
106: }
107: return 1;
108: }
109: 
