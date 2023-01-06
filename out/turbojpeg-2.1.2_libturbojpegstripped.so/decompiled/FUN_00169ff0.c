1: 
2: undefined8 FUN_00169ff0(long param_1,long param_2)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: undefined8 uVar3;
8: undefined *puVar4;
9: long lVar5;
10: undefined uVar6;
11: byte bVar7;
12: uint uVar8;
13: undefined *puVar9;
14: undefined *puVar10;
15: double dVar11;
16: 
17: iVar1 = *(int *)(param_2 + 0x50);
18: uVar3 = *(undefined8 *)(param_2 + 0x18);
19: puVar4 = (undefined *)**(undefined8 **)(param_2 + 0x20);
20: iVar2 = *(int *)(param_1 + 0x30);
21: if (iVar1 == 0xff) {
22: if (iVar2 != 0) {
23: puVar10 = puVar4;
24: do {
25: while( true ) {
26: bVar7 = FUN_00169820(param_1,uVar3,0xff);
27: dVar11 = 1.0 - (double)(uint)bVar7 / 255.0;
28: if (dVar11 == 1.0) break;
29: puVar9 = puVar10 + 4;
30: uVar6 = (undefined)(int)((255.0 - ((dVar11 - dVar11) / (1.0 - dVar11)) * 255.0) + 0.5);
31: *puVar10 = uVar6;
32: puVar10[1] = uVar6;
33: puVar10[2] = uVar6;
34: puVar10[3] = (char)(int)((255.0 - dVar11 * 255.0) + 0.5);
35: puVar10 = puVar9;
36: if (puVar9 == puVar4 + (ulong)(iVar2 - 1) * 4 + 4) {
37: return 1;
38: }
39: }
40: *puVar10 = 0xff;
41: puVar10[1] = 0xff;
42: puVar9 = puVar10 + 4;
43: puVar10[2] = 0xff;
44: puVar10[3] = 0;
45: puVar10 = puVar9;
46: } while (puVar9 != puVar4 + (ulong)(iVar2 - 1) * 4 + 4);
47: }
48: }
49: else {
50: if (iVar2 != 0) {
51: lVar5 = *(long *)(param_2 + 0x48);
52: puVar10 = puVar4;
53: do {
54: while( true ) {
55: uVar8 = FUN_00169820(param_1,uVar3,iVar1);
56: dVar11 = 1.0 - (double)(uint)*(byte *)(lVar5 + (ulong)uVar8) / 255.0;
57: if (dVar11 == 1.0) break;
58: puVar9 = puVar10 + 4;
59: uVar6 = (undefined)(int)((255.0 - ((dVar11 - dVar11) / (1.0 - dVar11)) * 255.0) + 0.5);
60: *puVar10 = uVar6;
61: puVar10[1] = uVar6;
62: puVar10[2] = uVar6;
63: puVar10[3] = (char)(int)((255.0 - dVar11 * 255.0) + 0.5);
64: puVar10 = puVar9;
65: if (puVar4 + (ulong)(iVar2 - 1) * 4 + 4 == puVar9) {
66: return 1;
67: }
68: }
69: *puVar10 = 0xff;
70: puVar10[1] = 0xff;
71: puVar9 = puVar10 + 4;
72: puVar10[2] = 0xff;
73: puVar10[3] = 0;
74: puVar10 = puVar9;
75: } while (puVar9 != puVar4 + (ulong)(iVar2 - 1) * 4 + 4);
76: }
77: }
78: return 1;
79: }
80: 
