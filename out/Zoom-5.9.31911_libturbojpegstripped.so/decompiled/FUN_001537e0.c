1: 
2: undefined8 FUN_001537e0(long param_1,long param_2)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: undefined8 uVar3;
8: long lVar4;
9: undefined *puVar5;
10: undefined uVar6;
11: byte bVar7;
12: uint uVar8;
13: undefined *puVar9;
14: undefined *puVar10;
15: double dVar11;
16: 
17: iVar1 = *(int *)(param_2 + 0x50);
18: uVar3 = *(undefined8 *)(param_2 + 0x18);
19: lVar4 = *(long *)(param_2 + 0x48);
20: puVar5 = (undefined *)**(long **)(param_2 + 0x20);
21: iVar2 = *(int *)(param_1 + 0x30);
22: if (iVar1 == 0xff) {
23: if (iVar2 != 0) {
24: puVar10 = puVar5;
25: do {
26: bVar7 = FUN_00152a10(param_1,uVar3,0xff);
27: dVar11 = 1.0 - (double)(uint)bVar7 / 255.0;
28: uVar6 = 0xff;
29: if (dVar11 != 1.0) {
30: uVar6 = (undefined)(int)((255.0 - ((dVar11 - dVar11) / (1.0 - dVar11)) * 255.0) + 0.5);
31: }
32: *puVar10 = uVar6;
33: puVar10[1] = uVar6;
34: puVar9 = puVar10 + 4;
35: puVar10[2] = uVar6;
36: puVar10[3] = (char)(int)((255.0 - dVar11 * 255.0) + 0.5);
37: puVar10 = puVar9;
38: } while (puVar9 != puVar5 + (ulong)(iVar2 - 1) * 4 + 4);
39: }
40: }
41: else {
42: if (iVar2 != 0) {
43: puVar10 = puVar5;
44: do {
45: uVar8 = FUN_00152a10(param_1,uVar3,iVar1);
46: dVar11 = 1.0 - (double)(uint)*(byte *)(lVar4 + (ulong)uVar8) / 255.0;
47: uVar6 = 0xff;
48: if (dVar11 != 1.0) {
49: uVar6 = (undefined)(int)((255.0 - ((dVar11 - dVar11) / (1.0 - dVar11)) * 255.0) + 0.5);
50: }
51: *puVar10 = uVar6;
52: puVar10[1] = uVar6;
53: puVar9 = puVar10 + 4;
54: puVar10[2] = uVar6;
55: puVar10[3] = (char)(int)((255.0 - dVar11 * 255.0) + 0.5);
56: puVar10 = puVar9;
57: } while (puVar9 != puVar5 + (ulong)(iVar2 - 1) * 4 + 4);
58: }
59: }
60: return 1;
61: }
62: 
