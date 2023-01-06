1: 
2: void FUN_0011ae80(long param_1,long param_2,long *param_3,long param_4)
3: 
4: {
5: byte *pbVar1;
6: int iVar2;
7: byte bVar3;
8: undefined *puVar4;
9: undefined *puVar5;
10: undefined *puVar6;
11: uint uVar7;
12: int iVar8;
13: void *__s;
14: byte *pbVar9;
15: byte *pbVar10;
16: long lVar11;
17: uint uVar12;
18: int iVar13;
19: long *plVar14;
20: 
21: uVar7 = *(uint *)(param_1 + 0x30);
22: iVar8 = *(int *)(param_1 + 0x13c);
23: iVar2 = *(int *)(param_2 + 0x1c) * 8;
24: uVar12 = *(int *)(param_2 + 0x1c) * 0x10 - uVar7;
25: if ((0 < (int)uVar12) && (0 < iVar8)) {
26: plVar14 = param_3;
27: do {
28: __s = (void *)((ulong)uVar7 + *plVar14);
29: plVar14 = plVar14 + 1;
30: memset(__s,(uint)*(byte *)((long)__s + -1),(ulong)uVar12);
31: } while (plVar14 != param_3 + (ulong)(iVar8 - 1) + 1);
32: }
33: iVar8 = *(int *)(param_2 + 0xc);
34: lVar11 = 0;
35: iVar13 = 0;
36: if (0 < iVar8) {
37: do {
38: puVar4 = *(undefined **)(param_4 + lVar11);
39: pbVar9 = *(byte **)((long)param_3 + lVar11 * 2);
40: if (iVar2 != 0) {
41: uVar7 = 1;
42: puVar5 = puVar4;
43: pbVar10 = *(byte **)((long)param_3 + lVar11 * 2 + 8);
44: do {
45: bVar3 = *pbVar9;
46: pbVar1 = pbVar9 + 1;
47: puVar6 = puVar5 + 1;
48: pbVar9 = pbVar9 + 2;
49: iVar8 = (uint)*pbVar1 + (uint)bVar3 + (uint)*pbVar10 + (uint)pbVar10[1] + uVar7;
50: uVar7 = uVar7 ^ 3;
51: *puVar5 = (char)(iVar8 >> 2);
52: puVar5 = puVar6;
53: pbVar10 = pbVar10 + 2;
54: } while (puVar6 != puVar4 + (ulong)(iVar2 - 1) + 1);
55: iVar8 = *(int *)(param_2 + 0xc);
56: }
57: iVar13 = iVar13 + 1;
58: lVar11 = lVar11 + 8;
59: } while (iVar13 < iVar8);
60: }
61: return;
62: }
63: 
