1: 
2: void FUN_0011ada0(long param_1,long param_2,long *param_3,long param_4)
3: 
4: {
5: byte *pbVar1;
6: int iVar2;
7: byte bVar3;
8: undefined *puVar4;
9: int iVar5;
10: uint uVar6;
11: undefined *puVar7;
12: undefined *puVar8;
13: int iVar9;
14: byte *pbVar10;
15: uint uVar11;
16: void *__s;
17: long lVar12;
18: long *plVar13;
19: 
20: uVar11 = *(uint *)(param_1 + 0x30);
21: iVar9 = *(int *)(param_1 + 0x13c);
22: iVar2 = *(int *)(param_2 + 0x1c) * 8;
23: uVar6 = *(int *)(param_2 + 0x1c) * 0x10 - uVar11;
24: if ((0 < (int)uVar6) && (0 < iVar9)) {
25: plVar13 = param_3;
26: do {
27: __s = (void *)((ulong)uVar11 + *plVar13);
28: plVar13 = plVar13 + 1;
29: memset(__s,(uint)*(byte *)((long)__s + -1),(ulong)uVar6);
30: } while (plVar13 != param_3 + (ulong)(iVar9 - 1) + 1);
31: }
32: iVar9 = *(int *)(param_2 + 0xc);
33: lVar12 = 0;
34: if (0 < iVar9) {
35: do {
36: puVar4 = *(undefined **)(param_4 + lVar12 * 8);
37: pbVar10 = (byte *)param_3[lVar12];
38: if (iVar2 != 0) {
39: uVar11 = 0;
40: puVar7 = puVar4;
41: do {
42: bVar3 = *pbVar10;
43: pbVar1 = pbVar10 + 1;
44: puVar8 = puVar7 + 1;
45: pbVar10 = pbVar10 + 2;
46: iVar9 = (uint)*pbVar1 + (uint)bVar3 + uVar11;
47: uVar11 = uVar11 ^ 1;
48: *puVar7 = (char)(iVar9 >> 1);
49: puVar7 = puVar8;
50: } while (puVar8 != puVar4 + (ulong)(iVar2 - 1) + 1);
51: iVar9 = *(int *)(param_2 + 0xc);
52: }
53: iVar5 = (int)lVar12;
54: lVar12 = lVar12 + 1;
55: } while (iVar5 + 1 < iVar9);
56: }
57: return;
58: }
59: 
