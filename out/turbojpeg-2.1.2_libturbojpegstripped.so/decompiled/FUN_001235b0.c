1: 
2: void FUN_001235b0(long param_1,long param_2,long *param_3,long param_4)
3: 
4: {
5: byte *pbVar1;
6: int iVar2;
7: byte bVar3;
8: int iVar4;
9: undefined *puVar5;
10: int iVar6;
11: byte *pbVar7;
12: undefined *puVar8;
13: undefined *puVar9;
14: uint uVar10;
15: void *__s;
16: long lVar11;
17: long *plVar12;
18: 
19: uVar10 = *(uint *)(param_1 + 0x30);
20: iVar2 = *(int *)(param_2 + 0x1c) * 8;
21: iVar6 = *(int *)(param_2 + 0x1c) * 0x10 - uVar10;
22: if ((0 < iVar6) && (iVar4 = *(int *)(param_1 + 0x13c), 0 < iVar4)) {
23: plVar12 = param_3;
24: do {
25: lVar11 = *plVar12;
26: plVar12 = plVar12 + 1;
27: __s = (void *)(lVar11 + (ulong)uVar10);
28: memset(__s,(uint)*(byte *)((long)__s + -1),(long)(iVar6 + -1) + 1);
29: } while (param_3 + (ulong)(iVar4 - 1) + 1 != plVar12);
30: }
31: if ((0 < *(int *)(param_2 + 0xc)) && (iVar2 != 0)) {
32: lVar11 = 1;
33: do {
34: puVar5 = *(undefined **)(param_4 + -8 + lVar11 * 8);
35: pbVar7 = (byte *)param_3[lVar11 + -1];
36: uVar10 = 0;
37: puVar8 = puVar5;
38: do {
39: bVar3 = *pbVar7;
40: pbVar1 = pbVar7 + 1;
41: puVar9 = puVar8 + 1;
42: pbVar7 = pbVar7 + 2;
43: iVar6 = (uint)bVar3 + (uint)*pbVar1 + uVar10;
44: uVar10 = uVar10 ^ 1;
45: *puVar8 = (char)(iVar6 >> 1);
46: puVar8 = puVar9;
47: } while (puVar9 != puVar5 + (ulong)(iVar2 - 1) + 1);
48: iVar6 = (int)lVar11;
49: lVar11 = lVar11 + 1;
50: } while (iVar6 < *(int *)(param_2 + 0xc));
51: }
52: return;
53: }
54: 
