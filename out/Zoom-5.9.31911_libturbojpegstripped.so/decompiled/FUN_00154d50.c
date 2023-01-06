1: 
2: void FUN_00154d50(long param_1,long param_2)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: int iVar3;
8: int iVar4;
9: int iVar5;
10: ulong uVar6;
11: undefined *puVar7;
12: undefined *puVar8;
13: undefined *puVar9;
14: undefined *__ptr;
15: 
16: uVar6 = (ulong)*(uint *)(param_1 + 0x40);
17: iVar1 = *(int *)(param_1 + 0x88);
18: iVar2 = *(int *)(&DAT_0018c7c0 + uVar6 * 4);
19: iVar3 = *(int *)(&DAT_0018c760 + uVar6 * 4);
20: iVar4 = *(int *)(&DAT_0018c700 + uVar6 * 4);
21: iVar5 = *(int *)(&DAT_0018c6a0 + uVar6 * 4);
22: __ptr = *(undefined **)(param_2 + 0x38);
23: if (iVar1 != 0) {
24: puVar7 = __ptr;
25: puVar9 = (undefined *)(**(long **)(param_2 + 0x28) + (long)iVar2);
26: do {
27: puVar8 = puVar7 + 3;
28: *puVar7 = *puVar9;
29: puVar7[1] = (puVar9 + -(long)iVar2)[iVar3];
30: puVar7[2] = (puVar9 + -(long)iVar2)[iVar4];
31: puVar7 = puVar8;
32: puVar9 = puVar9 + iVar5;
33: } while (__ptr + (ulong)(iVar1 - 1) * 3 + 3 != puVar8);
34: __ptr = *(undefined **)(param_2 + 0x38);
35: }
36: fwrite(__ptr,1,*(size_t *)(param_2 + 0x48),*(FILE **)(param_2 + 0x20));
37: return;
38: }
39: 
