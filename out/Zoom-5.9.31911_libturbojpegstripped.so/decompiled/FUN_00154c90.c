1: 
2: void FUN_00154c90(long param_1,long param_2)
3: 
4: {
5: byte bVar1;
6: byte bVar2;
7: int iVar3;
8: undefined *puVar4;
9: undefined *puVar5;
10: byte *pbVar6;
11: undefined *__ptr;
12: double dVar7;
13: 
14: iVar3 = *(int *)(param_1 + 0x88);
15: __ptr = *(undefined **)(param_2 + 0x38);
16: if (iVar3 != 0) {
17: puVar4 = __ptr;
18: pbVar6 = **(byte ***)(param_2 + 0x28);
19: do {
20: bVar1 = pbVar6[1];
21: bVar2 = pbVar6[2];
22: puVar5 = puVar4 + 3;
23: dVar7 = (double)(uint)pbVar6[3];
24: *puVar4 = (char)(int)(((double)(uint)*pbVar6 * dVar7) / 255.0 + 0.5);
25: puVar4[1] = (char)(int)(((double)(uint)bVar1 * dVar7) / 255.0 + 0.5);
26: puVar4[2] = (char)(int)(((double)(uint)bVar2 * dVar7) / 255.0 + 0.5);
27: puVar4 = puVar5;
28: pbVar6 = pbVar6 + 4;
29: } while (puVar5 != __ptr + (ulong)(iVar3 - 1) * 3 + 3);
30: __ptr = *(undefined **)(param_2 + 0x38);
31: }
32: fwrite(__ptr,1,*(size_t *)(param_2 + 0x48),*(FILE **)(param_2 + 0x20));
33: return;
34: }
35: 
