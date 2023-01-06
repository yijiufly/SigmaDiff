1: 
2: void FUN_00148a00(long param_1,int param_2,long param_3,int param_4,int param_5,uint param_6)
3: 
4: {
5: void **ppvVar1;
6: void *__src;
7: void **ppvVar2;
8: void **ppvVar3;
9: 
10: ppvVar2 = (void **)(param_1 + (long)param_2 * 8);
11: if (0 < param_5) {
12: ppvVar1 = ppvVar2 + (ulong)(param_5 - 1) + 1;
13: ppvVar3 = (void **)(param_3 + (long)param_4 * 8);
14: do {
15: __src = *ppvVar2;
16: ppvVar2 = ppvVar2 + 1;
17: memcpy(*ppvVar3,__src,(ulong)param_6);
18: ppvVar3 = ppvVar3 + 1;
19: } while (ppvVar2 != ppvVar1);
20: }
21: return;
22: }
23: 
