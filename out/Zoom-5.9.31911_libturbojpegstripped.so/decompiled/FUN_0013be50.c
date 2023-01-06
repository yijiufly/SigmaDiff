1: 
2: void FUN_0013be50(long param_1,int param_2,long param_3,int param_4,int param_5,uint param_6)
3: 
4: {
5: void **ppvVar1;
6: void **ppvVar2;
7: 
8: ppvVar2 = (void **)(param_1 + (long)param_2 * 8);
9: ppvVar1 = (void **)(param_3 + (long)param_4 * 8);
10: if (0 < param_5) {
11: do {
12: memcpy(*ppvVar1,*ppvVar2,(ulong)param_6);
13: param_5 = param_5 + -1;
14: ppvVar1 = ppvVar1 + 1;
15: ppvVar2 = ppvVar2 + 1;
16: } while (param_5 != 0);
17: }
18: return;
19: }
20: 
