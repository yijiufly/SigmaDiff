1: 
2: bool tjGetErrorCode(long param_1)
3: 
4: {
5: bool bVar1;
6: 
7: bVar1 = true;
8: if (param_1 != 0) {
9: bVar1 = *(int *)(param_1 + 0x5f8) == 0;
10: }
11: return bVar1;
12: }
13: 
