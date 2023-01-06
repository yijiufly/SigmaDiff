1: 
2: bool tjGetErrorCode(long param_1)
3: 
4: {
5: if (param_1 != 0) {
6: return *(int *)(param_1 + 0x5f8) == 0;
7: }
8: return true;
9: }
10: 
