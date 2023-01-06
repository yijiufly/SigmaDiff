1: 
2: char * tjGetErrorStr2(long param_1)
3: 
4: {
5: if ((param_1 != 0) && (*(int *)(param_1 + 0x6d0) != 0)) {
6: *(undefined4 *)(param_1 + 0x6d0) = 0;
7: return (char *)(param_1 + 0x608);
8: }
9: return s_No_error_003a6000;
10: }
11: 
