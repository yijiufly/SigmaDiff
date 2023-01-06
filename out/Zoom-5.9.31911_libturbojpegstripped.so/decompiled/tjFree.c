1: 
2: void tjFree(void *param_1)
3: 
4: {
5: if (param_1 != (void *)0x0) {
6: free(param_1);
7: return;
8: }
9: return;
10: }
11: 
