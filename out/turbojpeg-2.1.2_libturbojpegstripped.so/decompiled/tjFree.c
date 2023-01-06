1: 
2: /* WARNING: Unknown calling convention yet parameter storage is locked */
3: 
4: void tjFree(void *__ptr)
5: 
6: {
7: /* WARNING: Treating indirect jump as call */
8: free(__ptr);
9: return;
10: }
11: 
