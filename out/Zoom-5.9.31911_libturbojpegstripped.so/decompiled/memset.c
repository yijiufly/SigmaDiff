1: 
2: /* WARNING: Control flow encountered bad instruction data */
3: /* WARNING: Unknown calling convention yet parameter storage is locked */
4: 
5: void * memset(void *__s,int __c,size_t __n)
6: 
7: {
8: /* WARNING: Bad instruction - Truncating control flow here */
9: halt_baddata();
10: }
11: 
