1: 
2: /* WARNING: Control flow encountered bad instruction data */
3: 
4: void __stack_chk_fail(void)
5: 
6: {
7: /* WARNING: Bad instruction - Truncating control flow here */
8: halt_baddata();
9: }
10: 
