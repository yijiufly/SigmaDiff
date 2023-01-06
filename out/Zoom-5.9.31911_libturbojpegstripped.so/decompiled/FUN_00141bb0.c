1: 
2: void FUN_00141bb0(long *param_1)
3: 
4: {
5: long lVar1;
6: 
7: lVar1 = *param_1;
8: (**(code **)(lVar1 + 0x10))();
9: /* WARNING: Subroutine does not return */
10: longjmp((__jmp_buf_tag *)(lVar1 + 0xa8),1);
11: }
12: 
