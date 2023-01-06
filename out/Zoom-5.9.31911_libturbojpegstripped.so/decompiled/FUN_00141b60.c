1: 
2: void FUN_00141b60(long *param_1,int param_2)
3: 
4: {
5: long lVar1;
6: 
7: lVar1 = *param_1;
8: (**(code **)(lVar1 + 0x170))();
9: if ((param_2 < 0) && (*(undefined4 *)(lVar1 + 0x178) = 1, *(int *)(lVar1 + 0x17c) != 0)) {
10: /* WARNING: Subroutine does not return */
11: longjmp((__jmp_buf_tag *)(lVar1 + 0xa8),1);
12: }
13: return;
14: }
15: 
