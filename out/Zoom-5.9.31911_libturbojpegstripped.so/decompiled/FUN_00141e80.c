1: 
2: void * FUN_00141e80(void *param_1)
3: 
4: {
5: int iVar1;
6: undefined8 uVar2;
7: 
8: uVar2 = FUN_00132f40((long)param_1 + 0x480);
9: *(undefined8 *)((long)param_1 + 0x208) = uVar2;
10: *(undefined4 *)((long)param_1 + 0x520) = 1000;
11: *(undefined4 *)((long)param_1 + 0x524) = 0x404;
12: *(code **)((long)param_1 + 0x480) = FUN_00141bb0;
13: *(code **)((long)param_1 + 0x490) = FUN_00141a30;
14: *(undefined8 *)((long)param_1 + 0x5f0) = *(undefined8 *)((long)param_1 + 0x488);
15: *(code **)((long)param_1 + 0x488) = FUN_00141b60;
16: *(undefined **)((long)param_1 + 0x518) = &DAT_003a60e0;
17: iVar1 = _setjmp((__jmp_buf_tag *)((long)param_1 + 0x528));
18: if (iVar1 != 0) {
19: free(param_1);
20: return (void *)0x0;
21: }
22: FUN_0011ce30((long)param_1 + 0x208,0x3e,0x278);
23: FUN_00150390((long)param_1 + 0x208,&DAT_003a61e5,1);
24: *(uint *)((long)param_1 + 0x600) = *(uint *)((long)param_1 + 0x600) | 2;
25: return param_1;
26: }
27: 
