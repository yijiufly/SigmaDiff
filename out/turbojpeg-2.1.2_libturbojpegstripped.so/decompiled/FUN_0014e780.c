1: 
2: void * FUN_0014e780(void *param_1)
3: 
4: {
5: int iVar1;
6: undefined8 uVar2;
7: 
8: uVar2 = FUN_0013e0f0((long)param_1 + 0x480);
9: *(undefined8 *)((long)param_1 + 0x208) = uVar2;
10: *(code **)((long)param_1 + 0x480) = FUN_0014e430;
11: *(code **)((long)param_1 + 0x490) = FUN_0014e280;
12: *(undefined8 *)((long)param_1 + 0x5f0) = *(undefined8 *)((long)param_1 + 0x488);
13: *(code **)((long)param_1 + 0x488) = FUN_0014e3e0;
14: *(undefined **)((long)param_1 + 0x518) = &DAT_003991e0;
15: *(undefined8 *)((long)param_1 + 0x520) = 0x404000003e8;
16: iVar1 = _setjmp((__jmp_buf_tag *)((long)param_1 + 0x528));
17: if (iVar1 == 0) {
18: FUN_00124ea0((long)param_1 + 0x208,0x3e,0x278);
19: FUN_00167270((long)param_1 + 0x208,&DAT_003992c9,1);
20: *(uint *)((long)param_1 + 0x600) = *(uint *)((long)param_1 + 0x600) | 2;
21: }
22: else {
23: free(param_1);
24: param_1 = (void *)0x0;
25: }
26: return param_1;
27: }
28: 
