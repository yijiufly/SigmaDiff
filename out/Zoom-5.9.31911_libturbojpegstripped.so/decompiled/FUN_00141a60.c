1: 
2: undefined8 * FUN_00141a60(undefined8 *param_1)
3: 
4: {
5: int iVar1;
6: undefined8 uVar2;
7: undefined *apuStack40 [2];
8: undefined8 auStack24 [2];
9: 
10: apuStack40[0] = &DAT_003a61e6;
11: auStack24[0] = 1;
12: uVar2 = FUN_00132f40(param_1 + 0x90);
13: *param_1 = uVar2;
14: *(undefined4 *)(param_1 + 0xa4) = 1000;
15: *(undefined4 *)((long)param_1 + 0x524) = 0x404;
16: param_1[0x90] = FUN_00141bb0;
17: param_1[0x92] = FUN_00141a30;
18: param_1[0xbe] = param_1[0x91];
19: param_1[0x91] = FUN_00141b60;
20: param_1[0xa3] = &DAT_003a60e0;
21: iVar1 = _setjmp((__jmp_buf_tag *)(param_1 + 0xa5));
22: if (iVar1 != 0) {
23: free(param_1);
24: return (undefined8 *)0x0;
25: }
26: FUN_00102c40(param_1,0x3e,0x208);
27: FUN_00150120(param_1,apuStack40,auStack24,0);
28: *(uint *)(param_1 + 0xc0) = *(uint *)(param_1 + 0xc0) | 1;
29: return param_1;
30: }
31: 
