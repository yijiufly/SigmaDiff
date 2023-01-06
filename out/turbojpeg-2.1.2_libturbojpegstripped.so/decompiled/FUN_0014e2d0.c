1: 
2: undefined8 * FUN_0014e2d0(undefined8 *param_1)
3: 
4: {
5: int iVar1;
6: undefined8 uVar2;
7: long in_FS_OFFSET;
8: undefined *puStack32;
9: undefined8 uStack24;
10: long lStack16;
11: 
12: lStack16 = *(long *)(in_FS_OFFSET + 0x28);
13: uStack24 = 1;
14: puStack32 = &DAT_003992ca;
15: uVar2 = FUN_0013e0f0(param_1 + 0x90);
16: *param_1 = uVar2;
17: param_1[0x90] = FUN_0014e430;
18: param_1[0x92] = FUN_0014e280;
19: param_1[0xbe] = param_1[0x91];
20: param_1[0x91] = FUN_0014e3e0;
21: param_1[0xa3] = &DAT_003991e0;
22: param_1[0xa4] = 0x404000003e8;
23: iVar1 = _setjmp((__jmp_buf_tag *)(param_1 + 0xa5));
24: if (iVar1 == 0) {
25: FUN_00102b10(param_1,0x3e,0x208);
26: FUN_00166fe0(param_1,&puStack32,&uStack24,0);
27: *(uint *)(param_1 + 0xc0) = *(uint *)(param_1 + 0xc0) | 1;
28: }
29: else {
30: free(param_1);
31: param_1 = (undefined8 *)0x0;
32: }
33: if (lStack16 == *(long *)(in_FS_OFFSET + 0x28)) {
34: return param_1;
35: }
36: /* WARNING: Subroutine does not return */
37: __stack_chk_fail();
38: }
39: 
