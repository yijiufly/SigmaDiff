1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: void FUN_0013e060(long *param_1)
5: 
6: {
7: long in_FS_OFFSET;
8: undefined auStack216 [200];
9: long lStack16;
10: 
11: lStack16 = *(long *)(in_FS_OFFSET + 0x28);
12: (**(code **)(*param_1 + 0x18))(param_1,auStack216);
13: __fprintf_chk(_stderr,1,&DAT_0018d940,auStack216);
14: if (lStack16 == *(long *)(in_FS_OFFSET + 0x28)) {
15: return;
16: }
17: /* WARNING: Subroutine does not return */
18: __stack_chk_fail();
19: }
20: 
