1: 
2: void FUN_0013c5a0(long param_1)
3: 
4: {
5: long lVar1;
6: long lVar2;
7: long in_R8;
8: uint *in_R9;
9: long in_FS_OFFSET;
10: 
11: lVar1 = *(long *)(param_1 + 0x238);
12: lVar2 = *(long *)(in_FS_OFFSET + 0x28);
13: (**(code **)(*(long *)(param_1 + 0x260) + 8))();
14: (**(code **)(*(long *)(param_1 + 0x270) + 8))
15: (param_1,*(undefined8 *)(lVar1 + 0x18),in_R8 + (ulong)*in_R9 * 8,0);
16: *in_R9 = *in_R9;
17: if (lVar2 == *(long *)(in_FS_OFFSET + 0x28)) {
18: return;
19: }
20: /* WARNING: Subroutine does not return */
21: __stack_chk_fail();
22: }
23: 
