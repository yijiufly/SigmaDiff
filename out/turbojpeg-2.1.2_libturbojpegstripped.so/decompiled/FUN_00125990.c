1: 
2: int FUN_00125990(code **param_1,undefined8 param_2,undefined4 param_3)
3: 
4: {
5: uint uVar1;
6: code **ppcVar2;
7: code *pcVar3;
8: int iVar4;
9: long in_FS_OFFSET;
10: int iStack36;
11: long lStack32;
12: 
13: iVar4 = *(int *)((long)param_1 + 0x24);
14: lStack32 = *(long *)(in_FS_OFFSET + 0x28);
15: if (iVar4 != 0xcd) {
16: ppcVar2 = (code **)*param_1;
17: *(undefined4 *)(ppcVar2 + 5) = 0x14;
18: *(int *)((long)ppcVar2 + 0x2c) = iVar4;
19: (**ppcVar2)();
20: }
21: uVar1 = *(uint *)(param_1 + 0x15);
22: if (uVar1 < *(uint *)((long)param_1 + 0x8c)) {
23: ppcVar2 = (code **)param_1[2];
24: if (ppcVar2 != (code **)0x0) {
25: ppcVar2[2] = (code *)(ulong)*(uint *)((long)param_1 + 0x8c);
26: ppcVar2[1] = (code *)(ulong)uVar1;
27: (**ppcVar2)(param_1);
28: }
29: iStack36 = 0;
30: (**(code **)(param_1[0x45] + 8))(param_1,param_2,&iStack36,param_3);
31: *(int *)(param_1 + 0x15) = *(int *)(param_1 + 0x15) + iStack36;
32: iVar4 = iStack36;
33: }
34: else {
35: pcVar3 = *param_1;
36: *(undefined4 *)(pcVar3 + 0x28) = 0x7b;
37: (**(code **)(pcVar3 + 8))(param_1,0xffffffff);
38: iVar4 = 0;
39: }
40: if (lStack32 == *(long *)(in_FS_OFFSET + 0x28)) {
41: return iVar4;
42: }
43: /* WARNING: Subroutine does not return */
44: __stack_chk_fail();
45: }
46: 
