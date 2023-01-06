1: 
2: void FUN_00103090(code **param_1,undefined8 param_2,uint param_3)
3: 
4: {
5: int iVar1;
6: code **ppcVar2;
7: code *pcVar3;
8: uint uVar4;
9: long in_FS_OFFSET;
10: int iStack36;
11: long lStack32;
12: 
13: iVar1 = *(int *)((long)param_1 + 0x24);
14: lStack32 = *(long *)(in_FS_OFFSET + 0x28);
15: if (iVar1 != 0x65) {
16: ppcVar2 = (code **)*param_1;
17: *(undefined4 *)(ppcVar2 + 5) = 0x14;
18: *(int *)((long)ppcVar2 + 0x2c) = iVar1;
19: (**ppcVar2)();
20: }
21: if (*(uint *)((long)param_1 + 0x34) <= *(uint *)(param_1 + 0x26)) {
22: pcVar3 = *param_1;
23: *(undefined4 *)(pcVar3 + 0x28) = 0x7b;
24: (**(code **)(pcVar3 + 8))(param_1);
25: }
26: ppcVar2 = (code **)param_1[2];
27: if (ppcVar2 != (code **)0x0) {
28: ppcVar2[1] = (code *)(ulong)*(uint *)(param_1 + 0x26);
29: ppcVar2[2] = (code *)(ulong)*(uint *)((long)param_1 + 0x34);
30: (**ppcVar2)(param_1);
31: }
32: if (*(int *)(param_1[0x36] + 0x18) != 0) {
33: (**(code **)(param_1[0x36] + 8))(param_1);
34: }
35: uVar4 = *(int *)((long)param_1 + 0x34) - *(int *)(param_1 + 0x26);
36: iStack36 = 0;
37: if (uVar4 <= param_3) {
38: param_3 = uVar4;
39: }
40: (**(code **)(param_1[0x37] + 8))(param_1,param_2,&iStack36,param_3);
41: *(int *)(param_1 + 0x26) = *(int *)(param_1 + 0x26) + iStack36;
42: if (lStack32 == *(long *)(in_FS_OFFSET + 0x28)) {
43: return;
44: }
45: /* WARNING: Subroutine does not return */
46: __stack_chk_fail();
47: }
48: 
