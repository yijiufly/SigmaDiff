1: 
2: void FUN_00103230(code **param_1,undefined8 param_2,uint param_3)
3: 
4: {
5: code *pcVar1;
6: code **ppcVar2;
7: uint uVar3;
8: int aiStack40 [4];
9: 
10: if (*(int *)((long)param_1 + 0x24) != 0x65) {
11: pcVar1 = *param_1;
12: *(int *)(pcVar1 + 0x2c) = *(int *)((long)param_1 + 0x24);
13: ppcVar2 = (code **)*param_1;
14: *(undefined4 *)(pcVar1 + 0x28) = 0x14;
15: (**ppcVar2)();
16: }
17: if (*(uint *)((long)param_1 + 0x34) <= *(uint *)(param_1 + 0x26)) {
18: pcVar1 = *param_1;
19: *(undefined4 *)(pcVar1 + 0x28) = 0x7b;
20: (**(code **)(pcVar1 + 8))(param_1,0xffffffff);
21: }
22: ppcVar2 = (code **)param_1[2];
23: if (ppcVar2 != (code **)0x0) {
24: ppcVar2[1] = (code *)(ulong)*(uint *)(param_1 + 0x26);
25: ppcVar2[2] = (code *)(ulong)*(uint *)((long)param_1 + 0x34);
26: (**ppcVar2)(param_1);
27: }
28: if (*(int *)(param_1[0x36] + 0x18) != 0) {
29: (**(code **)(param_1[0x36] + 8))(param_1);
30: }
31: uVar3 = *(int *)((long)param_1 + 0x34) - *(int *)(param_1 + 0x26);
32: aiStack40[0] = 0;
33: if (param_3 <= uVar3) {
34: uVar3 = param_3;
35: }
36: (**(code **)(param_1[0x37] + 8))(param_1,param_2,aiStack40,uVar3);
37: *(int *)(param_1 + 0x26) = *(int *)(param_1 + 0x26) + aiStack40[0];
38: return;
39: }
40: 
