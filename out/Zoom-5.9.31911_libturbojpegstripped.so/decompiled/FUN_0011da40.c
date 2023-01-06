1: 
2: int FUN_0011da40(code **param_1,undefined8 param_2,undefined4 param_3)
3: 
4: {
5: uint uVar1;
6: code *pcVar2;
7: code **ppcVar3;
8: int aiStack40 [4];
9: 
10: if (*(int *)((long)param_1 + 0x24) != 0xcd) {
11: pcVar2 = *param_1;
12: *(int *)(pcVar2 + 0x2c) = *(int *)((long)param_1 + 0x24);
13: ppcVar3 = (code **)*param_1;
14: *(undefined4 *)(pcVar2 + 0x28) = 0x14;
15: (**ppcVar3)();
16: }
17: uVar1 = *(uint *)((long)param_1 + 0x8c);
18: if (*(uint *)(param_1 + 0x15) < uVar1) {
19: ppcVar3 = (code **)param_1[2];
20: if (ppcVar3 != (code **)0x0) {
21: ppcVar3[1] = (code *)(ulong)*(uint *)(param_1 + 0x15);
22: ppcVar3[2] = (code *)(ulong)uVar1;
23: (**ppcVar3)(param_1);
24: }
25: aiStack40[0] = 0;
26: (**(code **)(param_1[0x45] + 8))(param_1,param_2,aiStack40,param_3);
27: *(int *)(param_1 + 0x15) = *(int *)(param_1 + 0x15) + aiStack40[0];
28: return aiStack40[0];
29: }
30: pcVar2 = *param_1;
31: *(undefined4 *)(pcVar2 + 0x28) = 0x7b;
32: (**(code **)(pcVar2 + 8))(param_1,0xffffffff);
33: return 0;
34: }
35: 
