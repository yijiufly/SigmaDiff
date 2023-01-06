1: 
2: void FUN_00103030(code **param_1,ulong param_2,undefined *param_3,int param_4)
3: 
4: {
5: undefined *puVar1;
6: undefined uVar2;
7: code *pcVar3;
8: code **ppcVar4;
9: 
10: if ((*(int *)(param_1 + 0x26) != 0) || (2 < *(int *)((long)param_1 + 0x24) - 0x65U)) {
11: pcVar3 = *param_1;
12: *(int *)(pcVar3 + 0x2c) = *(int *)((long)param_1 + 0x24);
13: ppcVar4 = (code **)*param_1;
14: *(undefined4 *)(pcVar3 + 0x28) = 0x14;
15: (**ppcVar4)(param_1);
16: param_2 = param_2 & 0xffffffff;
17: }
18: (**(code **)(param_1[0x3a] + 0x28))(param_1,param_2,param_4);
19: pcVar3 = *(code **)(param_1[0x3a] + 0x30);
20: puVar1 = param_3 + (ulong)(param_4 - 1) + 1;
21: if (param_4 != 0) {
22: do {
23: uVar2 = *param_3;
24: param_3 = param_3 + 1;
25: (*pcVar3)(param_1,uVar2);
26: } while (param_3 != puVar1);
27: }
28: return;
29: }
30: 
