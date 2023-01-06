1: 
2: void FUN_00102e90(code **param_1,undefined4 param_2,undefined *param_3,int param_4)
3: 
4: {
5: undefined *puVar1;
6: undefined uVar2;
7: int iVar3;
8: code **ppcVar4;
9: code *pcVar5;
10: 
11: iVar3 = *(int *)((long)param_1 + 0x24);
12: if ((*(int *)(param_1 + 0x26) != 0) || (2 < iVar3 - 0x65U)) {
13: ppcVar4 = (code **)*param_1;
14: *(undefined4 *)(ppcVar4 + 5) = 0x14;
15: *(int *)((long)ppcVar4 + 0x2c) = iVar3;
16: (**ppcVar4)(param_1);
17: }
18: (**(code **)(param_1[0x3a] + 0x28))(param_1,param_2,param_4);
19: pcVar5 = *(code **)(param_1[0x3a] + 0x30);
20: if (param_4 != 0) {
21: puVar1 = param_3 + (ulong)(param_4 - 1) + 1;
22: do {
23: uVar2 = *param_3;
24: param_3 = param_3 + 1;
25: (*pcVar5)(param_1,uVar2);
26: } while (param_3 != puVar1);
27: }
28: return;
29: }
30: 
