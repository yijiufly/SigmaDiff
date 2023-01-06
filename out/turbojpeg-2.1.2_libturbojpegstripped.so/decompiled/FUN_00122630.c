1: 
2: void FUN_00122630(code **param_1,int param_2)
3: 
4: {
5: undefined4 uVar1;
6: code *pcVar2;
7: code **ppcVar3;
8: 
9: pcVar2 = param_1[0x38];
10: if (param_2 != 0) {
11: ppcVar3 = (code **)*param_1;
12: *(undefined4 *)(ppcVar3 + 5) = 4;
13: (**ppcVar3)();
14: }
15: uVar1 = *(undefined4 *)((long)param_1 + 0x34);
16: *(undefined8 *)(pcVar2 + 100) = 0;
17: *(undefined4 *)(pcVar2 + 0x60) = uVar1;
18: *(int *)(pcVar2 + 0x6c) = *(int *)((long)param_1 + 0x13c) * 2;
19: return;
20: }
21: 
