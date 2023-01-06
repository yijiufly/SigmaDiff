1: 
2: void FUN_001031b0(code **param_1,int param_2)
3: 
4: {
5: code *pcVar1;
6: code **ppcVar2;
7: 
8: if (*(int *)((long)param_1 + 0x24) != 100) {
9: pcVar1 = *param_1;
10: *(int *)(pcVar1 + 0x2c) = *(int *)((long)param_1 + 0x24);
11: ppcVar2 = (code **)*param_1;
12: *(undefined4 *)(pcVar1 + 0x28) = 0x14;
13: (**ppcVar2)();
14: }
15: if (param_2 != 0) {
16: FUN_00102e40(param_1,0);
17: }
18: (**(code **)(*param_1 + 0x20))(param_1);
19: (**(code **)(param_1[5] + 0x10))(param_1);
20: FUN_00112680(param_1);
21: (**(code **)param_1[0x36])(param_1);
22: *(undefined4 *)(param_1 + 0x26) = 0;
23: *(uint *)((long)param_1 + 0x24) = 0x66 - (uint)(*(int *)(param_1 + 0x20) == 0);
24: return;
25: }
26: 
