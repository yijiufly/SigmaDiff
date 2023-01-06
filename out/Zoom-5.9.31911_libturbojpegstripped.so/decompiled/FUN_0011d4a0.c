1: 
2: undefined4 FUN_0011d4a0(code **param_1)
3: 
4: {
5: code *pcVar1;
6: code **ppcVar2;
7: 
8: if (8 < *(int *)((long)param_1 + 0x24) - 0xcaU) {
9: pcVar1 = *param_1;
10: *(int *)(pcVar1 + 0x2c) = *(int *)((long)param_1 + 0x24);
11: ppcVar2 = (code **)*param_1;
12: *(undefined4 *)(pcVar1 + 0x28) = 0x14;
13: (**ppcVar2)();
14: }
15: return *(undefined4 *)(param_1[0x48] + 0x20);
16: }
17: 
