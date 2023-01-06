1: 
2: void FUN_0011e500(code **param_1,int param_2)
3: 
4: {
5: int iVar1;
6: code *pcVar2;
7: code **ppcVar3;
8: 
9: iVar1 = *(int *)((long)param_1 + 0x24);
10: if ((iVar1 != 0xcc) && (iVar1 != 0xcf)) {
11: pcVar2 = *param_1;
12: *(int *)(pcVar2 + 0x2c) = iVar1;
13: ppcVar3 = (code **)*param_1;
14: *(undefined4 *)(pcVar2 + 0x28) = 0x14;
15: (**ppcVar3)();
16: }
17: if (param_2 < 1) {
18: param_2 = 1;
19: }
20: if ((*(int *)(param_1[0x48] + 0x24) != 0) && (*(int *)((long)param_1 + 0xac) < param_2)) {
21: param_2 = *(int *)((long)param_1 + 0xac);
22: }
23: *(int *)((long)param_1 + 0xb4) = param_2;
24: FUN_0011d5b0(param_1);
25: return;
26: }
27: 
