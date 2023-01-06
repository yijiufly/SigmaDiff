1: 
2: void FUN_0012c860(code **param_1)
3: 
4: {
5: code *pcVar1;
6: code *pcVar2;
7: code **ppcVar3;
8: 
9: pcVar1 = param_1[0x44];
10: if (*(int *)((long)param_1 + 0x24) != 0xcf) {
11: pcVar2 = *param_1;
12: *(int *)(pcVar2 + 0x2c) = *(int *)((long)param_1 + 0x24);
13: ppcVar3 = (code **)*param_1;
14: *(undefined4 *)(pcVar2 + 0x28) = 0x14;
15: (**ppcVar3)();
16: }
17: if (((*(int *)((long)param_1 + 0x6c) != 0) && (*(int *)(param_1 + 0x10) != 0)) &&
18: (param_1[0x14] != (code *)0x0)) {
19: pcVar2 = *(code **)(pcVar1 + 0x80);
20: param_1[0x4e] = pcVar2;
21: (**(code **)(pcVar2 + 0x18))(param_1);
22: *(undefined4 *)(pcVar1 + 0x10) = 0;
23: return;
24: }
25: ppcVar3 = (code **)*param_1;
26: *(undefined4 *)(ppcVar3 + 5) = 0x2e;
27: /* WARNING: Could not recover jumptable at 0x0012c8e6. Too many branches */
28: /* WARNING: Treating indirect jump as call */
29: (**ppcVar3)(param_1);
30: return;
31: }
32: 
