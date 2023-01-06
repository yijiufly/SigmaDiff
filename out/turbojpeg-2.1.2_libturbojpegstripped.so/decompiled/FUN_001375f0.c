1: 
2: void FUN_001375f0(code **param_1)
3: 
4: {
5: int iVar1;
6: code *pcVar2;
7: code **ppcVar3;
8: code *pcVar4;
9: 
10: iVar1 = *(int *)((long)param_1 + 0x24);
11: pcVar2 = param_1[0x44];
12: if (iVar1 != 0xcf) {
13: ppcVar3 = (code **)*param_1;
14: *(undefined4 *)(ppcVar3 + 5) = 0x14;
15: *(int *)((long)ppcVar3 + 0x2c) = iVar1;
16: (**ppcVar3)();
17: }
18: if (((*(int *)((long)param_1 + 0x6c) != 0) && (*(int *)(param_1 + 0x10) != 0)) &&
19: (param_1[0x14] != (code *)0x0)) {
20: pcVar4 = *(code **)(pcVar2 + 0x88);
21: param_1[0x4e] = pcVar4;
22: (**(code **)(pcVar4 + 0x18))(param_1);
23: *(undefined4 *)(pcVar2 + 0x10) = 0;
24: return;
25: }
26: ppcVar3 = (code **)*param_1;
27: *(undefined4 *)(ppcVar3 + 5) = 0x2e;
28: /* WARNING: Could not recover jumptable at 0x00137637. Too many branches */
29: /* WARNING: Treating indirect jump as call */
30: (**ppcVar3)(param_1);
31: return;
32: }
33: 
