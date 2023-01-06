1: 
2: void FUN_0011c310(code **param_1,undefined param_2)
3: 
4: {
5: long *plVar1;
6: long *plVar2;
7: undefined *puVar3;
8: code **ppcVar4;
9: int iVar5;
10: 
11: plVar2 = (long *)param_1[5];
12: puVar3 = (undefined *)*plVar2;
13: *plVar2 = (long)(puVar3 + 1);
14: *puVar3 = param_2;
15: plVar1 = plVar2 + 1;
16: *plVar1 = *plVar1 + -1;
17: if (*plVar1 != 0) {
18: return;
19: }
20: iVar5 = (*(code *)plVar2[3])();
21: if (iVar5 == 0) {
22: ppcVar4 = (code **)*param_1;
23: *(undefined4 *)(ppcVar4 + 5) = 0x18;
24: /* WARNING: Could not recover jumptable at 0x0011c344. Too many branches */
25: /* WARNING: Treating indirect jump as call */
26: (**ppcVar4)(param_1);
27: return;
28: }
29: return;
30: }
31: 
