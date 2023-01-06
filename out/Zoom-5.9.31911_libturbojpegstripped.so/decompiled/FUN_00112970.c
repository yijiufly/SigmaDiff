1: 
2: void FUN_00112970(code **param_1,undefined param_2)
3: 
4: {
5: long *plVar1;
6: undefined *puVar2;
7: long lVar3;
8: code **ppcVar4;
9: int iVar5;
10: 
11: plVar1 = (long *)param_1[5];
12: puVar2 = (undefined *)*plVar1;
13: *plVar1 = (long)(puVar2 + 1);
14: *puVar2 = param_2;
15: lVar3 = plVar1[1];
16: plVar1[1] = lVar3 + -1;
17: if (lVar3 + -1 == 0) {
18: iVar5 = (*(code *)plVar1[3])(param_1);
19: if (iVar5 == 0) {
20: ppcVar4 = (code **)*param_1;
21: *(undefined4 *)(ppcVar4 + 5) = 0x18;
22: /* WARNING: Could not recover jumptable at 0x001129bb. Too many branches */
23: /* WARNING: Treating indirect jump as call */
24: (**ppcVar4)(param_1);
25: return;
26: }
27: }
28: return;
29: }
30: 
