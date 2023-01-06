1: 
2: void FUN_00154ef0(code **param_1,long param_2)
3: 
4: {
5: code **ppcVar1;
6: int iVar2;
7: 
8: fflush(*(FILE **)(param_2 + 0x20));
9: iVar2 = ferror(*(FILE **)(param_2 + 0x20));
10: if (iVar2 == 0) {
11: return;
12: }
13: ppcVar1 = (code **)*param_1;
14: *(undefined4 *)(ppcVar1 + 5) = 0x25;
15: /* WARNING: Could not recover jumptable at 0x00154f37. Too many branches */
16: /* WARNING: Treating indirect jump as call */
17: (**ppcVar1)(param_1);
18: return;
19: }
20: 
