1: 
2: void FUN_0016bc40(code **param_1,long param_2)
3: 
4: {
5: code **ppcVar1;
6: int iVar2;
7: 
8: fflush(*(FILE **)(param_2 + 0x20));
9: iVar2 = ferror(*(FILE **)(param_2 + 0x20));
10: if (iVar2 != 0) {
11: ppcVar1 = (code **)*param_1;
12: *(undefined4 *)(ppcVar1 + 5) = 0x25;
13: /* WARNING: Could not recover jumptable at 0x0016bc79. Too many branches */
14: /* WARNING: Treating indirect jump as call */
15: (**ppcVar1)(param_1);
16: return;
17: }
18: return;
19: }
20: 
