1: 
2: void FUN_00154e20(code **param_1,long param_2)
3: 
4: {
5: int iVar1;
6: code **ppcVar2;
7: ulong uVar3;
8: 
9: iVar1 = *(int *)(param_1 + 8);
10: if (iVar1 - 1U < 0xf) {
11: uVar3 = 1 << ((byte)(iVar1 - 1U) & 0x3f);
12: if ((uVar3 & 0x7fea) != 0) {
13: if (((9 < iVar1 - 6U) && (iVar1 != 2)) && (*(int *)((long)param_1 + 0x6c) != 0)) {
14: ppcVar2 = (code **)*param_1;
15: *(undefined4 *)(ppcVar2 + 5) = 0x3f6;
16: (**ppcVar2)();
17: }
18: fprintf(*(FILE **)(param_2 + 0x20),"P6\n%ld %ld\n%d\n",(ulong)*(uint *)(param_1 + 0x11),
19: (ulong)*(uint *)((long)param_1 + 0x8c),0xff);
20: return;
21: }
22: if ((uVar3 & 1) != 0) {
23: fprintf(*(FILE **)(param_2 + 0x20),"P5\n%ld %ld\n%d\n",(ulong)*(uint *)(param_1 + 0x11),
24: (ulong)*(uint *)((long)param_1 + 0x8c),0xff);
25: return;
26: }
27: }
28: ppcVar2 = (code **)*param_1;
29: *(undefined4 *)(ppcVar2 + 5) = 0x3f6;
30: /* WARNING: Could not recover jumptable at 0x00154e5d. Too many branches */
31: /* WARNING: Treating indirect jump as call */
32: (**ppcVar2)(param_1);
33: return;
34: }
35: 
