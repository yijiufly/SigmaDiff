1: 
2: void FUN_0011e770(code **param_1)
3: 
4: {
5: code *pcVar1;
6: code **ppcVar2;
7: int iVar3;
8: size_t sVar4;
9: size_t __n;
10: 
11: pcVar1 = param_1[5];
12: __n = 0x1000 - *(long *)(pcVar1 + 8);
13: if (__n != 0) {
14: sVar4 = fwrite(*(void **)(pcVar1 + 0x30),1,__n,*(FILE **)(pcVar1 + 0x28));
15: if (sVar4 != __n) {
16: ppcVar2 = (code **)*param_1;
17: *(undefined4 *)(ppcVar2 + 5) = 0x25;
18: (**ppcVar2)(param_1);
19: }
20: }
21: fflush(*(FILE **)(pcVar1 + 0x28));
22: iVar3 = ferror(*(FILE **)(pcVar1 + 0x28));
23: if (iVar3 == 0) {
24: return;
25: }
26: ppcVar2 = (code **)*param_1;
27: *(undefined4 *)(ppcVar2 + 5) = 0x25;
28: /* WARNING: Could not recover jumptable at 0x0011e7bd. Too many branches */
29: /* WARNING: Treating indirect jump as call */
30: (**ppcVar2)(param_1);
31: return;
32: }
33: 
