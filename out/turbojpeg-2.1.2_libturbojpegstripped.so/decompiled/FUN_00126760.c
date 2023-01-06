1: 
2: void FUN_00126760(code **param_1)
3: 
4: {
5: code *pcVar1;
6: code **ppcVar2;
7: int iVar3;
8: size_t sVar4;
9: size_t __n;
10: FILE *__s;
11: 
12: pcVar1 = param_1[5];
13: __n = 0x1000 - *(long *)(pcVar1 + 8);
14: __s = *(FILE **)(pcVar1 + 0x28);
15: if (__n != 0) {
16: sVar4 = fwrite(*(void **)(pcVar1 + 0x30),1,__n,__s);
17: if (sVar4 != __n) {
18: ppcVar2 = (code **)*param_1;
19: *(undefined4 *)(ppcVar2 + 5) = 0x25;
20: (**ppcVar2)(param_1);
21: }
22: __s = *(FILE **)(pcVar1 + 0x28);
23: }
24: fflush(__s);
25: iVar3 = ferror(*(FILE **)(pcVar1 + 0x28));
26: if (iVar3 != 0) {
27: ppcVar2 = (code **)*param_1;
28: *(undefined4 *)(ppcVar2 + 5) = 0x25;
29: /* WARNING: Could not recover jumptable at 0x001267a1. Too many branches */
30: /* WARNING: Treating indirect jump as call */
31: (**ppcVar2)(param_1);
32: return;
33: }
34: return;
35: }
36: 
