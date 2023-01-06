1: 
2: undefined8 FUN_00169540(code **param_1,long param_2)
3: 
4: {
5: code **ppcVar1;
6: size_t sVar2;
7: 
8: sVar2 = fread(*(void **)(param_2 + 0x30),1,*(size_t *)(param_2 + 0x40),*(FILE **)(param_2 + 0x18))
9: ;
10: if (*(size_t *)(param_2 + 0x40) != sVar2) {
11: ppcVar1 = (code **)*param_1;
12: *(undefined4 *)(ppcVar1 + 5) = 0x2b;
13: (**ppcVar1)(param_1);
14: }
15: return 1;
16: }
17: 
