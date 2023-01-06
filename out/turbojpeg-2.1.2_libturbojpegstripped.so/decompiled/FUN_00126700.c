1: 
2: undefined8 FUN_00126700(code **param_1)
3: 
4: {
5: undefined8 *puVar1;
6: code **ppcVar2;
7: size_t sVar3;
8: 
9: puVar1 = (undefined8 *)param_1[5];
10: sVar3 = fwrite((void *)puVar1[6],1,0x1000,(FILE *)puVar1[5]);
11: if (sVar3 != 0x1000) {
12: ppcVar2 = (code **)*param_1;
13: *(undefined4 *)(ppcVar2 + 5) = 0x25;
14: (**ppcVar2)(param_1);
15: }
16: puVar1[1] = 0x1000;
17: *puVar1 = puVar1[6];
18: return 1;
19: }
20: 
