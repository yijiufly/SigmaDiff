1: 
2: undefined8 FUN_00126ac0(code **param_1)
3: 
4: {
5: undefined8 *puVar1;
6: size_t sVar2;
7: code **ppcVar3;
8: 
9: puVar1 = (undefined8 *)param_1[5];
10: sVar2 = fread((void *)puVar1[8],1,0x1000,(FILE *)puVar1[7]);
11: if (sVar2 == 0) {
12: ppcVar3 = (code **)*param_1;
13: if (*(int *)(puVar1 + 9) != 0) {
14: *(undefined4 *)(ppcVar3 + 5) = 0x2a;
15: (**ppcVar3)(param_1);
16: ppcVar3 = (code **)*param_1;
17: }
18: *(undefined4 *)(ppcVar3 + 5) = 0x78;
19: (*ppcVar3[1])(param_1,0xffffffff);
20: *(undefined *)puVar1[8] = 0xff;
21: *(undefined *)(puVar1[8] + 1) = 0xd9;
22: sVar2 = 2;
23: }
24: puVar1[1] = sVar2;
25: *(undefined4 *)(puVar1 + 9) = 0;
26: *puVar1 = puVar1[8];
27: return 1;
28: }
29: 
