1: 
2: undefined8 FUN_0011ea70(code **param_1)
3: 
4: {
5: undefined8 *puVar1;
6: code *pcVar2;
7: code **ppcVar3;
8: size_t sVar4;
9: 
10: puVar1 = (undefined8 *)param_1[5];
11: sVar4 = fread((void *)puVar1[8],1,0x1000,(FILE *)puVar1[7]);
12: if (sVar4 == 0) {
13: if (*(int *)(puVar1 + 9) != 0) {
14: ppcVar3 = (code **)*param_1;
15: *(undefined4 *)(ppcVar3 + 5) = 0x2a;
16: (**ppcVar3)(param_1);
17: }
18: pcVar2 = *param_1;
19: *(undefined4 *)(pcVar2 + 0x28) = 0x78;
20: (**(code **)(pcVar2 + 8))(param_1,0xffffffff);
21: *(undefined *)puVar1[8] = 0xff;
22: *(undefined *)(puVar1[8] + 1) = 0xd9;
23: sVar4 = 2;
24: }
25: puVar1[1] = sVar4;
26: *(undefined4 *)(puVar1 + 9) = 0;
27: *puVar1 = puVar1[8];
28: return 1;
29: }
30: 
