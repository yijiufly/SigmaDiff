1: 
2: void FUN_00131920(long param_1,int param_2)
3: 
4: {
5: undefined4 uVar1;
6: long lVar2;
7: undefined4 uVar3;
8: code **ppcVar4;
9: code *pcVar5;
10: 
11: ppcVar4 = (code **)(***(code ***)(param_1 + 8))(param_1,1,0x30);
12: *(code ***)(param_1 + 0x238) = ppcVar4;
13: ppcVar4[2] = (code *)0x0;
14: ppcVar4[3] = (code *)0x0;
15: *ppcVar4 = FUN_00131600;
16: if (*(int *)(param_1 + 0x6c) != 0) {
17: uVar1 = *(undefined4 *)(param_1 + 0x19c);
18: lVar2 = *(long *)(param_1 + 8);
19: *(undefined4 *)(ppcVar4 + 4) = uVar1;
20: if (param_2 != 0) {
21: pcVar5 = *(code **)(lVar2 + 0x20);
22: uVar3 = FUN_0013be30(*(undefined4 *)(param_1 + 0x8c),uVar1);
23: pcVar5 = (code *)(*pcVar5)(param_1,1,0,*(int *)(param_1 + 0x90) * *(int *)(param_1 + 0x88),
24: uVar3,uVar1);
25: ppcVar4[2] = pcVar5;
26: return;
27: }
28: pcVar5 = (code *)(**(code **)(lVar2 + 0x10))
29: (param_1,1,*(int *)(param_1 + 0x90) * *(int *)(param_1 + 0x88),uVar1)
30: ;
31: ppcVar4[3] = pcVar5;
32: }
33: return;
34: }
35: 
