1: 
2: void FUN_0011c360(code **param_1)
3: 
4: {
5: long *plVar1;
6: undefined8 *puVar2;
7: undefined *puVar3;
8: code **ppcVar4;
9: int iVar5;
10: 
11: puVar2 = (undefined8 *)param_1[5];
12: puVar3 = (undefined *)*puVar2;
13: *puVar2 = puVar3 + 1;
14: *puVar3 = 0xff;
15: plVar1 = puVar2 + 1;
16: *plVar1 = *plVar1 + -1;
17: if (*plVar1 == 0) {
18: iVar5 = (*(code *)puVar2[3])();
19: if (iVar5 == 0) {
20: ppcVar4 = (code **)*param_1;
21: *(undefined4 *)(ppcVar4 + 5) = 0x18;
22: (**ppcVar4)(param_1);
23: }
24: }
25: puVar2 = (undefined8 *)param_1[5];
26: puVar3 = (undefined *)*puVar2;
27: *puVar2 = puVar3 + 1;
28: *puVar3 = 0xd9;
29: plVar1 = puVar2 + 1;
30: *plVar1 = *plVar1 + -1;
31: if (*plVar1 == 0) {
32: iVar5 = (*(code *)puVar2[3])(param_1);
33: if (iVar5 == 0) {
34: ppcVar4 = (code **)*param_1;
35: *(undefined4 *)(ppcVar4 + 5) = 0x18;
36: /* WARNING: Could not recover jumptable at 0x0011c3c5. Too many branches */
37: /* WARNING: Treating indirect jump as call */
38: (**ppcVar4)(param_1);
39: return;
40: }
41: }
42: return;
43: }
44: 
