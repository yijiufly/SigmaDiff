1: 
2: void FUN_001129c0(code **param_1)
3: 
4: {
5: undefined8 *puVar1;
6: undefined *puVar2;
7: long lVar3;
8: code **ppcVar4;
9: int iVar5;
10: 
11: puVar1 = (undefined8 *)param_1[5];
12: puVar2 = (undefined *)*puVar1;
13: *puVar1 = puVar2 + 1;
14: *puVar2 = 0xff;
15: lVar3 = puVar1[1];
16: puVar1[1] = lVar3 + -1;
17: if (lVar3 + -1 == 0) {
18: iVar5 = (*(code *)puVar1[3])();
19: if (iVar5 == 0) {
20: ppcVar4 = (code **)*param_1;
21: *(undefined4 *)(ppcVar4 + 5) = 0x18;
22: (**ppcVar4)(param_1);
23: }
24: }
25: puVar1 = (undefined8 *)param_1[5];
26: puVar2 = (undefined *)*puVar1;
27: *puVar1 = puVar2 + 1;
28: *puVar2 = 0xd9;
29: lVar3 = puVar1[1];
30: puVar1[1] = lVar3 + -1;
31: if (lVar3 + -1 == 0) {
32: iVar5 = (*(code *)puVar1[3])(param_1);
33: if (iVar5 == 0) {
34: ppcVar4 = (code **)*param_1;
35: *(undefined4 *)(ppcVar4 + 5) = 0x18;
36: /* WARNING: Could not recover jumptable at 0x00112a2b. Too many branches */
37: /* WARNING: Treating indirect jump as call */
38: (**ppcVar4)(param_1);
39: return;
40: }
41: }
42: return;
43: }
44: 
