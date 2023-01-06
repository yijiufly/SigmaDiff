1: 
2: void FUN_0016bc90(code **param_1,long param_2)
3: 
4: {
5: uint uVar1;
6: code **ppcVar2;
7: ulong uVar3;
8: 
9: uVar1 = *(uint *)(param_1 + 8);
10: if (uVar1 < 0x10) {
11: uVar3 = 1 << ((byte)uVar1 & 0x3f);
12: if ((uVar3 & 0xffd4) != 0) {
13: if (((9 < uVar1 - 6) && (uVar1 != 2)) && (*(int *)((long)param_1 + 0x6c) != 0)) {
14: ppcVar2 = (code **)*param_1;
15: *(undefined4 *)(ppcVar2 + 5) = 0x3f6;
16: (**ppcVar2)();
17: }
18: __fprintf_chk(*(undefined8 *)(param_2 + 0x20),1,"P6\n%ld %ld\n%d\n",
19: *(undefined4 *)(param_1 + 0x11),*(undefined4 *)((long)param_1 + 0x8c),0xff);
20: return;
21: }
22: if ((uVar3 & 2) != 0) {
23: __fprintf_chk(*(undefined8 *)(param_2 + 0x20),1,"P5\n%ld %ld\n%d\n",
24: *(undefined4 *)(param_1 + 0x11),*(undefined4 *)((long)param_1 + 0x8c),0xff);
25: return;
26: }
27: }
28: param_1 = (code **)*param_1;
29: *(undefined4 *)(param_1 + 5) = 0x3f6;
30: /* WARNING: Could not recover jumptable at 0x0016bcb5. Too many branches */
31: /* WARNING: Treating indirect jump as call */
32: (**param_1)();
33: return;
34: }
35: 
