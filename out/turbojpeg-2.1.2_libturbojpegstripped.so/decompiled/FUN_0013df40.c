1: 
2: void FUN_0013df40(long *param_1,undefined8 param_2)
3: 
4: {
5: int iVar1;
6: long lVar2;
7: char *pcVar3;
8: char *pcVar4;
9: char *pcVar5;
10: 
11: lVar2 = *param_1;
12: iVar1 = *(int *)(lVar2 + 0x28);
13: if ((iVar1 < 1) || (*(int *)(lVar2 + 0x90) < iVar1)) {
14: if ((*(long *)(lVar2 + 0x98) != 0) &&
15: ((*(int *)(lVar2 + 0xa0) <= iVar1 && (iVar1 <= *(int *)(lVar2 + 0xa4))))) {
16: pcVar4 = *(char **)(*(long *)(lVar2 + 0x98) + (long)(iVar1 - *(int *)(lVar2 + 0xa0)) * 8);
17: goto LAB_0013df6d;
18: }
19: }
20: else {
21: pcVar4 = *(char **)(*(long *)(lVar2 + 0x88) + (long)iVar1 * 8);
22: LAB_0013df6d:
23: pcVar3 = pcVar4;
24: if (pcVar4 != (char *)0x0) goto LAB_0013df9b;
25: }
26: *(int *)(lVar2 + 0x2c) = iVar1;
27: pcVar4 = **(char ***)(lVar2 + 0x88);
28: pcVar3 = pcVar4;
29: LAB_0013df9b:
30: do {
31: pcVar5 = pcVar3;
32: if (*pcVar5 == '\0') goto LAB_0013dfa7;
33: pcVar3 = pcVar5 + 1;
34: } while (*pcVar5 != '%');
35: if (pcVar5[1] == 's') {
36: __sprintf_chk(param_2,1,0xffffffffffffffff,pcVar4,lVar2 + 0x2c);
37: return;
38: }
39: LAB_0013dfa7:
40: __sprintf_chk(param_2,1,0xffffffffffffffff,pcVar4,*(undefined4 *)(lVar2 + 0x2c),
41: *(undefined4 *)(lVar2 + 0x30),*(undefined4 *)(lVar2 + 0x34),
42: *(undefined4 *)(lVar2 + 0x38),*(undefined4 *)(lVar2 + 0x3c),
43: *(undefined4 *)(lVar2 + 0x40),*(undefined4 *)(lVar2 + 0x44),
44: *(undefined4 *)(lVar2 + 0x48));
45: return;
46: }
47: 
