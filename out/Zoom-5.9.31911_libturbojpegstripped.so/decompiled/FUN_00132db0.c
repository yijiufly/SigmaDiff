1: 
2: void FUN_00132db0(long *param_1,char *param_2)
3: 
4: {
5: int iVar1;
6: long lVar2;
7: char *pcVar3;
8: char *pcVar4;
9: char *__format;
10: 
11: lVar2 = *param_1;
12: iVar1 = *(int *)(lVar2 + 0x28);
13: if ((iVar1 < 1) || (*(int *)(lVar2 + 0x90) < iVar1)) {
14: if ((*(long *)(lVar2 + 0x98) != 0) &&
15: ((*(int *)(lVar2 + 0xa0) <= iVar1 && (iVar1 <= *(int *)(lVar2 + 0xa4))))) {
16: __format = *(char **)(*(long *)(lVar2 + 0x98) + (long)(iVar1 - *(int *)(lVar2 + 0xa0)) * 8);
17: goto LAB_00132de2;
18: }
19: }
20: else {
21: __format = *(char **)(*(long *)(lVar2 + 0x88) + (long)iVar1 * 8);
22: LAB_00132de2:
23: pcVar3 = __format;
24: if (__format != (char *)0x0) goto LAB_00132dfb;
25: }
26: *(int *)(lVar2 + 0x2c) = iVar1;
27: __format = **(char ***)(lVar2 + 0x88);
28: pcVar3 = __format;
29: LAB_00132dfb:
30: do {
31: pcVar4 = pcVar3;
32: if (*pcVar4 == '\0') goto LAB_00132e07;
33: pcVar3 = pcVar4 + 1;
34: } while (*pcVar4 != '%');
35: if (pcVar4[1] == 's') {
36: sprintf(param_2,__format,lVar2 + 0x2c);
37: return;
38: }
39: LAB_00132e07:
40: sprintf(param_2,__format,(ulong)*(uint *)(lVar2 + 0x2c),(ulong)*(uint *)(lVar2 + 0x30),
41: (ulong)*(uint *)(lVar2 + 0x34),(ulong)*(uint *)(lVar2 + 0x38),
42: *(undefined4 *)(lVar2 + 0x3c),*(undefined4 *)(lVar2 + 0x40),*(undefined4 *)(lVar2 + 0x44),
43: *(undefined4 *)(lVar2 + 0x48));
44: return;
45: }
46: 
