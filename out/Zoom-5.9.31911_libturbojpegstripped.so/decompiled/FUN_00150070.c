1: 
2: undefined8 FUN_00150070(code **param_1)
3: 
4: {
5: long *plVar1;
6: long lVar2;
7: code **ppcVar3;
8: code *pcVar4;
9: size_t __size;
10: void *__dest;
11: size_t __n;
12: 
13: plVar1 = (long *)param_1[5];
14: if (*(int *)(plVar1 + 10) == 0) {
15: ppcVar3 = (code **)*param_1;
16: *(undefined4 *)(ppcVar3 + 5) = 0x17;
17: (**ppcVar3)();
18: }
19: __n = plVar1[9];
20: __size = __n * 2;
21: __dest = malloc(__size);
22: if (__dest == (void *)0x0) {
23: pcVar4 = *param_1;
24: *(undefined4 *)(pcVar4 + 0x28) = 0x36;
25: *(undefined4 *)(pcVar4 + 0x2c) = 10;
26: (**(code **)*param_1)(param_1);
27: __n = plVar1[9];
28: }
29: memcpy(__dest,(void *)plVar1[8],__n);
30: if ((void *)plVar1[7] != (void *)0x0) {
31: free((void *)plVar1[7]);
32: }
33: lVar2 = plVar1[9];
34: plVar1[7] = (long)__dest;
35: plVar1[8] = (long)__dest;
36: plVar1[9] = __size;
37: plVar1[1] = lVar2;
38: *plVar1 = (long)__dest + lVar2;
39: return 1;
40: }
41: 
