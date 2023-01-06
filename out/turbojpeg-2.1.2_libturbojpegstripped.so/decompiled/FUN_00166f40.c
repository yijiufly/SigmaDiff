1: 
2: undefined8 FUN_00166f40(code **param_1)
3: 
4: {
5: long *plVar1;
6: code **ppcVar2;
7: long lVar3;
8: size_t __size;
9: void *__dest;
10: size_t __n;
11: 
12: plVar1 = (long *)param_1[5];
13: if (*(int *)(plVar1 + 10) == 0) {
14: ppcVar2 = (code **)*param_1;
15: *(undefined4 *)(ppcVar2 + 5) = 0x17;
16: (**ppcVar2)();
17: }
18: __n = plVar1[9];
19: __size = __n * 2;
20: __dest = malloc(__size);
21: if (__dest == (void *)0x0) {
22: ppcVar2 = (code **)*param_1;
23: ppcVar2[5] = (code *)0xa00000036;
24: (**ppcVar2)(param_1);
25: __n = plVar1[9];
26: }
27: memcpy(__dest,(void *)plVar1[8],__n);
28: free((void *)plVar1[7]);
29: lVar3 = plVar1[9];
30: plVar1[7] = (long)__dest;
31: plVar1[8] = (long)__dest;
32: plVar1[9] = __size;
33: plVar1[1] = lVar3;
34: *plVar1 = (long)__dest + lVar3;
35: return 1;
36: }
37: 
