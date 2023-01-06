1: 
2: undefined8 FUN_001267f0(code **param_1)
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
13: __n = plVar1[9];
14: __size = __n * 2;
15: __dest = malloc(__size);
16: if (__dest == (void *)0x0) {
17: ppcVar2 = (code **)*param_1;
18: ppcVar2[5] = (code *)0xa00000036;
19: (**ppcVar2)(param_1);
20: __n = plVar1[9];
21: }
22: memcpy(__dest,(void *)plVar1[8],__n);
23: free((void *)plVar1[7]);
24: lVar3 = plVar1[9];
25: plVar1[7] = (long)__dest;
26: plVar1[8] = (long)__dest;
27: plVar1[9] = __size;
28: plVar1[1] = lVar3;
29: *plVar1 = (long)__dest + lVar3;
30: return 1;
31: }
32: 
