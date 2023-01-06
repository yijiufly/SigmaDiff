1: 
2: void FUN_00111ae0(code **param_1,int param_2)
3: 
4: {
5: uint uVar1;
6: code *pcVar2;
7: bool bVar3;
8: undefined4 uVar4;
9: int iVar5;
10: code *pcVar6;
11: ulong uVar7;
12: code *pcVar8;
13: long lVar9;
14: uint uVar10;
15: ulong uVar11;
16: undefined8 *puVar12;
17: undefined8 *puVar13;
18: bool bVar14;
19: byte bVar15;
20: 
21: bVar15 = 0;
22: pcVar8 = FUN_001115b0;
23: pcVar2 = param_1[0x3e];
24: if (param_2 != 0) {
25: pcVar8 = FUN_001122d0;
26: }
27: pcVar6 = FUN_00108900;
28: if (param_2 != 0) {
29: pcVar6 = FUN_00108530;
30: }
31: *(code **)(pcVar2 + 0x10) = pcVar8;
32: lVar9 = 0;
33: *(code **)(pcVar2 + 8) = pcVar6;
34: uVar4 = FUN_001689b0();
35: iVar5 = *(int *)((long)param_1 + 0x144);
36: *(undefined4 *)(pcVar2 + 0xc0) = uVar4;
37: if (0 < iVar5) {
38: do {
39: uVar10 = *(uint *)(param_1[lVar9 + 0x29] + 0x14);
40: uVar1 = *(uint *)(param_1[lVar9 + 0x29] + 0x18);
41: if (param_2 == 0) {
42: FUN_00111780(param_1,1,(long)(int)uVar10,pcVar2 + (long)(int)uVar10 * 8 + 0x40);
43: FUN_00111780(param_1,0,(long)(int)uVar1 & 0xffffffff,pcVar2 + (long)(int)uVar1 * 8 + 0x60);
44: }
45: else {
46: if (3 < uVar10) {
47: *(undefined4 *)(*param_1 + 0x28) = 0x32;
48: *(uint *)(*param_1 + 0x2c) = uVar10;
49: (**(code **)*param_1)(param_1);
50: }
51: if (uVar1 < 4) {
52: pcVar8 = pcVar2 + (long)(int)uVar10 * 8;
53: puVar13 = *(undefined8 **)(pcVar8 + 0x80);
54: if (puVar13 == (undefined8 *)0x0) goto LAB_00111d05;
55: LAB_00111b8a:
56: puVar12 = puVar13;
57: if (((ulong)puVar13 & 1) != 0) goto LAB_00111d40;
58: LAB_00111b9a:
59: uVar11 = 0x808;
60: bVar14 = false;
61: iVar5 = 0x808;
62: bVar3 = false;
63: if (((ulong)puVar12 & 2) != 0) goto LAB_00111d58;
64: LAB_00111ba4:
65: uVar10 = (uint)uVar11;
66: }
67: else {
68: pcVar8 = *param_1;
69: *(undefined4 *)(pcVar8 + 0x28) = 0x32;
70: *(uint *)(pcVar8 + 0x2c) = uVar1;
71: (**(code **)*param_1)(param_1);
72: pcVar8 = pcVar2 + (long)(int)uVar10 * 8;
73: puVar13 = *(undefined8 **)(pcVar8 + 0x80);
74: if (puVar13 != (undefined8 *)0x0) goto LAB_00111b8a;
75: LAB_00111d05:
76: puVar13 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x808);
77: *(undefined8 **)(pcVar8 + 0x80) = puVar13;
78: puVar12 = puVar13;
79: if (((ulong)puVar13 & 1) == 0) goto LAB_00111b9a;
80: LAB_00111d40:
81: puVar12 = (undefined8 *)((long)puVar13 + 1);
82: *(undefined *)puVar13 = 0;
83: uVar11 = 0x807;
84: bVar14 = true;
85: iVar5 = 0x807;
86: bVar3 = true;
87: if (((ulong)puVar12 & 2) == 0) goto LAB_00111ba4;
88: LAB_00111d58:
89: bVar14 = bVar3;
90: uVar10 = iVar5 - 2;
91: uVar11 = (ulong)uVar10;
92: *(undefined2 *)puVar12 = 0;
93: puVar12 = (undefined8 *)((long)puVar12 + 2);
94: }
95: if (((ulong)puVar12 & 4) != 0) {
96: *(undefined4 *)puVar12 = 0;
97: uVar11 = (ulong)(uVar10 - 4);
98: puVar12 = (undefined8 *)((long)puVar12 + 4);
99: }
100: uVar7 = uVar11 >> 3;
101: while (uVar7 != 0) {
102: uVar7 = uVar7 - 1;
103: *puVar12 = 0;
104: puVar12 = puVar12 + (ulong)bVar15 * -2 + 1;
105: }
106: if ((uVar11 & 4) != 0) {
107: *(undefined4 *)puVar12 = 0;
108: puVar12 = (undefined8 *)((long)puVar12 + 4);
109: }
110: puVar13 = puVar12;
111: if ((uVar11 & 2) != 0) {
112: puVar13 = (undefined8 *)((long)puVar12 + 2);
113: *(undefined2 *)puVar12 = 0;
114: }
115: if (bVar14) {
116: *(undefined *)puVar13 = 0;
117: }
118: puVar13 = *(undefined8 **)(pcVar2 + (long)(int)uVar1 * 8 + 0xa0);
119: if (puVar13 == (undefined8 *)0x0) {
120: puVar13 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x808);
121: *(undefined8 **)(pcVar2 + (long)(int)uVar1 * 8 + 0xa0) = puVar13;
122: }
123: bVar14 = ((ulong)puVar13 & 1) != 0;
124: uVar11 = 0x808;
125: if (bVar14) {
126: *(undefined *)puVar13 = 0;
127: puVar13 = (undefined8 *)((long)puVar13 + 1);
128: uVar11 = 0x807;
129: }
130: puVar12 = puVar13;
131: if (((ulong)puVar13 & 2) != 0) {
132: puVar12 = (undefined8 *)((long)puVar13 + 2);
133: uVar11 = (ulong)((int)uVar11 - 2);
134: *(undefined2 *)puVar13 = 0;
135: }
136: if (((ulong)puVar12 & 4) != 0) {
137: *(undefined4 *)puVar12 = 0;
138: uVar11 = (ulong)((int)uVar11 - 4);
139: puVar12 = (undefined8 *)((long)puVar12 + 4);
140: }
141: uVar7 = uVar11 >> 3;
142: while (uVar7 != 0) {
143: uVar7 = uVar7 - 1;
144: *puVar12 = 0;
145: puVar12 = puVar12 + (ulong)bVar15 * -2 + 1;
146: }
147: if ((uVar11 & 4) != 0) {
148: *(undefined4 *)puVar12 = 0;
149: puVar12 = (undefined8 *)((long)puVar12 + 4);
150: }
151: puVar13 = puVar12;
152: if ((uVar11 & 2) != 0) {
153: puVar13 = (undefined8 *)((long)puVar12 + 2);
154: *(undefined2 *)puVar12 = 0;
155: }
156: if (bVar14) {
157: *(undefined *)puVar13 = 0;
158: }
159: }
160: *(undefined4 *)(pcVar2 + lVar9 * 4 + 0x24) = 0;
161: iVar5 = (int)lVar9 + 1;
162: lVar9 = lVar9 + 1;
163: } while (*(int *)((long)param_1 + 0x144) != iVar5 && iVar5 <= *(int *)((long)param_1 + 0x144));
164: }
165: uVar4 = *(undefined4 *)(param_1 + 0x23);
166: *(undefined8 *)(pcVar2 + 0x18) = 0;
167: *(undefined4 *)(pcVar2 + 0x20) = 0;
168: *(undefined4 *)(pcVar2 + 0x3c) = 0;
169: *(undefined4 *)(pcVar2 + 0x38) = uVar4;
170: return;
171: }
172: 
