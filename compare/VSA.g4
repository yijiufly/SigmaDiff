grammar VSA;

expr_
   : expression
   | function
   | expr_ binop expr_
   |  (MINUS)* LPAREN expr_ RPAREN
   |  (MINUS)* '(' expr_ ')'
   |  (NEG)* '(' expr_ ')'
   ;

function
   : 'f' '(' expression (',' expression)* ')'
   | 'f' '(' ')'
   ;

expression
   :  expression  binop expression
   |  (MINUS)* LPAREN expression RPAREN
   |  (MINUS)* '(' expression ')'
   |  (MINUS)* atom
   |  (NEG)* atom
   |  (NEG)* '(' expression ')'
   ;

atom
   : scientific
   | variable
   ;

scientific
   : SCIENTIFIC_NUMBER
   ;

variable
   : VARIABLE
   ;

binop
   : PLUS
   | MINUS
   | TIMES
   | DIV
   | LS
   | RS
   | OR
   | AND
   | XOR
   | REM
   | CON
   ;


VARIABLE
   : VALID_ID_START VALID_ID_CHAR*
   ;


fragment VALID_ID_START
   : ('a' .. 'z') | ('A' .. 'Z')
   ;


fragment VALID_ID_CHAR
   : VALID_ID_START | ('0' .. '9')
   ;

//The NUMBER part gets its potential sign from "(PLUS | MINUS)* atom" in the expression rule
SCIENTIFIC_NUMBER
   : NUMBER (E SIGN? UNSIGNED_INTEGER)?
   ;

fragment NUMBER
   : ('0' .. '9') + ('.' ('0' .. '9') +)?
   ;

fragment UNSIGNED_INTEGER
   : ('0' .. '9')+
   ;


fragment E
   : 'E' | 'e'
   ;


fragment SIGN
   : ('+' | '-')
   ;


LPAREN
   : '['
   ;


RPAREN
   : ']'
   ;


PLUS
   : '+'
   ;


MINUS
   : '-'
   ;


TIMES
   : '*'
   ;


DIV
   : '/'
   ;


LS
   : '<''<'
   ;


RS
   : '>''>'
   ;


OR
   : '|'
   ;


AND
   : '&'
   ;


XOR
   : '^'
   ;
   
CON
   : '#'
   ;

REM
   : '%'
   ;
   
NEG
   : '~'
   ;

WS
   : [ \r\n\t] + -> skip
   ;