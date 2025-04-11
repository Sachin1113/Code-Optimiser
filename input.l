%{
#include <stdio.h>
%}

DIGIT  [0-9]
ALPHA  [a-zA-Z]

%%
[a-zA-Z]+ { printf("WORD\n"); }
[a-zA-Z0-9]+ { printf("ALPHANUM\n"); }
[0-9]+    { printf("NUMBER\n"); }
[a-z]+    { printf("WORD\n"); }
[A-Z]+    { printf("WORD\n"); }
[0-9]+    { printf("NUMBER\n"); }
[A-Z0-9]+ { printf("ALPHANUM\n"); }
    
    [ \t\n]+  { /* Ignore whitespace */ }
.  { printf("UNKNOWN\n"); } // Catch-all for any other character


%%
int main() {
    yylex();
    return 0;
}
