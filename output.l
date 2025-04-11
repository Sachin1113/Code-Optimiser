%%
// Literals
[a-zA-Z0-9]+ | [A-Z0-9]+ { printf("ALPHANUM\n"); }
\d+ | \d+ { printf("NUMBER\n"); }
// Operators
[A-Za-z]+ | [a-z]+ | [A-Z]+ { printf("WORD\n"); }
// Others
. { printf("UNKNOWN\n"); }
%%
int main() {
    yylex();
    return 0;
}
