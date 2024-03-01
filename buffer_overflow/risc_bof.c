void not_called() {
    printf("Enjoy your shell!\n");
    system("/bin/bash");
}


int test_empty() {
    printf("Empty function\n");
    return 1;
}
void vulnerable_function(char* string) {
    char buffer[100];
    test_empty();
    strcpy(buffer, string);
}

int main(int argc, char** argv) {
    vulnerable_function(argv[1]);
    return 0;
}