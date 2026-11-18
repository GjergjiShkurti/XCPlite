/* A 32-bit target's call frame information in .debug_frame alone, with CIEs that do not state their
 * address size (DWARF 3 and earlier), as an older embedded GCC writes them. */
int counter;

int step(int x)
{
    int local = x + 1;
    counter += local;
    return local;
}

int main(void)
{
    for (int i = 0; i < 3; i++) {
        step(i);
    }
    return 0;
}
