#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>

struct test_unit
{
	union
	{
		uint8_t u8;
		uint16_t u16;
		uint32_t u32;
		size_t u64;
	};
	
	uint8_t *value;
};


int main(void)
{
    struct test_unit unit={0};
    printf("sizeof(a) = %lu\n", sizeof(unit.u8));
    printf("sizeof(b) = %lu\n", sizeof(unit.u16));
    printf("sizeof(c) = %lu\n", sizeof(unit.u32));
    printf("sizeof(test_unit) = %lu\n", sizeof(struct test_unit));

    return 0;
}