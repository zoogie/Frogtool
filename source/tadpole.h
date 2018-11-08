#include <3ds.h>

void getSection(u8 *dsiware_pointer, u32 section_size, u8 *key, u8 *output);
void placeSection(u8 *dsiware_pointer, u8 *section, u32 section_size, u8 *key, u8 *key_cmac);