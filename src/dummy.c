/* NOTE: This file is just to avoid the linkage issues for CMake file,
 *       Remove it after adding the HW-Vtep code and change the CMake
 *       file accordingly.
 */

#include <stdio.h>
#include <unistd.h>

int main(void)
{
    while(1) {
        printf("OPS-HW-VTEP!\n");
        sleep(60);
    }
    return 0;
}
