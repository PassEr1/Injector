#pragma once

void __attribute__ ((constructor)) my_init(void);
void __attribute__ ((destructor)) my_finish(void);
