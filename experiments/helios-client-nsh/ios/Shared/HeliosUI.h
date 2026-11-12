#ifndef HELIOS_UI_H
#define HELIOS_UI_H
#include <stddef.h>
typedef void (*HeliosCommand)(const char *json);
void helios_ios_register(HeliosCommand callback);
void helios_ios_update(const char *json);
void *helios_ui_create(const char *data_directory, double width, double height);
void *helios_ui_view(void *app);
void helios_ui_destroy(void *app);
#endif
