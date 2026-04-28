#include "iconia_app.h"

static IconiaApp gIconiaApp;

void setup() {
  gIconiaApp.begin();
}

void loop() {
  gIconiaApp.loop();
}
