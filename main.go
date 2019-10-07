package main

import (
	/*
		#cgo CFLAGS: -x objective-c -fmacro-backtrace-limit=0 -std=gnu11 -Wobjc-property-no-attribute -Wunguarded-availability-new
		#cgo LDFLAGS: -framework Foundation -framework IOKit -lbsm -lEndpointSecurity
		#include "appmon.h"

		extern void handleEvent(char* json);
	*/
	"C"
	"fmt"
)

//export handleJSON
func handleJSON(json *C.char) {
	res := C.GoString(json)

	fmt.Println(res)
}

func main() {
	cCallbacks := C.Callbacks{}
	cCallbacks.f = C.EventHandlerFn(C.handleEvent)
	C.startEventHandler(cCallbacks)
}
