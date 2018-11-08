#ifndef WEBSTER_NETWORK_HH
#define WEBSTER_NETWORK_HH


#include "internal.h"

#define WBNET_INITIALIZE  networkImpl.initialize
#define WBNET_TERMINATE   networkImpl.terminate
#define WBNET_OPEN        networkImpl.open
#define WBNET_CLOSE       networkImpl.close
#define WBNET_CONNECT     networkImpl.connect
#define WBNET_RECEIVE     networkImpl.receive
#define WBNET_SEND        networkImpl.send
#define WBNET_ACCEPT      networkImpl.accept
#define WBNET_LISTEN      networkImpl.listen

extern webster_network_t networkImpl;

WEBSTER_PRIVATE int network_setImpl(
	webster_network_t *impl );

WEBSTER_PRIVATE int network_resetImpl();

#endif // WEBSTER_NETWORK_HH
