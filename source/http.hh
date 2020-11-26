#ifndef WEBSTER_HTTP_HH
#define WEBSTER_HTTP_HH

namespace webster {
namespace http {

const char *http_method( int value );
const char *http_status_message( int status );

} // namespace http
} // namespace webster

#endif // WEBSTER_HTTP_HH