/*
 *   Copyright 2016-2023 Bruno Costa
 *   <https://github.com/brunexgeek/webster>
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#ifndef WEBSTER_HTTP_HH
#define WEBSTER_HTTP_HH

#include <webster.hh> // AUTO-REMOVE

namespace webster {

WEBSTER_PRIVATE const char *http_method( int value );
WEBSTER_PRIVATE const char *http_status_message( int status );

} // namespace webster

#endif // WEBSTER_HTTP_HH