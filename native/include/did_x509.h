// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file did_x509.h
 * @brief Compatibility header - redirects to cose/did_x509.h
 *
 * This header is maintained for backward compatibility. New code should
 * include <cose/did_x509.h> directly.
 *
 * @deprecated Include <cose/did_x509.h> instead.
 */

#ifndef DID_X509_H
#define DID_X509_H

#include "../c/include/cose/did/did_x509.h"

#endif // DID_X509_H