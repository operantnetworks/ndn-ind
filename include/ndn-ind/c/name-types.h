/**
 * Copyright (C) 2015-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version, with the additional exemption that
 * compiling, linking, and/or using OpenSSL is allowed.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

#ifndef NDN_NAME_TYPES_H
#define NDN_NAME_TYPES_H

#include "util/blob-types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * An ndn_NameComponentType specifies the recognized types of a name component.
 * If the component type in the packet is not a recognized enum value, then we
 * use ndn_NameComponentType_OTHER_CODE and you can call
 * Name.Component.getOtherTypeCode(). We do this to keep the recognized
 * component type values independent of packet encoding details.
 */
typedef enum {
  ndn_NameComponentType_IMPLICIT_SHA256_DIGEST = 1,
  ndn_NameComponentType_PARAMETERS_SHA256_DIGEST = 2,
  ndn_NameComponentType_GENERIC = 8,
  ndn_NameComponentType_OTHER_CODE = 0x7fff
} ndn_NameComponentType;

/**
 * An ndn_NameComponent holds a pointer to the component value.
 */
struct ndn_NameComponent {
  ndn_NameComponentType type;
  int otherTypeCode;
  struct ndn_Blob value;     /**< A Blob with a pointer to the pre-allocated buffer for the component value */
};

/**
 * An ndn_Name holds an array of ndn_NameComponent.
 */
struct ndn_Name {
  struct ndn_NameComponent *components; /**< pointer to the array of components. */
  size_t maxComponents;                 /**< the number of elements in the allocated components array */
  size_t nComponents;                   /**< the number of components in the name */
};

#ifdef __cplusplus
}
#endif

#endif
