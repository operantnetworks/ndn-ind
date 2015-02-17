/**
 * Copyright (C) 2013-2015 Regents of the University of California.
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

#include <string.h>
#include "util/ndn_memory.h"
#include "name.h"

uint64_t ndn_NameComponent_toNumber(struct ndn_NameComponent *self)
{
  uint64_t result = 0;
  size_t i;
  for (i = 0; i < self->value.length; ++i) {
    result *= 256;
    result += (uint64_t)self->value.value[i];
  }

  return result;
}

ndn_Error ndn_NameComponent_toNumberWithMarker(struct ndn_NameComponent *self, uint8_t marker, uint64_t *result)
{
  uint64_t localResult;
  size_t i;

  if (self->value.length == 0 || self->value.value[0] != marker)
    return NDN_ERROR_Name_component_does_not_begin_with_the_expected_marker;

  localResult = 0;
  for (i = 1; i < self->value.length; ++i) {
    localResult *= 256;
    localResult += (uint64_t)self->value.value[i];
  }

  *result = localResult;
  return NDN_ERROR_success;
}

ndn_Error ndn_NameComponent_toNumberWithPrefix
  (struct ndn_NameComponent *self, const uint8_t *prefix, size_t prefixLength, uint64_t *result)
{
  uint64_t localResult;
  size_t i;

  if (self->value.length < prefixLength || ndn_memcmp(self->value.value, prefix, prefixLength) != 0)
    return NDN_ERROR_Name_component_does_not_begin_with_the_expected_marker;

  localResult = 0;
  for (i = prefixLength; i < self->value.length; ++i) {
    localResult *= 256;
    localResult += (uint64_t)self->value.value[i];
  }

  *result = localResult;
  return NDN_ERROR_success;
}

int ndn_Name_match(struct ndn_Name *self, struct ndn_Name *name)
{
  int i;

  // This name is longer than the name we are checking it against.
  if (self->nComponents > name->nComponents)
    return 0;

  // Check if at least one of given components doesn't match. Check from last to
  // first since the last components are more likely to differ.
  for (i = self->nComponents - 1; i >= 0; --i) {
    struct ndn_NameComponent *selfComponent = self->components + i;
    struct ndn_NameComponent *nameComponent = name->components + i;

    if (selfComponent->value.length != nameComponent->value.length ||
        ndn_memcmp(selfComponent->value.value, nameComponent->value.value, selfComponent->value.length) != 0)
      return 0;
  }

  return 1;
}

ndn_Error ndn_Name_appendComponent(struct ndn_Name *self, const uint8_t *value, size_t valueLength)
{
  if (self->nComponents >= self->maxComponents)
      return NDN_ERROR_attempt_to_add_a_component_past_the_maximum_number_of_components_allowed_in_the_name;
  ndn_NameComponent_initialize(self->components + self->nComponents, value, valueLength);
  ++self->nComponents;

  return NDN_ERROR_success;
}

ndn_Error ndn_Name_appendString(struct ndn_Name *self, const char *value)
{
  return ndn_Name_appendComponent(self, (const uint8_t *)value, strlen(value));
}
