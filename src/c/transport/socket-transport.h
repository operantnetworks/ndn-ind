/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/c/transport/socket-transport.h
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes. Add readRawPackets. Support WinSock2.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2013-2020 Regents of the University of California.
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

#ifndef NDN_SOCKETTRANSPORT_H
#define NDN_SOCKETTRANSPORT_H

#include <ndn-ind/c/common.h>
#include <ndn-ind/c/errors.h>
#include <ndn-ind/c/transport/transport-types.h>
#include "../encoding/element-reader.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  SOCKET_TCP,
  SOCKET_UDP,
  SOCKET_UNIX
} ndn_SocketType;

/**
 * Initialize the ndn_SocketTransport struct with default values for no
 * connection yet and to use the given buffer for the ElementReader. Note that
 * the ElementReader is not valid until you call ndn_SocketTransport_connect.
 * @param self A pointer to the ndn_SocketTransport struct.
 * @param buffer A pointer to a ndn_DynamicUInt8Array struct which is used to
 * save data before calling the elementListener (see ndn_SocketTransport_connect).
 * The struct must remain valid during the entire life of this
 * ndn_SocketTransport. If the buffer->realloc function pointer is 0, its array
 * must be large enough to save a full element, perhaps MAX_NDN_PACKET_SIZE bytes.
 * However, if readRawPackets is 1, then the buffer is not used.
 * @param readRawPackets If 1, then call elementListener->onReceivedElement for
 * each received packet as-is. If 0, then use the ndn_TlvStructureDecoder to
 * ensure that elementListener->onReceivedElement is called once for a whole
 * TLV packet.
 */
static __inline void ndn_SocketTransport_initialize
  (struct ndn_SocketTransport *self, struct ndn_DynamicUInt8Array *buffer,
   int readRawPackets)
{
#if defined(_WIN32)
  self->socketDescriptor = INVALID_SOCKET;
#else
  self->socketDescriptor = -1;
#endif

  ndn_ElementReader_initialize(&self->elementReader, 0, buffer, readRawPackets);
}

/**
 * Connect with TCP or UDP to the host:port, or with Unix Sockets to host
 *   (which is interpreted as the Unix Socket filename).
 * @param self A pointer to the ndn_SocketTransport struct.
 * @param socketType SOCKET_TCP, SOCKET_UDP or SOCKET_UNIX.
 * @param host For SOCKET_TCP or SOCKET_UDP, the host to connect to. For
 * SOCKET_UNIX, the socket filename.
 * @param port The port to connect to (ignored for SOCKET_UNIX).
 * @param elementListener A pointer to the ndn_ElementListener used by
 * ndn_SocketTransport_processEvents, which remain valid during the life of this
 * object or until replaced by the next call to connect.
 * @return 0 for success, else an error code.
 */
ndn_Error ndn_SocketTransport_connect
  (struct ndn_SocketTransport *self, ndn_SocketType socketType, const char *host,
   unsigned short port, struct ndn_ElementListener *elementListener);

/**
 * Set this transport to use the existing socket descriptor.
 * @param self A pointer to the ndn_SocketTransport struct.
 * @param socketDescriptor The socket descriptor, which must already be open.
 * @param elementListener A pointer to the ndn_ElementListener used by
 * ndn_SocketTransport_processEvents, which remain valid during the life of this
 * object or until replaced by the next call to connect.
 * @return 0 for success, else an error code.
 */
static __inline ndn_Error ndn_SocketTransport_useSocket
  (struct ndn_SocketTransport *self,
#if defined(_WIN32)
   SOCKET socketDescriptor,
#else
   int socketDescriptor,
#endif
   struct ndn_ElementListener *elementListener)
{
  ndn_ElementReader_reset(&self->elementReader, elementListener);
  self->socketDescriptor = socketDescriptor;
  return NDN_ERROR_success;
}

/**
 * Send data to the socket.
 * @param self A pointer to the ndn_SocketTransport struct.
 * @param data A pointer to the buffer of data to send.
 * @param dataLength The number of bytes in data.
 * @return 0 for success, else an error code.
 */
ndn_Error ndn_SocketTransport_send(struct ndn_SocketTransport *self, const uint8_t *data, size_t dataLength);

/**
 * Check if there is data ready on the socket to be received with ndn_SocketTransport_receive.
 * This does not block, and returns immediately.
 * @param self A pointer to the ndn_SocketTransport struct.
 * @param receiveIsReady This will be set to 1 if data is ready, 0 if not.
 * @return 0 for success, else an error code.
 */
ndn_Error ndn_SocketTransport_receiveIsReady(struct ndn_SocketTransport *self, int *receiveIsReady);

/**
 * Receive data from the socket.  NOTE: This is a blocking call.  You should first call ndn_SocketTransport_receiveIsReady
 * to make sure there is data ready to receive.
 * @param self A pointer to the ndn_SocketTransport struct.
 * @param buffer A pointer to the buffer to receive the data.
 * @param bufferLength The maximum length of buffer.
 * @param nBytes Return the number of bytes received into buffer.
 * @return 0 for success, else an error code.
 */
ndn_Error ndn_SocketTransport_receive
  (struct ndn_SocketTransport *self, uint8_t *buffer, size_t bufferLength, size_t *nBytes);

/**
 * Process any data to receive.  For each element received, call
 * (*elementListener->onReceivedElement)(element, elementLength) for the
 * elementListener in the elementReader given to connect(). This is non-blocking
 * and will return immediately if there is no data to receive.
 * @param self A pointer to the ndn_SocketTransport struct.
 * @param buffer A pointer to a buffer for receiving data. Note that this is
 * only for temporary use and is not the way that this function supplies data.
 * It supplies the data by calling the onReceivedElement callback.
 * @param bufferLength The size of buffer. The buffer should be as large as
 * resources permit up to MAX_NDN_PACKET_SIZE, but smaller sizes will work
 * however may be less efficient due to multiple calls to socket receive and
 * more processing by the ElementReader.
 * @return 0 for success, else an error code.
 */
ndn_Error
ndn_SocketTransport_processEvents
  (struct ndn_SocketTransport *self, uint8_t *buffer, size_t bufferLength);

/**
 * Close the socket.
 * @param self A pointer to the ndn_SocketTransport struct.
 * @return 0 for success, else an error code.
 */
ndn_Error ndn_SocketTransport_close(struct ndn_SocketTransport *self);

#ifdef __cplusplus
}
#endif

#endif
