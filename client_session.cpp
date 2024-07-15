#include <stdio.h>
#include <cstring>
#include "client_session.h"

#include <iostream>


ClientSession::ClientSession(unsigned int remotePort, const char* remoteIpAddress, const char* keyFilename, char* password, const char* certFilename, const char* rootCaFilename, const char* peerIdentity) :Session(keyFilename, password, certFilename, rootCaFilename, peerIdentity)
{
    if (!active())
    {
        std::cerr << "Error: Session is Not Active." << std::endl; // Handle Error: Inactive Session
        return;
    }

    // Load Root CA Certificate
    if (!loadRootCACertificate())
    {
        std::cerr << "Error: Loading Root CA Certificate Failed." << std::endl; // Handle Error: Loading Root CA Certificate
        _state = UNINITIALIZED_SESSION_STATE;
        return;
    }

    setRemoteAddress(remoteIpAddress, remotePort);

    // Perhaps we can use the first message as Sigma message #1?
    // 
    // Start DH Key Exchange
    if (!CryptoWrapper::startDh(&_dhContext, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES))
    {
        std::cerr << "Error: Starting DH Key Exchange Failed." << std::endl; // Handle Error: Starting DH Key Exchange
        _state = UNINITIALIZED_SESSION_STATE;
        return;
    }

    // Send SIGMA message 1 (HELLO_SESSION_MESSAGE)
    if (!sendMessageInternal(HELLO_SESSION_MESSAGE, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES))
    {
        std::cerr << "Error: Sending HELLO_SESSION_MESSAGE Failed." << std::endl; // Handle Error: Sending HELLO_SESSION_MESSAGE
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return;
    }
    _state = HELLO_SESSION_MESSAGE;

    BYTE messageBuffer[MESSAGE_BUFFER_SIZE_BYTES];
    memset(messageBuffer, '\0', MESSAGE_BUFFER_SIZE_BYTES);

    BYTE* pPayload = NULL;
    size_t payloadSize = 0;
    bool rcvResult = receiveMessage(messageBuffer, MESSAGE_BUFFER_SIZE_BYTES, 10, &pPayload, &payloadSize);
    if (!rcvResult || _state != HELLO_BACK_SESSION_MESSAGE)
    {
        std::cerr << "Error: Receiving HELLO_BACK_SESSION_MESSAGE Failed." << std::endl; // Handle Error: Receiving HELLO_BACK_SESSION_MESSAGE
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return;
    }

    // here we need to verify the DH message 2 part
    if (!verifySigmaMessage(2, pPayload, (size_t)payloadSize))
    {
        std::cerr << "Error: Verifying Sigma Message 2 Failed." << std::endl; // Handle Error: Verifying Sigma Message 2
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return;
    }

    std::vector<MessagePart> parts;
    if (!unpackMessageParts(pPayload, payloadSize, parts) || parts.size() != 4)
    {
        std::cerr << "Error: Unpack Message Parts Failed / Incorrect Number of Parts." << std::endl; // Handle Error: Unpack Message Parts
        _state = UNINITIALIZED_SESSION_STATE;
        return;
    }
    memcpy(_remoteDhPublicKeyBuffer, parts[0].part, DH_KEY_SIZE_BYTES);

    // send SIGMA message 3 part
    ByteSmartPtr message3 = prepareSigmaMessage(3);
    if (message3 == NULL)
    {
        std::cerr << "Error: Prepare Sigma Message 3 Failed." << std::endl; // Handle Error: Prepare Sigma Message
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return;
    }
    //

    if (!sendMessageInternal(HELLO_DONE_SESSION_MESSAGE, message3, message3.size()))
    {
        std::cerr << "Error: Sending HELLO_DONE_SESSION_MESSAGE Failed." << std::endl; // Handle Error: Sending HELLO_DONE_SESSION_MESSAGE
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return;
    }

    // now we will calculate the session key
    deriveSessionKey();

    _state = DATA_SESSION_MESSAGE;
    return;
}


ClientSession::~ClientSession()
{
    closeSession();
    destroySession();
}


Session::ReceiveResult ClientSession::receiveMessage(BYTE* buffer, size_t bufferSize, unsigned int timeout_sec, BYTE** ppPayload, size_t* pPayloadSize)
{
    if (!active())
    {
        std::cerr << "Error: Session is Not Active." << std::endl; // Handle Error: Inactive Session
        return RR_FATAL_ERROR;
    }

    struct sockaddr_in remoteAddr;
    int remoteAddrSize = sizeof(remoteAddr);
    memset(&remoteAddr, 0, remoteAddrSize);

    size_t recvSize = 0;
    Socket::ReceiveResult rcvResult = _localSocket->receive(buffer, bufferSize, timeout_sec, &recvSize, &remoteAddr);
    switch (rcvResult)
    {
    case Socket::RR_TIMEOUT:
        std::cerr << "Error: Server Receive Timed Out." << std::endl; // Handle Error: Server Receive Time Out
        return RR_TIMEOUT;
    case Socket::RR_ERROR:
        std::cerr << "Error: Server Receive Error." << std::endl; // Handle Error: Server Receive Error
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return RR_FATAL_ERROR;
    }

    if (recvSize < sizeof(MessageHeader))
    {
        std::cerr << "Error: Message Smaller Than Header." << std::endl; // Handle Error: Message Smaller Than Header
        return RR_BAD_MESSAGE;
    }

    MessageHeader* header = (MessageHeader*)buffer;
    if (header->messageType < FIRST_SESSION_MESSAGE_TYPE || header->messageType > LAST_SESSION_MESSAGE_TYPE)
    {
        std::cerr << "Error: Bad Message Type: " << header->messageType << std::endl; // Handle Error: Bad Message Type
        return RR_BAD_MESSAGE;
    }

    if (header->payloadSize != recvSize - sizeof(MessageHeader))
    {
        return RR_BAD_MESSAGE;
    }

    if (header->messageCounter != _incomingMessageCounter)
    {
        std::cerr << "Error: Message Size Mismatch." << std::endl; // Handle Error: Message Size Mismatch
        return RR_BAD_MESSAGE;
    }

    _incomingMessageCounter++;

    switch (header->messageType)
    {
    case GOODBYE_SESSION_MESSAGE:
        std::cout << "Session Close Request Sent." << std::endl;
        return RR_SESSION_CLOSED;
    case HELLO_SESSION_MESSAGE:
        std::cerr << "Error: Unexpected HELLO_SESSION_MESSAGE Received." << std::endl; // Handle Error: Unexpected HELLO_SESSION_MESSAGE
        return RR_BAD_MESSAGE;
    case HELLO_BACK_SESSION_MESSAGE:
        if (_state == HELLO_SESSION_MESSAGE)
        {
            _sessionId = header->sessionId;
            _state = HELLO_BACK_SESSION_MESSAGE;

            if (ppPayload != NULL)
                *ppPayload = buffer + sizeof(MessageHeader);

            if (pPayloadSize != NULL)
                *pPayloadSize = header->payloadSize;

            std::cout << "Session Started with " << _expectedRemoteIdentityString << std::endl;
            return RR_PROTOCOL_MESSAGE;
        }
        else
        {
            return RR_BAD_MESSAGE;
        }
    case DATA_SESSION_MESSAGE:
        if (_state == DATA_SESSION_MESSAGE)
        {
            size_t plaintextSize = 0;
            if (!decryptMessage(header, buffer + sizeof(MessageHeader), &plaintextSize))
            {
                std::cerr << "Error: Decrypting DATA_SESSION_MESSAGE Failed." << std::endl; // Handle Error: Decrypting DATA_SESSION_MESSAGE
                return RR_BAD_MESSAGE;
            }

            if (ppPayload != NULL)
            {
                *ppPayload = buffer + sizeof(MessageHeader);
            }

            if (pPayloadSize != NULL)
            {
                *pPayloadSize = plaintextSize;
            }
            _state = DATA_SESSION_MESSAGE;
            return RR_DATA_MESSAGE;
        }
        else
        {
            std::cerr << "Error: Unexpected DATA_SESSION_MESSAGE Received." << std::endl; // Handle Error: Unexpected DATA_SESSION_MESSAGE
            return RR_BAD_MESSAGE;
        }
    }
    std::cerr << "Error: Unknown Message Type Received." << std::endl; // Handle Error: Unknown Message Type
    return RR_BAD_MESSAGE;
}