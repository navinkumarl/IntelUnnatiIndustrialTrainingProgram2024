#include <list>
#include <stdio.h>
#include <cstring>
#include <cstdarg>
#include <cstdlib>
#include "session.h"
#include "utils.h"
#include "crypto_wrapper.h"

#include <iostream>


#ifdef WIN
#pragma warning(disable:4996) 
#endif // #ifdef WIN


static constexpr size_t MAX_CONTEXT_SIZE = 100;


Session::Session(const char* keyFilename, char* password, const char* certFilename, const char* rootCaFilename, const char* peerIdentity)
{
    _state = UNINITIALIZED_SESSION_STATE;

    _localSocket = new Socket(0);
    if (!_localSocket->valid())
    {
        std::cerr << "Error: Creating Local Socket Failed." << std::endl; // Handle Error: Creating Local Socket
        return;
    }
    _pReferenceCounter = new ReferenceCounter();
    _pReferenceCounter->AddRef();

    _sessionId = 0;
    _outgoingMessageCounter = 0;
    _incomingMessageCounter = 0;

    // Init crypto part
    _privateKeyFilename = keyFilename;
    _privateKeyPassword = password;
    _localCertFilename = certFilename;
    _rootCaCertFilename = rootCaFilename;
    _expectedRemoteIdentityString = peerIdentity;
    memset(_sessionKey, 0, SYMMETRIC_KEY_SIZE_BYTES);

    _state = INITIALIZED_SESSION_STATE;
}


Session::Session(const Session& other)
{
    _state = UNINITIALIZED_SESSION_STATE;
    _pReferenceCounter = other._pReferenceCounter;
    _pReferenceCounter->AddRef();

    _localSocket = other._localSocket;

    _sessionId = 0;
    _outgoingMessageCounter = 0;
    _incomingMessageCounter = 0;

    // Init crypto part
    _privateKeyFilename = other._privateKeyFilename;
    _privateKeyPassword = other._privateKeyPassword;
    _localCertFilename = other._localCertFilename;
    _rootCaCertFilename = other._rootCaCertFilename;
    _expectedRemoteIdentityString = other._expectedRemoteIdentityString;
    memset(_sessionKey, 0, SYMMETRIC_KEY_SIZE_BYTES);

    _state = INITIALIZED_SESSION_STATE;

    if (!loadRootCACertificate())
    {
        std::cerr << "Error: Loading Root CA Certificate Failed." << std::endl; // Handle Error: Loading Root CA Certificate
        return;
    }
}


void Session::closeSession()
{
    if (active())
    {
        ByteSmartPtr encryptedMessage = prepareEncryptedMessage(GOODBYE_SESSION_MESSAGE, NULL, 0);
        if (encryptedMessage != NULL)
        {
            if (!sendMessageInternal(GOODBYE_SESSION_MESSAGE, encryptedMessage, encryptedMessage.size()))
            {
                std::cerr << "Error: Sending Encrypted GOODBYE_SESSION_MESSAGE Failed." << std::endl; // Handle Error: Sending Encrypted GOODBYE_SESSION_MESSAGE
                return;
            }
            _state = GOODBYE_SESSION_MESSAGE;
        }
        else
        {
            std::cerr << "Error: Encrypting GOODBYE_SESSION_MESSAGE Failed." << std::endl; // Handle Error: Encrypting GOODBYE_SESSION_MESSAGE
            return;
        }
    }
}

void Session::destroySession()
{
    cleanDhData();
    if (_pReferenceCounter != NULL && _pReferenceCounter->Release() == 0)
    {
        delete _localSocket;
        _localSocket = NULL;
        delete _pReferenceCounter;
        _pReferenceCounter = NULL;

        if (_privateKeyPassword != NULL)
        {
            // we better clean it using some Utils function
            // ...
            Utils::secureCleanMemory((BYTE*)_privateKeyPassword, strlen(_privateKeyPassword));
            free(_privateKeyPassword);
            _privateKeyPassword = NULL;
        }
    }
    else
    {
        _pReferenceCounter = NULL;
    }

    _state = DEACTIVATED_SESSION_STATE;
}


bool Session::loadRootCACertificate()
{
    ByteSmartPtr certBufferSmartPtr = Utils::readBufferFromFile(_rootCaCertFilename);
    if (certBufferSmartPtr == NULL)
    {
        std::cerr << "Error: Reading Root CA Certificate File - " << _rootCaCertFilename << "Failed." << std::endl; // Handle Error: Reading Root CA Certificate File
        return false;
    }
    _rootCaCertBufferSize = certBufferSmartPtr.size();
    _rootCaCertBuffer = (BYTE*)Utils::allocateBuffer(_rootCaCertBufferSize);
    memcpy(_rootCaCertBuffer, certBufferSmartPtr, _rootCaCertBufferSize);
    return true;
}


bool Session::active()
{
    return (_state == INITIALIZED_SESSION_STATE ||
        (_state >= FIRST_SESSION_MESSAGE_TYPE && _state <= LAST_SESSION_MESSAGE_TYPE));
}


void Session::setRemoteAddress(const char* remoteIpAddress, unsigned int remotePort)
{
    memset(&(_remoteAddress), 0, sizeof(sockaddr_in));
    _remoteAddress.sin_family = AF_INET;
    _remoteAddress.sin_port = htons(remotePort);
    _remoteAddress.sin_addr.s_addr = inet_addr(remoteIpAddress);
}


void Session::prepareMessageHeader(MessageHeader* header, unsigned int type, size_t messageSize)
{
    header->sessionId = _sessionId;
    header->messageType = type;
    header->messageCounter = _outgoingMessageCounter;
    header->payloadSize = (unsigned int)messageSize;
}


bool Session::sendMessageInternal(unsigned int type, const BYTE* message, size_t messageSize)
{
    if (!active())
    {
        std::cerr << "Error: Session is Not Active." << std::endl; // Handle Error: Inactive Session
        return false;
    }

    MessageHeader header;
    prepareMessageHeader(&header, type, messageSize);

    ByteSmartPtr messageBufferSmartPtr = concat(2, &header, sizeof(header), message, messageSize);
    if (messageBufferSmartPtr == NULL)
    {
        std::cerr << "Error: Concatenating Message Parts Failed." << std::endl; // Handle Error: Concatenating Message Parts
        return false;
    }

    bool result = _localSocket->send(messageBufferSmartPtr, messageBufferSmartPtr.size(), &(_remoteAddress));
    if (result)
    {
        _outgoingMessageCounter++;
    }
    else
    {
        std::cerr << "Error: Sending Message Failed." << std::endl; // Handle Error: Sending Message
    }

    return result;
}


void Session::cleanDhData()
{
    // ...
    if (_dhContext != NULL) {
        CryptoWrapper::cleanDhContext(&_dhContext);
        _dhContext = NULL;
    }
    Utils::secureCleanMemory(_localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
    Utils::secureCleanMemory(_sharedSecret, SYMMETRIC_KEY_SIZE_BYTES);
}


void Session::deriveMacKey(BYTE* macKeyBuffer)
{
    char keyDerivationContext[MAX_CONTEXT_SIZE];
    if (sprintf_s(keyDerivationContext, MAX_CONTEXT_SIZE, "MAC over certificate key %d", _sessionId) <= 0)
    {
        std::cerr << "Error: Formatting Key Derivation Context Failed." << std::endl; // Handle Error: Formatting Key Derivation Context
        exit(0);
    }

    // ...
    // Derive the session key using HKDF
    if (!CryptoWrapper::deriveKey_HKDF_SHA256(NULL, 0, _sharedSecret, SYMMETRIC_KEY_SIZE_BYTES, (BYTE*)keyDerivationContext, strlen(keyDerivationContext), macKeyBuffer, SYMMETRIC_KEY_SIZE_BYTES))
    {
        std::cerr << "Error: Deriving MAC Key using HKDF Failed." << std::endl; // Handle Error: Deriving MAC Key using HKDF
        exit(0);
    }
    // std::cout << "MAC Key Derived Successfully." << std::endl;
}


void Session::deriveSessionKey()
{
    char keyDerivationContext[MAX_CONTEXT_SIZE];
    if (sprintf_s(keyDerivationContext, MAX_CONTEXT_SIZE, "ENC session key %d", _sessionId) <= 0)
    {
        std::cerr << "Error: Formatting Key Derivation Context Failed." << std::endl; // Handle Error: Formatting Key Derivation Context
        exit(0);
    }
    // ...
    // Derive the session key using HKDF
    if (!CryptoWrapper::deriveKey_HKDF_SHA256(NULL, 0, _sharedSecret, SYMMETRIC_KEY_SIZE_BYTES, (BYTE*)keyDerivationContext, strlen(keyDerivationContext), _sessionKey, SYMMETRIC_KEY_SIZE_BYTES))
    {
        std::cerr << "Error: Deriving Session Key using HKDF Failed." << std::endl; // Handle Error: Deriving Session Key using HKDF
        exit(0);
    }
    // std::cout << "Session Key Derived Successfully." << std::endl;
}


ByteSmartPtr Session::prepareSigmaMessage(unsigned int messageType)
{
    if (messageType != 2 && messageType != 3)
    {
        std::cerr << "Error: Bad Message Type." << std::endl; // Handle Error: Bad Message Type
        return 0;
    }

    // we will be building the following message parts:
    // 1: my DH public key 
    // 2: My certificate (PEM)
    // 3: Signature over concatenated public keys with my permanenet private key
    // 4: MAC over my certificate with the shared MAC key

    // Generate DH Key Pair if not already done
    if (_dhContext == NULL) {
        if (!CryptoWrapper::startDh(&_dhContext, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES))
        {
            std::cerr << "Error: Starting DH Key Exchange Failed." << std::endl; // Handle Error: Starting DH Key Exchange
            cleanDhData();
            return NULL;
        }
    }

    // get my certificate
    ByteSmartPtr certBufferSmartPtr = Utils::readBufferFromFile(_localCertFilename);
    if (certBufferSmartPtr == NULL)
    {
        std::cerr << "Error: Reading Certificate Filename - " << _localCertFilename << " Failed." << std::endl; // Handle Error: Reading Certificate Filename
        return NULL;
    }

    // get my private key for signing
    KeypairContext* privateKeyContext = NULL;
    if (!CryptoWrapper::readRSAKeyFromFile(_privateKeyFilename, _privateKeyPassword, &privateKeyContext))
    {
        std::cerr << "Error: Reading RSA Key from File - " << _privateKeyFilename << " Failed." << std::endl; // Handle Error: Reading RSA Key from File
        cleanDhData();
        return NULL;
    }

    ByteSmartPtr conacatenatedPublicKeysSmartPtr = concat(2, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES, _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
    if (conacatenatedPublicKeysSmartPtr == NULL)
    {
        std::cerr << "Error: Concatenating Public Keys Failed." << std::endl; // Handle Error: Concatenating Public Keys
        cleanDhData();
        return NULL;
    }

    BYTE signature[SIGNATURE_SIZE_BYTES];
    // ...
    if (!CryptoWrapper::signMessageRsa3072Pss(conacatenatedPublicKeysSmartPtr, conacatenatedPublicKeysSmartPtr.size(), privateKeyContext, signature, SIGNATURE_SIZE_BYTES)) {
        std::cerr << "Error: Signing Message using RSA 3072 PSS Failed." << std::endl; // Handle Error: Signing Message using RSA 3072 PSS
        cleanDhData();
        return NULL;
    }

    // Now we will calculate the MAC over my certiicate
    BYTE calculatedMac[HMAC_SIZE_BYTES];
    // ...
    if (!CryptoWrapper::hmac_SHA256(_macKey, DH_KEY_SIZE_BYTES, certBufferSmartPtr, certBufferSmartPtr.size(), calculatedMac, HMAC_SIZE_BYTES)) {
        std::cerr << "Error: Calculating MAC (HMAC) using SHA256 Failed." << std::endl; // Handle Error: Calculating MAC (HMAC) using SHA256
        cleanDhData();
        return NULL;
    }

    // pack all of the parts together
    ByteSmartPtr messageToSend = packMessageParts(4, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES, (BYTE*)certBufferSmartPtr, certBufferSmartPtr.size(), signature, SIGNATURE_SIZE_BYTES, calculatedMac, HMAC_SIZE_BYTES);
    Utils::secureCleanMemory(calculatedMac, HMAC_SIZE_BYTES);
    return messageToSend;
}


bool Session::verifySigmaMessage(unsigned int messageType, const BYTE* pPayload, size_t payloadSize)
{
    if (messageType != 2 && messageType != 3)
    {
        std::cerr << "Error: Bad Message Type." << std::endl; // Handle Error: Bad Message Type
        return false;
    }

    unsigned int expectedNumberOfParts = 4;

    // We are expecting 4 parts
    // 1: Remote public DH key (in message type 3 we will check that it equalss the value received in message type 1)
    // 2: Remote certificate (PEM) null terminated
    // 3: Signature over concatenated public keys (remote|local)
    // 4: MAC over remote certificate with the shared MAC key

    std::vector<MessagePart> parts;
    if (!unpackMessageParts(pPayload, payloadSize, parts) || parts.size() != expectedNumberOfParts)
    {
        std::cerr << "Error: Unpack Message Parts Failed / Incorrect Number of Parts." << std::endl; // Handle Error: Unpack Message Parts
        return false;
    }

    // ...
    const BYTE* remotePublicKey = parts[0].part;
    const size_t remotePublicKeySize = parts[0].partSize;
    const BYTE* remoteCertBuffer = parts[1].part;
    size_t remoteCertSize = parts[1].partSize;
    const BYTE* signature = parts[2].part;
    const BYTE* receivedMac = parts[3].part;

    // Concatenate public keys
    ByteSmartPtr concatenatedPublicKeysSmartPtr = concat(2, remotePublicKey, remotePublicKeySize, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
    if (concatenatedPublicKeysSmartPtr == NULL)
    {
        std::cerr << "Error: Concatenating Public Keys Failed." << std::endl; // Handle Error: Concatenating Public Keys
        return false;
    }

    // we will now verify if the received certificate belongs to the expected remote entity
    // ...
    // Verify certificate
    if (!CryptoWrapper::checkCertificate(_rootCaCertBuffer, _rootCaCertBufferSize, remoteCertBuffer, remoteCertSize, _expectedRemoteIdentityString)) {
        std::cerr << "Error: Verifying Certificate Failed." << std::endl; // Handle Error: Verifying Certificate
        return false;
    }

    // now we will verify if the signature over the concatenated public keys is ok
    // ...
    // Verify signature
    KeypairContext* remotePublicKeyContext;
    if (!CryptoWrapper::getPublicKeyFromCertificate(remoteCertBuffer, remoteCertSize, &remotePublicKeyContext)) {
        std::cerr << "Error: Extracting Public Key from Certificate Failed." << std::endl; // Handle Error: Extracting Public Key from Certificate
        return false;
    }

    bool signatureValid;
    if (!CryptoWrapper::verifyMessageRsa3072Pss(concatenatedPublicKeysSmartPtr, concatenatedPublicKeysSmartPtr.size(), remotePublicKeyContext, signature, SIGNATURE_SIZE_BYTES, &signatureValid) || !signatureValid) {
        std::cerr << "Error: Verifying Signature of Message using RSA 3072 PSS Failed." << std::endl; // Handle Error: Verifying Signature of Message using RSA 3072 PSS
        return false;
    }

    if (messageType == 2 || messageType == 3)
    {
        // Now we will calculate the shared secret
        // ...
        if (!CryptoWrapper::getDhSharedSecret(_dhContext, remotePublicKey, remotePublicKeySize, _sharedSecret, DH_KEY_SIZE_BYTES)) {
            std::cerr << "Error: Getting DH Shared Secret Failed." << std::endl; // Handle Error: Getting DH Shared Secret
            return false;
        }
    }

    // Now we will verify the MAC over the certificate
    // ...
    BYTE calculatedMac[HMAC_SIZE_BYTES];
    if (!CryptoWrapper::hmac_SHA256(_macKey, DH_KEY_SIZE_BYTES, remoteCertBuffer, remoteCertSize, calculatedMac, HMAC_SIZE_BYTES)) {
        std::cerr << "Error: Calculating MAC (HMAC) using SHA256 Failed." << std::endl; // Handle Error: Calculating MAC (HMAC) using SHA256
        return false;
    }

    if (memcmp(calculatedMac, receivedMac, HMAC_SIZE_BYTES) != 0) {
        std::cerr << "Error: Calculated and Received MACs (HMAC) using SHA256 do not Match." << std::endl; // Handle Error: Calculated and Received MACs (HMAC) using SHA256 do not Match
        return false;
    }

    return true;
}


ByteSmartPtr Session::prepareEncryptedMessage(unsigned int messageType, const BYTE* message, size_t messageSize) {
    size_t ciphertextSize = CryptoWrapper::getCiphertextSizeAES_GCM256(messageSize);
    BYTE* ciphertext = (BYTE*)Utils::allocateBuffer(ciphertextSize);
    size_t actualCiphertextSize;

    if (!CryptoWrapper::encryptAES_GCM256(_sessionKey, SYMMETRIC_KEY_SIZE_BYTES, message, messageSize, (const BYTE*)(&messageSize), sizeof(messageSize), ciphertext, ciphertextSize, &actualCiphertextSize))
    {
        std::cerr << "Error: Encrypting Message Failed." << std::endl; // Handle Error: Encrypting Message
        return NULL;
    }

    return ByteSmartPtr(ciphertext, actualCiphertextSize);

    /*
    // we will do a plain copy for now
    size_t encryptedMessageSize = messageSize;
    BYTE* ciphertext = (BYTE*)Utils::allocateBuffer(encryptedMessageSize);
    if (ciphertext == NULL)
    {
        return NULL;
    }

    memcpy_s(ciphertext, encryptedMessageSize, message, messageSize);

    ByteSmartPtr result(ciphertext, encryptedMessageSize);
    return result;
    */
}


bool Session::decryptMessage(MessageHeader* header, BYTE* buffer, size_t* pPlaintextSize)
{
    size_t plaintextSize = CryptoWrapper::getPlaintextSizeAES_GCM256(header->payloadSize);
    BYTE* plaintext = (BYTE*)Utils::allocateBuffer(plaintextSize);
    size_t actualPlaintextSize;

    bool success = CryptoWrapper::decryptAES_GCM256(_sessionKey, SYMMETRIC_KEY_SIZE_BYTES, buffer, header->payloadSize, (const BYTE*)(&plaintextSize), sizeof(plaintextSize), plaintext, plaintextSize, &actualPlaintextSize);

    if (success) {
        memcpy(buffer, plaintext, actualPlaintextSize);
        *pPlaintextSize = actualPlaintextSize;
    }

    Utils::secureCleanMemory(plaintext, plaintextSize);
    Utils::freeBuffer(plaintext);

    return success;

    /*
    // we will do a plain copy for now
    size_t ciphertextSize = header->payloadSize;
    size_t plaintextSize = ciphertextSize;


    if (pPlaintextSize != NULL)
    {
        *pPlaintextSize = plaintextSize;
    }

    return true;
    */
}


bool Session::sendDataMessage(const BYTE* message, size_t messageSize)
{
    if (!active() || _state != DATA_SESSION_MESSAGE)
    {
        std::cerr << "Error: Session is Not Active / State is Not DATA_SESSION_MESSAGE." << std::endl; // Handle Error: Inactive Session
        return false;
    }

    ByteSmartPtr encryptedMessage = prepareEncryptedMessage(DATA_SESSION_MESSAGE, message, messageSize);
    if (encryptedMessage == NULL)
    {
        std::cerr << "Error: Encrypting Message Failed." << std::endl; // Handle Error: Encrypting Message
        return false;
    }

    return sendMessageInternal(DATA_SESSION_MESSAGE, encryptedMessage, encryptedMessage.size());
}


ByteSmartPtr Session::concat(unsigned int numOfParts, ...)
{
    va_list args;
    va_start(args, numOfParts);
    size_t totalSize = 0;
    std::list<MessagePart> partsList;

    // build a list and count the desired size for buffer
    for (unsigned int i = 0; i < numOfParts; i++)
    {
        MessagePart messagePart;
        messagePart.part = va_arg(args, const BYTE*);
        messagePart.partSize = va_arg(args, unsigned int);
        totalSize += messagePart.partSize;
        partsList.push_back(messagePart);
    }
    va_end(args);

    // allocate required buffer size (will be released by the smart pointer logic)
    BYTE* buffer = (BYTE*)Utils::allocateBuffer(totalSize);
    if (buffer == NULL)
    {
        std::cerr << "Error: Allocating Buffer Failed." << std::endl; // Handle Error: Allocating Buffer
        return NULL;
    }

    // copy the parts into the new buffer
    BYTE* pos = buffer;
    size_t spaceLeft = totalSize;
    for (std::list<MessagePart>::iterator it = partsList.begin(); it != partsList.end(); it++)
    {
        memcpy_s(pos, spaceLeft, it->part, it->partSize);
        pos += it->partSize;
        spaceLeft -= it->partSize;
    }

    ByteSmartPtr result(buffer, totalSize);
    return result;
}


ByteSmartPtr Session::packMessageParts(unsigned int numOfParts, ...)
{
    va_list args;
    va_start(args, numOfParts);
    size_t totalSize = 0;
    std::list<MessagePart> partsList;

    // build a list and count the desired size for buffer
    for (unsigned int i = 0; i < numOfParts; i++)
    {
        MessagePart messagePart;
        messagePart.part = va_arg(args, const BYTE*);
        messagePart.partSize = va_arg(args, unsigned int);
        totalSize += (messagePart.partSize + sizeof(size_t));
        partsList.push_back(messagePart);
    }
    va_end(args);

    // allocate required buffer size (will be released by caller's smart pointer)
    BYTE* buffer = (BYTE*)Utils::allocateBuffer(totalSize);
    if (buffer == NULL)
    {
        std::cerr << "Error: Allocating Buffer Failed." << std::endl; // Handle Error: Allocating Buffer
        return NULL;
    }

    // copy the parts into the new buffer
    std::list<MessagePart>::iterator it = partsList.begin();
    BYTE* pos = buffer;
    size_t spaceLeft = totalSize;
    for (; it != partsList.end(); it++)
    {
        memcpy_s(pos, spaceLeft, (void*)&(it->partSize), sizeof(size_t));
        pos += sizeof(size_t);
        spaceLeft -= sizeof(size_t);
        memcpy_s(pos, spaceLeft, it->part, it->partSize);
        pos += it->partSize;
        spaceLeft -= it->partSize;
    }

    ByteSmartPtr result(buffer, totalSize);
    return result;
}


bool Session::unpackMessageParts(const BYTE* buffer, size_t bufferSize, std::vector<MessagePart>& result)
{
    std::list<MessagePart> partsList;
    size_t pos = 0;
    while (pos < bufferSize)
    {
        if (pos + sizeof(size_t) >= bufferSize)
        {
            return false;
        }

        size_t partSize = 0;
        memcpy_s(&partSize, sizeof(size_t), buffer + pos, sizeof(size_t));
        pos += sizeof(size_t);

        if (pos + partSize > bufferSize)
        {
            return false;
        }

        MessagePart part;
        part.partSize = partSize;
        part.part = buffer + pos;
        partsList.push_back(part);
        pos += partSize;
    }

    result.assign(partsList.begin(), partsList.end());
    return true;
}