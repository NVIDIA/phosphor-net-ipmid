#include "message_parsers.hpp"

#include <iostream>
#include <memory>

#include "endian.hpp"
#include "main.hpp"
#include "message.hpp"
#include "sessions_manager.hpp"

namespace message
{

namespace parser
{

std::tuple<std::unique_ptr<Message>, SessionHeader> unflatten(
        std::vector<uint8_t>& inPacket)
{
    // Check if the packet has atleast the size of the RMCP Header
    if (inPacket.size() < sizeof(BasicHeader_t))
    {
        throw std::runtime_error("RMCP Header missing");
    }

    auto rmcpHeaderPtr = reinterpret_cast<BasicHeader_t*>(inPacket.data());

    // Verify if the fields in the RMCP header conforms to the specification
    if ((rmcpHeaderPtr->version != RMCP_VERSION) ||
        (rmcpHeaderPtr->rmcpSeqNum != RMCP_SEQ) ||
        (rmcpHeaderPtr->classOfMsg != RMCP_MESSAGE_CLASS_IPMI))
    {
        throw std::runtime_error("RMCP Header is invalid");
    }

    // Read the Session Header and invoke the parser corresponding to the
    // header type
    switch (static_cast<SessionHeader>(rmcpHeaderPtr->format.formatType))
    {
        case SessionHeader::IPMI15:
        {
            return std::make_tuple(ipmi15parser::unflatten(inPacket),
                                   SessionHeader::IPMI15);
        }
        case SessionHeader::IPMI20:
        {
            return std::make_tuple(ipmi20parser::unflatten(inPacket),
                                   SessionHeader::IPMI20);
        }
        default:
        {
            throw std::runtime_error("Invalid Session Header");
        }
    }
}

std::vector<uint8_t> flatten(Message& outMessage,
                             SessionHeader authType,
                             session::Session& session)
{
    // Call the flatten routine based on the header type
    switch (authType)
    {
        case SessionHeader::IPMI15:
        {
            return ipmi15parser::flatten(outMessage, session);
        }
        case SessionHeader::IPMI20:
        {
            return ipmi20parser::flatten(outMessage, session);
        }
        default:
        {
            return {};
        }
    }
}

} // namespace parser

namespace ipmi15parser
{

std::unique_ptr<Message> unflatten(std::vector<uint8_t>& inPacket)
{
    // Check if the packet has atleast the Session Header
    if (inPacket.size() < sizeof(SessionHeader_t))
    {
        throw std::runtime_error("IPMI1.5 Session Header Missing");
    }

    auto message = std::make_unique<Message>();

    auto header = reinterpret_cast<SessionHeader_t*>(inPacket.data());

    message->payloadType = PayloadType::IPMI;
    message->bmcSessionID = endian::from_ipmi<>(header->sessId);
    message->sessionSeqNum = endian::from_ipmi<>(header->sessSeqNum);
    message->isPacketEncrypted = false;
    message->isPacketAuthenticated = false;

    auto payloadLen = header->payloadLength;

    (message->payload).assign(inPacket.data() + sizeof(SessionHeader_t),
                              inPacket.data() + sizeof(SessionHeader_t) +
                              payloadLen);

    return message;
}

std::vector<uint8_t> flatten(Message& outMessage, session::Session& session)
{
    std::vector<uint8_t> packet(sizeof(SessionHeader_t));

    // Insert Session Header into the Packet
    auto header = reinterpret_cast<SessionHeader_t*>(packet.data());
    header->base.version = parser::RMCP_VERSION;
    header->base.reserved = 0x00;
    header->base.rmcpSeqNum = parser::RMCP_SEQ;
    header->base.classOfMsg = parser::RMCP_MESSAGE_CLASS_IPMI;
    header->base.format.formatType =
        static_cast<uint8_t>(parser::SessionHeader::IPMI15);
    header->sessSeqNum = 0;
    header->sessId = endian::to_ipmi<>(outMessage.rcSessionID);

    header->payloadLength = static_cast<uint8_t>(outMessage.payload.size());

    // Insert the Payload into the Packet
    packet.insert(packet.end(), outMessage.payload.begin(),
                  outMessage.payload.end());

    // Insert the Session Trailer
    packet.resize(packet.size() + sizeof(SessionTrailer_t));
    auto trailer = reinterpret_cast<SessionTrailer_t*>(packet.data() +
                   packet.size());
    trailer->legacyPad = 0x00;

    return packet;
}

} // namespace ipmi15parser

namespace ipmi20parser
{

std::unique_ptr<Message> unflatten(std::vector<uint8_t>& inPacket)
{
    // Check if the packet has atleast the Session Header
    if (inPacket.size() < sizeof(SessionHeader_t))
    {
        throw std::runtime_error("IPMI2.0 Session Header Missing");
    }

    auto message = std::make_unique<Message>();

    auto header = reinterpret_cast<SessionHeader_t*>(inPacket.data());

    message->payloadType = static_cast<PayloadType>
                           (header->payloadType & 0x3F);
    message->bmcSessionID = endian::from_ipmi<>(header->sessId);
    message->sessionSeqNum = endian::from_ipmi<>(header->sessSeqNum);
    message->isPacketEncrypted =
        ((header->payloadType & PAYLOAD_ENCRYPT_MASK) ? true : false);
    message->isPacketAuthenticated =
        ((header->payloadType & PAYLOAD_AUTH_MASK) ? true : false);

    auto payloadLen = endian::from_ipmi<>(header->payloadLength);
    message->payload.assign(inPacket.begin() + sizeof(SessionHeader_t),
                            inPacket.begin() + sizeof(SessionHeader_t) +
                            payloadLen);

    return message;
}

std::vector<uint8_t> flatten(Message& outMessage, session::Session& session)
{
    std::vector<uint8_t> packet(sizeof(SessionHeader_t));

    SessionHeader_t* header = reinterpret_cast<SessionHeader_t*>(packet.data());
    header->base.version = parser::RMCP_VERSION;
    header->base.reserved = 0x00;
    header->base.rmcpSeqNum = parser::RMCP_SEQ;
    header->base.classOfMsg = parser::RMCP_MESSAGE_CLASS_IPMI;
    header->base.format.formatType =
        static_cast<uint8_t>(parser::SessionHeader::IPMI20);
    header->payloadType = static_cast<uint8_t>(outMessage.payloadType);
    header->sessId = endian::to_ipmi<>(outMessage.rcSessionID);

    // Add session sequence number
    internal::addSequenceNumber(packet, session);

    // Add Payload
    header->payloadLength = endian::to_ipmi<>(outMessage.payload.size());
    // Insert the Payload into the Packet
    packet.insert(packet.end(), outMessage.payload.begin(),
                  outMessage.payload.end());

    return packet;
}

namespace internal
{

void addSequenceNumber(std::vector<uint8_t>& packet, session::Session& session)
{
    SessionHeader_t* header = reinterpret_cast<SessionHeader_t*>(packet.data());

    if (header->sessId == session::SESSION_ZERO)
    {
        header->sessSeqNum = 0x00;
    }
    else
    {
        auto seqNum = session.sequenceNums.increment();
        header->sessSeqNum = endian::to_ipmi<>(seqNum);
    }
}

} // namespace internal

} // namespace ipmi20parser

} // namespace message