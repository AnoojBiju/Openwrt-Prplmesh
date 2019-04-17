#include <mapf/common/socket.h>
#include <mapf/common/message_factory.h>
#include <mapf/common/err.h>
#include <mapf/common/logger.h>
#include <algorithm>

//#define MAPF_DEBUG
#ifdef MAPF_DEBUG
#define DBG MAPF_DBG
#else
#define DBG(...)
#endif

namespace mapf
{

/* PUB socket API */
size_t PubSocket::Send(const void *buf, size_t len, int flags)
{
	if (connected() == false) {
		errno = ENOTCONN;
		return -1;
	}

	int nbytes = zmq_send(ptr_, buf, len, flags);
	if (nbytes >= 0) {
		if (nbytes != int(len))
			errno = EIO;
		return (size_t)nbytes;
	}
	if (zmq_errno () == EAGAIN)
		return 0;
	return -1;
}

bool PubSocket::Send(const Message::Frame &frame, int flags)
{
	size_t nbytes = Send(frame.get(), frame.len(), flags);
	DBG("Send frame len=" << frame.len() << " flags=" << flags);
	if (nbytes != frame.len()) {
		MAPF_ERR("message send failed, errno=" << strerror(errno));
		return false;
	}
	return true;
}

bool PubSocket::Send(const Message &msg, int flags)
{
	mapf_assert(msg.version() == Message::kMessageHeaderVersion);
	mapf_assert(msg.len() <= Message::kMaxFrameLength);

	size_t nframes = msg.frames().size();

	// first, send the topic
	flags |= ZMQ_SNDMORE;
	DBG("sending topic=" << msg.topic() << " flags=" << flags);
	size_t nbytes = Send(msg.topic().data(), msg.topic().length(), flags);
	if (nbytes != msg.topic().length()) {
		MAPF_ERR("topic send failed, errno=" << strerror(errno));
		return false;
	}

	// next send the header
	Message::Header hdr = msg.header();
	flags = (nframes) ? flags | ZMQ_SNDMORE : flags & ~ZMQ_SNDMORE;
	DBG("sending header len=" << msg.len() << " flags=" << flags);
	nbytes = Send(&hdr, sizeof(hdr), flags);
	if (nbytes != sizeof(hdr)) {
		MAPF_ERR("header send failed, errno=" << strerror(errno));
		return false;
	}

	// Finally, Send all data frames
	for (auto frame:msg.frames()) {
		flags = (--nframes) ? flags | ZMQ_SNDMORE : flags & ~ZMQ_SNDMORE;
		if (false == Send(frame, flags))
			return false;
	}

	DBG("message sent");
	return true;
}

bool PubSocket::Send(const std::unique_ptr<Message>& msg, int flags)
{
	mapf_assert(msg);
	return Send(*msg, flags);
}

/* SUB socket API */
int SubSocket::Subscribe(const std::string& topic)
{
	errno = 0;
	int rc = zmq_setsockopt(ptr_, ZMQ_SUBSCRIBE, topic.c_str(), topic.length());
	if (rc) {
		MAPF_ERR("Subscribe " << topic << "failed, errno=" << strerror(errno));
		return rc;
	}

	AddSubscription(topic);
	return 0;
}

int SubSocket::Subscribe(const std::initializer_list<std::string>& topics)
{
	for (auto& topic:topics) {
		Subscribe(topic);
	}	
	return 0;
}

int SubSocket::Unsubscribe(const std::string& topic)
{
	if (topic.empty()) return 0;
	int rc = zmq_setsockopt(ptr_, ZMQ_UNSUBSCRIBE, topic.c_str(), topic.length());
	if (rc == 0)
		EraseSubscription(topic);
	return rc;
}

int SubSocket::Unsubscribe(std::initializer_list<std::string> topics)
{
	for (auto& topic:topics)
		Unsubscribe(topic);

	return 0;
}

ssize_t SubSocket::Receive(void *buf, size_t len, int flags)
{
	if (connected() == false) {
		errno = ENOTCONN;
		return -1;
	}

	int nbytes = zmq_recv(ptr_, buf, len, flags);
	if (nbytes >= 0)
		return (size_t) nbytes;
	if (zmq_errno () == EAGAIN)
		return 0;

	return -1;
}

bool SubSocket::Receive(Message::Frame& frame, int flags)
{
	int nbytes = Receive(frame.get(), frame.len(), flags);
	if (nbytes == -1) {
		MAPF_ERR("zmq_recv failed with error " << strerror(errno));
		return false;
	}

	return true;
}

bool SubSocket::Receive(Message& msg, int flags)
{
	msg.Clear();

	/** first, receive the topic */
	auto topic = ReceiveTopic(flags);
	if (topic == nullptr)
		return false;
	msg.set_topic(*topic);

	if (false == More())
		return true; // message with topic only, allowed

	/** next, receive the header */
	auto hdr = ReceiveHeader(flags);
	if (hdr == nullptr)
		return false;

	if (false == More()) {
		mapf_assert(hdr->len == 0);
		DBG("message with topic only received");
		return true; // message with header only, allowed
	}

	/** finally, receive all the rest of the message parts to a
	 *  single frame */
	Message::Frame frame = ReceiveFrames(hdr->len, flags);
	msg.Add(frame);

	DBG("message received");
	return true;
}

std::unique_ptr<Message> SubSocket::Receive(int flags)
{
	/** first, receive the topic */
	auto topic = ReceiveTopic(flags);
	if (topic == nullptr)
		return nullptr;

	/** next, receive the header */
	auto hdr = ReceiveHeader(flags);
	if (hdr == nullptr)
		return nullptr;

	if (false == More()) {
		mapf_assert(hdr->len == 0);
		DBG("message with topic only received");
		return MessageFactory::Instance().Create(*topic); // message with header only, allowed
	}

	/** finally, receive all the rest of the message parts to a
	 *  single frame */
	Message::Frame frame = ReceiveFrames(hdr->len, flags);
	DBG("message received");
	return MessageFactory::Instance().Create(*topic, {frame});
}

/* SUB Socket Private */
std::unique_ptr<std::string>
SubSocket::ReceiveTopic(int flags)
{
	char topic[Message::kMaxTopicSize];
	int nbytes = Receive(topic, sizeof(topic) - 1, flags);
	if (nbytes == -1) {
		MAPF_ERR("topic receive failed, errno=" << strerror(errno));
		return nullptr;
	}
	topic[nbytes] = 0;
	DBG("received topic=" << topic);
	return std::unique_ptr<std::string>(new std::string(topic));
}

std::unique_ptr<Message::Header>
SubSocket::ReceiveHeader(int flags)
{
	Message::Header hdr;
	ssize_t nbytes = Receive(&hdr, sizeof(hdr), flags);
	if (nbytes == -1) {
		MAPF_ERR("header receive failed, errno=" << strerror(errno));
		return nullptr;
	}
	DBG("received header len=" << hdr.len << " more=" << More());
	// we do not support different header versions YET
	mapf_assert(hdr.version == Message::kMessageHeaderVersion);
	mapf_assert(hdr.len <= Message::kMaxFrameLength);
	return std::unique_ptr<Message::Header>(new Message::Header(hdr));
}

Message::Frame SubSocket::ReceiveFrames(size_t total_len, int flags)
{
	Message::Frame frame(total_len);
	uint8_t *ptr = frame.get();
	size_t len = 0;
	do {
		len += Receive(ptr + len, total_len - len, flags);
		mapf_assert(len <= total_len); //total length mismatch!
	} while (More());

	mapf_assert(len == total_len);
	return frame; // allowed since Message::Frame contains a shared pointer
}

bool SubSocket::More() const
{
	int more;
	size_t len = sizeof(more);
	int rc = zmq_getsockopt(ptr_, ZMQ_RCVMORE, &more, &len);
	errno_assert(rc == 0);
	return more;
}

std::vector<std::string>::iterator
SubSocket::FindSubscription(const std::string& topic)
{
	return std::find_if(topics_.begin(), topics_.end(),
					   [&topic](const std::string &item) {
						   return item == topic;
						});
}

void SubSocket::AddSubscription(const std::string& topic)
{
	auto it = FindSubscription(topic);
	if (it == topics_.end())
		topics_.push_back(topic);
}

void SubSocket::EraseSubscription(const std::string& topic)
{
	auto it = FindSubscription(topic);
	if (it != topics_.end())
		topics_.erase(it);
}

} // namespace mapf
