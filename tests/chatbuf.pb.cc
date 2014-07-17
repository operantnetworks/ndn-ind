// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: chatbuf.proto

#define INTERNAL_SUPPRESS_PROTOBUF_FIELD_DEPRECATION
#include "chatbuf.pb.h"

#include <algorithm>

#include <google/protobuf/stubs/common.h>
#include <google/protobuf/stubs/once.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/wire_format_lite_inl.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)

namespace SyncDemo {

namespace {

const ::google::protobuf::Descriptor* ChatMessage_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  ChatMessage_reflection_ = NULL;
const ::google::protobuf::EnumDescriptor* ChatMessage_ChatMessageType_descriptor_ = NULL;

}  // namespace


void protobuf_AssignDesc_chatbuf_2eproto() {
  protobuf_AddDesc_chatbuf_2eproto();
  const ::google::protobuf::FileDescriptor* file =
    ::google::protobuf::DescriptorPool::generated_pool()->FindFileByName(
      "chatbuf.proto");
  GOOGLE_CHECK(file != NULL);
  ChatMessage_descriptor_ = file->message_type(0);
  static const int ChatMessage_offsets_[5] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ChatMessage, to_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ChatMessage, from_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ChatMessage, type_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ChatMessage, data_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ChatMessage, timestamp_),
  };
  ChatMessage_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      ChatMessage_descriptor_,
      ChatMessage::default_instance_,
      ChatMessage_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ChatMessage, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(ChatMessage, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      ::google::protobuf::MessageFactory::generated_factory(),
      sizeof(ChatMessage));
  ChatMessage_ChatMessageType_descriptor_ = ChatMessage_descriptor_->enum_type(0);
}

namespace {

GOOGLE_PROTOBUF_DECLARE_ONCE(protobuf_AssignDescriptors_once_);
inline void protobuf_AssignDescriptorsOnce() {
  ::google::protobuf::GoogleOnceInit(&protobuf_AssignDescriptors_once_,
                 &protobuf_AssignDesc_chatbuf_2eproto);
}

void protobuf_RegisterTypes(const ::std::string&) {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    ChatMessage_descriptor_, &ChatMessage::default_instance());
}

}  // namespace

void protobuf_ShutdownFile_chatbuf_2eproto() {
  delete ChatMessage::default_instance_;
  delete ChatMessage_reflection_;
}

void protobuf_AddDesc_chatbuf_2eproto() {
  static bool already_here = false;
  if (already_here) return;
  already_here = true;
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  ::google::protobuf::DescriptorPool::InternalAddGeneratedFile(
    "\n\rchatbuf.proto\022\010SyncDemo\"\313\001\n\013ChatMessag"
    "e\022\n\n\002to\030\001 \002(\t\022\014\n\004from\030\002 \002(\t\0229\n\004type\030\003 \002("
    "\0162%.SyncDemo.ChatMessage.ChatMessageType"
    ":\004CHAT\022\014\n\004data\030\004 \001(\t\022\021\n\ttimestamp\030\005 \002(\005\""
    "F\n\017ChatMessageType\022\010\n\004CHAT\020\000\022\t\n\005HELLO\020\001\022"
    "\t\n\005LEAVE\020\002\022\010\n\004JOIN\020\003\022\t\n\005OTHER\020\004", 231);
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedFile(
    "chatbuf.proto", &protobuf_RegisterTypes);
  ChatMessage::default_instance_ = new ChatMessage();
  ChatMessage::default_instance_->InitAsDefaultInstance();
  ::google::protobuf::internal::OnShutdown(&protobuf_ShutdownFile_chatbuf_2eproto);
}

// Force AddDescriptors() to be called at static initialization time.
struct StaticDescriptorInitializer_chatbuf_2eproto {
  StaticDescriptorInitializer_chatbuf_2eproto() {
    protobuf_AddDesc_chatbuf_2eproto();
  }
} static_descriptor_initializer_chatbuf_2eproto_;

// ===================================================================

const ::google::protobuf::EnumDescriptor* ChatMessage_ChatMessageType_descriptor() {
  protobuf_AssignDescriptorsOnce();
  return ChatMessage_ChatMessageType_descriptor_;
}
bool ChatMessage_ChatMessageType_IsValid(int value) {
  switch(value) {
    case 0:
    case 1:
    case 2:
    case 3:
    case 4:
      return true;
    default:
      return false;
  }
}

#ifndef _MSC_VER
const ChatMessage_ChatMessageType ChatMessage::CHAT;
const ChatMessage_ChatMessageType ChatMessage::HELLO;
const ChatMessage_ChatMessageType ChatMessage::LEAVE;
const ChatMessage_ChatMessageType ChatMessage::JOIN;
const ChatMessage_ChatMessageType ChatMessage::OTHER;
const ChatMessage_ChatMessageType ChatMessage::ChatMessageType_MIN;
const ChatMessage_ChatMessageType ChatMessage::ChatMessageType_MAX;
const int ChatMessage::ChatMessageType_ARRAYSIZE;
#endif  // _MSC_VER
#ifndef _MSC_VER
const int ChatMessage::kToFieldNumber;
const int ChatMessage::kFromFieldNumber;
const int ChatMessage::kTypeFieldNumber;
const int ChatMessage::kDataFieldNumber;
const int ChatMessage::kTimestampFieldNumber;
#endif  // !_MSC_VER

ChatMessage::ChatMessage()
  : ::google::protobuf::Message() {
  SharedCtor();
}

void ChatMessage::InitAsDefaultInstance() {
}

ChatMessage::ChatMessage(const ChatMessage& from)
  : ::google::protobuf::Message() {
  SharedCtor();
  MergeFrom(from);
}

void ChatMessage::SharedCtor() {
  _cached_size_ = 0;
  to_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
  from_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
  type_ = 0;
  data_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
  timestamp_ = 0;
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

ChatMessage::~ChatMessage() {
  SharedDtor();
}

void ChatMessage::SharedDtor() {
  if (to_ != &::google::protobuf::internal::kEmptyString) {
    delete to_;
  }
  if (from_ != &::google::protobuf::internal::kEmptyString) {
    delete from_;
  }
  if (data_ != &::google::protobuf::internal::kEmptyString) {
    delete data_;
  }
  if (this != default_instance_) {
  }
}

void ChatMessage::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* ChatMessage::descriptor() {
  protobuf_AssignDescriptorsOnce();
  return ChatMessage_descriptor_;
}

const ChatMessage& ChatMessage::default_instance() {
  if (default_instance_ == NULL) protobuf_AddDesc_chatbuf_2eproto();
  return *default_instance_;
}

ChatMessage* ChatMessage::default_instance_ = NULL;

ChatMessage* ChatMessage::New() const {
  return new ChatMessage;
}

void ChatMessage::Clear() {
  if (_has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    if (has_to()) {
      if (to_ != &::google::protobuf::internal::kEmptyString) {
        to_->clear();
      }
    }
    if (has_from()) {
      if (from_ != &::google::protobuf::internal::kEmptyString) {
        from_->clear();
      }
    }
    type_ = 0;
    if (has_data()) {
      if (data_ != &::google::protobuf::internal::kEmptyString) {
        data_->clear();
      }
    }
    timestamp_ = 0;
  }
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  mutable_unknown_fields()->Clear();
}

bool ChatMessage::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!(EXPRESSION)) return false
  ::google::protobuf::uint32 tag;
  while ((tag = input->ReadTag()) != 0) {
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // required string to = 1;
      case 1: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_LENGTH_DELIMITED) {
          DO_(::google::protobuf::internal::WireFormatLite::ReadString(
                input, this->mutable_to()));
          ::google::protobuf::internal::WireFormat::VerifyUTF8String(
            this->to().data(), this->to().length(),
            ::google::protobuf::internal::WireFormat::PARSE);
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectTag(18)) goto parse_from;
        break;
      }

      // required string from = 2;
      case 2: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_LENGTH_DELIMITED) {
         parse_from:
          DO_(::google::protobuf::internal::WireFormatLite::ReadString(
                input, this->mutable_from()));
          ::google::protobuf::internal::WireFormat::VerifyUTF8String(
            this->from().data(), this->from().length(),
            ::google::protobuf::internal::WireFormat::PARSE);
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectTag(24)) goto parse_type;
        break;
      }

      // required .SyncDemo.ChatMessage.ChatMessageType type = 3 [default = CHAT];
      case 3: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_VARINT) {
         parse_type:
          int value;
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   int, ::google::protobuf::internal::WireFormatLite::TYPE_ENUM>(
                 input, &value)));
          if (::SyncDemo::ChatMessage_ChatMessageType_IsValid(value)) {
            set_type(static_cast< ::SyncDemo::ChatMessage_ChatMessageType >(value));
          } else {
            mutable_unknown_fields()->AddVarint(3, value);
          }
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectTag(34)) goto parse_data;
        break;
      }

      // optional string data = 4;
      case 4: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_LENGTH_DELIMITED) {
         parse_data:
          DO_(::google::protobuf::internal::WireFormatLite::ReadString(
                input, this->mutable_data()));
          ::google::protobuf::internal::WireFormat::VerifyUTF8String(
            this->data().data(), this->data().length(),
            ::google::protobuf::internal::WireFormat::PARSE);
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectTag(40)) goto parse_timestamp;
        break;
      }

      // required int32 timestamp = 5;
      case 5: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_VARINT) {
         parse_timestamp:
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::int32, ::google::protobuf::internal::WireFormatLite::TYPE_INT32>(
                 input, &timestamp_)));
          set_has_timestamp();
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectAtEnd()) return true;
        break;
      }

      default: {
      handle_uninterpreted:
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_END_GROUP) {
          return true;
        }
        DO_(::google::protobuf::internal::WireFormat::SkipField(
              input, tag, mutable_unknown_fields()));
        break;
      }
    }
  }
  return true;
#undef DO_
}

void ChatMessage::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // required string to = 1;
  if (has_to()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8String(
      this->to().data(), this->to().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE);
    ::google::protobuf::internal::WireFormatLite::WriteString(
      1, this->to(), output);
  }

  // required string from = 2;
  if (has_from()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8String(
      this->from().data(), this->from().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE);
    ::google::protobuf::internal::WireFormatLite::WriteString(
      2, this->from(), output);
  }

  // required .SyncDemo.ChatMessage.ChatMessageType type = 3 [default = CHAT];
  if (has_type()) {
    ::google::protobuf::internal::WireFormatLite::WriteEnum(
      3, this->type(), output);
  }

  // optional string data = 4;
  if (has_data()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8String(
      this->data().data(), this->data().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE);
    ::google::protobuf::internal::WireFormatLite::WriteString(
      4, this->data(), output);
  }

  // required int32 timestamp = 5;
  if (has_timestamp()) {
    ::google::protobuf::internal::WireFormatLite::WriteInt32(5, this->timestamp(), output);
  }

  if (!unknown_fields().empty()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        unknown_fields(), output);
  }
}

::google::protobuf::uint8* ChatMessage::SerializeWithCachedSizesToArray(
    ::google::protobuf::uint8* target) const {
  // required string to = 1;
  if (has_to()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8String(
      this->to().data(), this->to().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE);
    target =
      ::google::protobuf::internal::WireFormatLite::WriteStringToArray(
        1, this->to(), target);
  }

  // required string from = 2;
  if (has_from()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8String(
      this->from().data(), this->from().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE);
    target =
      ::google::protobuf::internal::WireFormatLite::WriteStringToArray(
        2, this->from(), target);
  }

  // required .SyncDemo.ChatMessage.ChatMessageType type = 3 [default = CHAT];
  if (has_type()) {
    target = ::google::protobuf::internal::WireFormatLite::WriteEnumToArray(
      3, this->type(), target);
  }

  // optional string data = 4;
  if (has_data()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8String(
      this->data().data(), this->data().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE);
    target =
      ::google::protobuf::internal::WireFormatLite::WriteStringToArray(
        4, this->data(), target);
  }

  // required int32 timestamp = 5;
  if (has_timestamp()) {
    target = ::google::protobuf::internal::WireFormatLite::WriteInt32ToArray(5, this->timestamp(), target);
  }

  if (!unknown_fields().empty()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        unknown_fields(), target);
  }
  return target;
}

int ChatMessage::ByteSize() const {
  int total_size = 0;

  if (_has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    // required string to = 1;
    if (has_to()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::StringSize(
          this->to());
    }

    // required string from = 2;
    if (has_from()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::StringSize(
          this->from());
    }

    // required .SyncDemo.ChatMessage.ChatMessageType type = 3 [default = CHAT];
    if (has_type()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::EnumSize(this->type());
    }

    // optional string data = 4;
    if (has_data()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::StringSize(
          this->data());
    }

    // required int32 timestamp = 5;
    if (has_timestamp()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::Int32Size(
          this->timestamp());
    }

  }
  if (!unknown_fields().empty()) {
    total_size +=
      ::google::protobuf::internal::WireFormat::ComputeUnknownFieldsSize(
        unknown_fields());
  }
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = total_size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
  return total_size;
}

void ChatMessage::MergeFrom(const ::google::protobuf::Message& from) {
  GOOGLE_CHECK_NE(&from, this);
  const ChatMessage* source =
    ::google::protobuf::internal::dynamic_cast_if_available<const ChatMessage*>(
      &from);
  if (source == NULL) {
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
    MergeFrom(*source);
  }
}

void ChatMessage::MergeFrom(const ChatMessage& from) {
  GOOGLE_CHECK_NE(&from, this);
  if (from._has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    if (from.has_to()) {
      set_to(from.to());
    }
    if (from.has_from()) {
      set_from(from.from());
    }
    if (from.has_type()) {
      set_type(from.type());
    }
    if (from.has_data()) {
      set_data(from.data());
    }
    if (from.has_timestamp()) {
      set_timestamp(from.timestamp());
    }
  }
  mutable_unknown_fields()->MergeFrom(from.unknown_fields());
}

void ChatMessage::CopyFrom(const ::google::protobuf::Message& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void ChatMessage::CopyFrom(const ChatMessage& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool ChatMessage::IsInitialized() const {
  if ((_has_bits_[0] & 0x00000017) != 0x00000017) return false;

  return true;
}

void ChatMessage::Swap(ChatMessage* other) {
  if (other != this) {
    std::swap(to_, other->to_);
    std::swap(from_, other->from_);
    std::swap(type_, other->type_);
    std::swap(data_, other->data_);
    std::swap(timestamp_, other->timestamp_);
    std::swap(_has_bits_[0], other->_has_bits_[0]);
    _unknown_fields_.Swap(&other->_unknown_fields_);
    std::swap(_cached_size_, other->_cached_size_);
  }
}

::google::protobuf::Metadata ChatMessage::GetMetadata() const {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::Metadata metadata;
  metadata.descriptor = ChatMessage_descriptor_;
  metadata.reflection = ChatMessage_reflection_;
  return metadata;
}


// @@protoc_insertion_point(namespace_scope)

}  // namespace SyncDemo

// @@protoc_insertion_point(global_scope)
