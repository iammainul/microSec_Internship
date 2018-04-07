// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: demo.proto

#include "demo.pb.h"

#include <algorithm>

#include <google/protobuf/stubs/common.h>
#include <google/protobuf/stubs/port.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/wire_format_lite_inl.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// This is a temporary google only hack
#ifdef GOOGLE_PROTOBUF_ENFORCE_UNIQUENESS
#include "third_party/protobuf/version.h"
#endif
// @@protoc_insertion_point(includes)

namespace CSR {
class CSTBSDefaultTypeInternal {
 public:
  ::google::protobuf::internal::ExplicitlyConstructed<CSTBS>
      _instance;
} _CSTBS_default_instance_;
}  // namespace CSR
namespace protobuf_demo_2eproto {
static void InitDefaultsCSTBS() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  {
    void* ptr = &::CSR::_CSTBS_default_instance_;
    new (ptr) ::CSR::CSTBS();
    ::google::protobuf::internal::OnShutdownDestroyMessage(ptr);
  }
  ::CSR::CSTBS::InitAsDefaultInstance();
}

::google::protobuf::internal::SCCInfo<0> scc_info_CSTBS =
    {{ATOMIC_VAR_INIT(::google::protobuf::internal::SCCInfoBase::kUninitialized), 0, InitDefaultsCSTBS}, {}};

void InitDefaults() {
  ::google::protobuf::internal::InitSCC(&scc_info_CSTBS.base);
}

::google::protobuf::Metadata file_level_metadata[1];

const ::google::protobuf::uint32 TableStruct::offsets[] GOOGLE_PROTOBUF_ATTRIBUTE_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(::CSR::CSTBS, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(::CSR::CSTBS, deviceid_),
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(::CSR::CSTBS, orgid_),
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(::CSR::CSTBS, curveid_),
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(::CSR::CSTBS, hashid_),
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(::CSR::CSTBS, pubklen_),
};
static const ::google::protobuf::internal::MigrationSchema schemas[] GOOGLE_PROTOBUF_ATTRIBUTE_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, sizeof(::CSR::CSTBS)},
};

static ::google::protobuf::Message const * const file_default_instances[] = {
  reinterpret_cast<const ::google::protobuf::Message*>(&::CSR::_CSTBS_default_instance_),
};

void protobuf_AssignDescriptors() {
  AddDescriptors();
  AssignDescriptors(
      "demo.proto", schemas, file_default_instances, TableStruct::offsets,
      file_level_metadata, NULL, NULL);
}

void protobuf_AssignDescriptorsOnce() {
  static ::google::protobuf::internal::once_flag once;
  ::google::protobuf::internal::call_once(once, protobuf_AssignDescriptors);
}

void protobuf_RegisterTypes(const ::std::string&) GOOGLE_PROTOBUF_ATTRIBUTE_COLD;
void protobuf_RegisterTypes(const ::std::string&) {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::internal::RegisterAllTypes(file_level_metadata, 1);
}

void AddDescriptorsImpl() {
  InitDefaults();
  static const char descriptor[] GOOGLE_PROTOBUF_ATTRIBUTE_SECTION_VARIABLE(protodesc_cold) = {
      "\n\ndemo.proto\022\003CSR\"Z\n\005CSTBS\022\020\n\010deviceID\030\001"
      " \001(\003\022\r\n\005orgID\030\002 \001(\003\022\017\n\007curveID\030\003 \001(\t\022\016\n\006"
      "hashID\030\004 \001(\t\022\017\n\007pubKLen\030\005 \001(\003b\006proto3"
  };
  ::google::protobuf::DescriptorPool::InternalAddGeneratedFile(
      descriptor, 117);
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedFile(
    "demo.proto", &protobuf_RegisterTypes);
}

void AddDescriptors() {
  static ::google::protobuf::internal::once_flag once;
  ::google::protobuf::internal::call_once(once, AddDescriptorsImpl);
}
// Force AddDescriptors() to be called at dynamic initialization time.
struct StaticDescriptorInitializer {
  StaticDescriptorInitializer() {
    AddDescriptors();
  }
} static_descriptor_initializer;
}  // namespace protobuf_demo_2eproto
namespace CSR {

// ===================================================================

void CSTBS::InitAsDefaultInstance() {
}
#if !defined(_MSC_VER) || _MSC_VER >= 1900
const int CSTBS::kDeviceIDFieldNumber;
const int CSTBS::kOrgIDFieldNumber;
const int CSTBS::kCurveIDFieldNumber;
const int CSTBS::kHashIDFieldNumber;
const int CSTBS::kPubKLenFieldNumber;
#endif  // !defined(_MSC_VER) || _MSC_VER >= 1900

CSTBS::CSTBS()
  : ::google::protobuf::Message(), _internal_metadata_(NULL) {
  ::google::protobuf::internal::InitSCC(
      &protobuf_demo_2eproto::scc_info_CSTBS.base);
  SharedCtor();
  // @@protoc_insertion_point(constructor:CSR.CSTBS)
}
CSTBS::CSTBS(const CSTBS& from)
  : ::google::protobuf::Message(),
      _internal_metadata_(NULL) {
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  curveid_.UnsafeSetDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  if (from.curveid().size() > 0) {
    curveid_.AssignWithDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), from.curveid_);
  }
  hashid_.UnsafeSetDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  if (from.hashid().size() > 0) {
    hashid_.AssignWithDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), from.hashid_);
  }
  ::memcpy(&deviceid_, &from.deviceid_,
    static_cast<size_t>(reinterpret_cast<char*>(&pubklen_) -
    reinterpret_cast<char*>(&deviceid_)) + sizeof(pubklen_));
  // @@protoc_insertion_point(copy_constructor:CSR.CSTBS)
}

void CSTBS::SharedCtor() {
  curveid_.UnsafeSetDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  hashid_.UnsafeSetDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  ::memset(&deviceid_, 0, static_cast<size_t>(
      reinterpret_cast<char*>(&pubklen_) -
      reinterpret_cast<char*>(&deviceid_)) + sizeof(pubklen_));
}

CSTBS::~CSTBS() {
  // @@protoc_insertion_point(destructor:CSR.CSTBS)
  SharedDtor();
}

void CSTBS::SharedDtor() {
  curveid_.DestroyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  hashid_.DestroyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}

void CSTBS::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}
const ::google::protobuf::Descriptor* CSTBS::descriptor() {
  ::protobuf_demo_2eproto::protobuf_AssignDescriptorsOnce();
  return ::protobuf_demo_2eproto::file_level_metadata[kIndexInFileMessages].descriptor;
}

const CSTBS& CSTBS::default_instance() {
  ::google::protobuf::internal::InitSCC(&protobuf_demo_2eproto::scc_info_CSTBS.base);
  return *internal_default_instance();
}


void CSTBS::Clear() {
// @@protoc_insertion_point(message_clear_start:CSR.CSTBS)
  ::google::protobuf::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  curveid_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  hashid_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  ::memset(&deviceid_, 0, static_cast<size_t>(
      reinterpret_cast<char*>(&pubklen_) -
      reinterpret_cast<char*>(&deviceid_)) + sizeof(pubklen_));
  _internal_metadata_.Clear();
}

bool CSTBS::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!GOOGLE_PREDICT_TRUE(EXPRESSION)) goto failure
  ::google::protobuf::uint32 tag;
  // @@protoc_insertion_point(parse_start:CSR.CSTBS)
  for (;;) {
    ::std::pair<::google::protobuf::uint32, bool> p = input->ReadTagWithCutoffNoLastTag(127u);
    tag = p.first;
    if (!p.second) goto handle_unusual;
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // int64 deviceID = 1;
      case 1: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(8u /* 8 & 0xFF */)) {

          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::int64, ::google::protobuf::internal::WireFormatLite::TYPE_INT64>(
                 input, &deviceid_)));
        } else {
          goto handle_unusual;
        }
        break;
      }

      // int64 orgID = 2;
      case 2: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(16u /* 16 & 0xFF */)) {

          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::int64, ::google::protobuf::internal::WireFormatLite::TYPE_INT64>(
                 input, &orgid_)));
        } else {
          goto handle_unusual;
        }
        break;
      }

      // string curveID = 3;
      case 3: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(26u /* 26 & 0xFF */)) {
          DO_(::google::protobuf::internal::WireFormatLite::ReadString(
                input, this->mutable_curveid()));
          DO_(::google::protobuf::internal::WireFormatLite::VerifyUtf8String(
            this->curveid().data(), static_cast<int>(this->curveid().length()),
            ::google::protobuf::internal::WireFormatLite::PARSE,
            "CSR.CSTBS.curveID"));
        } else {
          goto handle_unusual;
        }
        break;
      }

      // string hashID = 4;
      case 4: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(34u /* 34 & 0xFF */)) {
          DO_(::google::protobuf::internal::WireFormatLite::ReadString(
                input, this->mutable_hashid()));
          DO_(::google::protobuf::internal::WireFormatLite::VerifyUtf8String(
            this->hashid().data(), static_cast<int>(this->hashid().length()),
            ::google::protobuf::internal::WireFormatLite::PARSE,
            "CSR.CSTBS.hashID"));
        } else {
          goto handle_unusual;
        }
        break;
      }

      // int64 pubKLen = 5;
      case 5: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(40u /* 40 & 0xFF */)) {

          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::int64, ::google::protobuf::internal::WireFormatLite::TYPE_INT64>(
                 input, &pubklen_)));
        } else {
          goto handle_unusual;
        }
        break;
      }

      default: {
      handle_unusual:
        if (tag == 0) {
          goto success;
        }
        DO_(::google::protobuf::internal::WireFormat::SkipField(
              input, tag, _internal_metadata_.mutable_unknown_fields()));
        break;
      }
    }
  }
success:
  // @@protoc_insertion_point(parse_success:CSR.CSTBS)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:CSR.CSTBS)
  return false;
#undef DO_
}

void CSTBS::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:CSR.CSTBS)
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // int64 deviceID = 1;
  if (this->deviceid() != 0) {
    ::google::protobuf::internal::WireFormatLite::WriteInt64(1, this->deviceid(), output);
  }

  // int64 orgID = 2;
  if (this->orgid() != 0) {
    ::google::protobuf::internal::WireFormatLite::WriteInt64(2, this->orgid(), output);
  }

  // string curveID = 3;
  if (this->curveid().size() > 0) {
    ::google::protobuf::internal::WireFormatLite::VerifyUtf8String(
      this->curveid().data(), static_cast<int>(this->curveid().length()),
      ::google::protobuf::internal::WireFormatLite::SERIALIZE,
      "CSR.CSTBS.curveID");
    ::google::protobuf::internal::WireFormatLite::WriteStringMaybeAliased(
      3, this->curveid(), output);
  }

  // string hashID = 4;
  if (this->hashid().size() > 0) {
    ::google::protobuf::internal::WireFormatLite::VerifyUtf8String(
      this->hashid().data(), static_cast<int>(this->hashid().length()),
      ::google::protobuf::internal::WireFormatLite::SERIALIZE,
      "CSR.CSTBS.hashID");
    ::google::protobuf::internal::WireFormatLite::WriteStringMaybeAliased(
      4, this->hashid(), output);
  }

  // int64 pubKLen = 5;
  if (this->pubklen() != 0) {
    ::google::protobuf::internal::WireFormatLite::WriteInt64(5, this->pubklen(), output);
  }

  if ((_internal_metadata_.have_unknown_fields() &&  ::google::protobuf::internal::GetProto3PreserveUnknownsDefault())) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        (::google::protobuf::internal::GetProto3PreserveUnknownsDefault()   ? _internal_metadata_.unknown_fields()   : _internal_metadata_.default_instance()), output);
  }
  // @@protoc_insertion_point(serialize_end:CSR.CSTBS)
}

::google::protobuf::uint8* CSTBS::InternalSerializeWithCachedSizesToArray(
    bool deterministic, ::google::protobuf::uint8* target) const {
  (void)deterministic; // Unused
  // @@protoc_insertion_point(serialize_to_array_start:CSR.CSTBS)
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // int64 deviceID = 1;
  if (this->deviceid() != 0) {
    target = ::google::protobuf::internal::WireFormatLite::WriteInt64ToArray(1, this->deviceid(), target);
  }

  // int64 orgID = 2;
  if (this->orgid() != 0) {
    target = ::google::protobuf::internal::WireFormatLite::WriteInt64ToArray(2, this->orgid(), target);
  }

  // string curveID = 3;
  if (this->curveid().size() > 0) {
    ::google::protobuf::internal::WireFormatLite::VerifyUtf8String(
      this->curveid().data(), static_cast<int>(this->curveid().length()),
      ::google::protobuf::internal::WireFormatLite::SERIALIZE,
      "CSR.CSTBS.curveID");
    target =
      ::google::protobuf::internal::WireFormatLite::WriteStringToArray(
        3, this->curveid(), target);
  }

  // string hashID = 4;
  if (this->hashid().size() > 0) {
    ::google::protobuf::internal::WireFormatLite::VerifyUtf8String(
      this->hashid().data(), static_cast<int>(this->hashid().length()),
      ::google::protobuf::internal::WireFormatLite::SERIALIZE,
      "CSR.CSTBS.hashID");
    target =
      ::google::protobuf::internal::WireFormatLite::WriteStringToArray(
        4, this->hashid(), target);
  }

  // int64 pubKLen = 5;
  if (this->pubklen() != 0) {
    target = ::google::protobuf::internal::WireFormatLite::WriteInt64ToArray(5, this->pubklen(), target);
  }

  if ((_internal_metadata_.have_unknown_fields() &&  ::google::protobuf::internal::GetProto3PreserveUnknownsDefault())) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        (::google::protobuf::internal::GetProto3PreserveUnknownsDefault()   ? _internal_metadata_.unknown_fields()   : _internal_metadata_.default_instance()), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:CSR.CSTBS)
  return target;
}

size_t CSTBS::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:CSR.CSTBS)
  size_t total_size = 0;

  if ((_internal_metadata_.have_unknown_fields() &&  ::google::protobuf::internal::GetProto3PreserveUnknownsDefault())) {
    total_size +=
      ::google::protobuf::internal::WireFormat::ComputeUnknownFieldsSize(
        (::google::protobuf::internal::GetProto3PreserveUnknownsDefault()   ? _internal_metadata_.unknown_fields()   : _internal_metadata_.default_instance()));
  }
  // string curveID = 3;
  if (this->curveid().size() > 0) {
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::StringSize(
        this->curveid());
  }

  // string hashID = 4;
  if (this->hashid().size() > 0) {
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::StringSize(
        this->hashid());
  }

  // int64 deviceID = 1;
  if (this->deviceid() != 0) {
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::Int64Size(
        this->deviceid());
  }

  // int64 orgID = 2;
  if (this->orgid() != 0) {
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::Int64Size(
        this->orgid());
  }

  // int64 pubKLen = 5;
  if (this->pubklen() != 0) {
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::Int64Size(
        this->pubklen());
  }

  int cached_size = ::google::protobuf::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void CSTBS::MergeFrom(const ::google::protobuf::Message& from) {
// @@protoc_insertion_point(generalized_merge_from_start:CSR.CSTBS)
  GOOGLE_DCHECK_NE(&from, this);
  const CSTBS* source =
      ::google::protobuf::internal::DynamicCastToGenerated<const CSTBS>(
          &from);
  if (source == NULL) {
  // @@protoc_insertion_point(generalized_merge_from_cast_fail:CSR.CSTBS)
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
  // @@protoc_insertion_point(generalized_merge_from_cast_success:CSR.CSTBS)
    MergeFrom(*source);
  }
}

void CSTBS::MergeFrom(const CSTBS& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:CSR.CSTBS)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if (from.curveid().size() > 0) {

    curveid_.AssignWithDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), from.curveid_);
  }
  if (from.hashid().size() > 0) {

    hashid_.AssignWithDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), from.hashid_);
  }
  if (from.deviceid() != 0) {
    set_deviceid(from.deviceid());
  }
  if (from.orgid() != 0) {
    set_orgid(from.orgid());
  }
  if (from.pubklen() != 0) {
    set_pubklen(from.pubklen());
  }
}

void CSTBS::CopyFrom(const ::google::protobuf::Message& from) {
// @@protoc_insertion_point(generalized_copy_from_start:CSR.CSTBS)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void CSTBS::CopyFrom(const CSTBS& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:CSR.CSTBS)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool CSTBS::IsInitialized() const {
  return true;
}

void CSTBS::Swap(CSTBS* other) {
  if (other == this) return;
  InternalSwap(other);
}
void CSTBS::InternalSwap(CSTBS* other) {
  using std::swap;
  curveid_.Swap(&other->curveid_, &::google::protobuf::internal::GetEmptyStringAlreadyInited(),
    GetArenaNoVirtual());
  hashid_.Swap(&other->hashid_, &::google::protobuf::internal::GetEmptyStringAlreadyInited(),
    GetArenaNoVirtual());
  swap(deviceid_, other->deviceid_);
  swap(orgid_, other->orgid_);
  swap(pubklen_, other->pubklen_);
  _internal_metadata_.Swap(&other->_internal_metadata_);
}

::google::protobuf::Metadata CSTBS::GetMetadata() const {
  protobuf_demo_2eproto::protobuf_AssignDescriptorsOnce();
  return ::protobuf_demo_2eproto::file_level_metadata[kIndexInFileMessages];
}


// @@protoc_insertion_point(namespace_scope)
}  // namespace CSR
namespace google {
namespace protobuf {
template<> GOOGLE_PROTOBUF_ATTRIBUTE_NOINLINE ::CSR::CSTBS* Arena::CreateMaybeMessage< ::CSR::CSTBS >(Arena* arena) {
  return Arena::CreateInternal< ::CSR::CSTBS >(arena);
}
}  // namespace protobuf
}  // namespace google

// @@protoc_insertion_point(global_scope)