// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: csr.proto

#ifndef PROTOBUF_INCLUDED_csr_2eproto
#define PROTOBUF_INCLUDED_csr_2eproto

#include <string>

#include <google/protobuf/stubs/common.h>

#if GOOGLE_PROTOBUF_VERSION < 3005000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please update
#error your headers.
#endif
#if 3005001 < GOOGLE_PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/arena.h>
#include <google/protobuf/arenastring.h>
#include <google/protobuf/generated_message_table_driven.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/inlined_string_field.h>
#include <google/protobuf/metadata.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>  // IWYU pragma: export
#include <google/protobuf/extension_set.h>  // IWYU pragma: export
#include <google/protobuf/unknown_field_set.h>
// @@protoc_insertion_point(includes)
#define PROTOBUF_INTERNAL_EXPORT_protobuf_csr_2eproto 

namespace protobuf_csr_2eproto {
// Internal implementation detail -- do not use these members.
struct TableStruct {
  static const ::google::protobuf::internal::ParseTableField entries[];
  static const ::google::protobuf::internal::AuxillaryParseTableField aux[];
  static const ::google::protobuf::internal::ParseTable schema[3];
  static const ::google::protobuf::internal::FieldMetadata field_metadata[];
  static const ::google::protobuf::internal::SerializationTable serialization_table[];
  static const ::google::protobuf::uint32 offsets[];
};
void AddDescriptors();
}  // namespace protobuf_csr_2eproto
namespace CSR {
class CA;
class CADefaultTypeInternal;
extern CADefaultTypeInternal _CA_default_instance_;
class CSTBS;
class CSTBSDefaultTypeInternal;
extern CSTBSDefaultTypeInternal _CSTBS_default_instance_;
class MCSR;
class MCSRDefaultTypeInternal;
extern MCSRDefaultTypeInternal _MCSR_default_instance_;
}  // namespace CSR
namespace google {
namespace protobuf {
template<> ::CSR::CA* Arena::CreateMaybeMessage<::CSR::CA>(Arena*);
template<> ::CSR::CSTBS* Arena::CreateMaybeMessage<::CSR::CSTBS>(Arena*);
template<> ::CSR::MCSR* Arena::CreateMaybeMessage<::CSR::MCSR>(Arena*);
}  // namespace protobuf
}  // namespace google
namespace CSR {

// ===================================================================

class CSTBS : public ::google::protobuf::Message /* @@protoc_insertion_point(class_definition:CSR.CSTBS) */ {
 public:
  CSTBS();
  virtual ~CSTBS();

  CSTBS(const CSTBS& from);

  inline CSTBS& operator=(const CSTBS& from) {
    CopyFrom(from);
    return *this;
  }
  #if LANG_CXX11
  CSTBS(CSTBS&& from) noexcept
    : CSTBS() {
    *this = ::std::move(from);
  }

  inline CSTBS& operator=(CSTBS&& from) noexcept {
    if (GetArenaNoVirtual() == from.GetArenaNoVirtual()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }
  #endif
  static const ::google::protobuf::Descriptor* descriptor();
  static const CSTBS& default_instance();

  static void InitAsDefaultInstance();  // FOR INTERNAL USE ONLY
  static inline const CSTBS* internal_default_instance() {
    return reinterpret_cast<const CSTBS*>(
               &_CSTBS_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    0;

  void Swap(CSTBS* other);
  friend void swap(CSTBS& a, CSTBS& b) {
    a.Swap(&b);
  }

  // implements Message ----------------------------------------------

  inline CSTBS* New() const final {
    return CreateMaybeMessage<CSTBS>(NULL);
  }

  CSTBS* New(::google::protobuf::Arena* arena) const final {
    return CreateMaybeMessage<CSTBS>(arena);
  }
  void CopyFrom(const ::google::protobuf::Message& from) final;
  void MergeFrom(const ::google::protobuf::Message& from) final;
  void CopyFrom(const CSTBS& from);
  void MergeFrom(const CSTBS& from);
  void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input) final;
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const final;
  ::google::protobuf::uint8* InternalSerializeWithCachedSizesToArray(
      bool deterministic, ::google::protobuf::uint8* target) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(CSTBS* other);
  private:
  inline ::google::protobuf::Arena* GetArenaNoVirtual() const {
    return NULL;
  }
  inline void* MaybeArenaPtr() const {
    return NULL;
  }
  public:

  ::google::protobuf::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // string curveID = 3;
  void clear_curveid();
  static const int kCurveIDFieldNumber = 3;
  const ::std::string& curveid() const;
  void set_curveid(const ::std::string& value);
  #if LANG_CXX11
  void set_curveid(::std::string&& value);
  #endif
  void set_curveid(const char* value);
  void set_curveid(const char* value, size_t size);
  ::std::string* mutable_curveid();
  ::std::string* release_curveid();
  void set_allocated_curveid(::std::string* curveid);

  // string hashID = 4;
  void clear_hashid();
  static const int kHashIDFieldNumber = 4;
  const ::std::string& hashid() const;
  void set_hashid(const ::std::string& value);
  #if LANG_CXX11
  void set_hashid(::std::string&& value);
  #endif
  void set_hashid(const char* value);
  void set_hashid(const char* value, size_t size);
  ::std::string* mutable_hashid();
  ::std::string* release_hashid();
  void set_allocated_hashid(::std::string* hashid);

  // int64 deviceID = 1;
  void clear_deviceid();
  static const int kDeviceIDFieldNumber = 1;
  ::google::protobuf::int64 deviceid() const;
  void set_deviceid(::google::protobuf::int64 value);

  // int64 orgID = 2;
  void clear_orgid();
  static const int kOrgIDFieldNumber = 2;
  ::google::protobuf::int64 orgid() const;
  void set_orgid(::google::protobuf::int64 value);

  // int64 pubKLen = 5;
  void clear_pubklen();
  static const int kPubKLenFieldNumber = 5;
  ::google::protobuf::int64 pubklen() const;
  void set_pubklen(::google::protobuf::int64 value);

  // @@protoc_insertion_point(class_scope:CSR.CSTBS)
 private:

  ::google::protobuf::internal::InternalMetadataWithArena _internal_metadata_;
  ::google::protobuf::internal::ArenaStringPtr curveid_;
  ::google::protobuf::internal::ArenaStringPtr hashid_;
  ::google::protobuf::int64 deviceid_;
  ::google::protobuf::int64 orgid_;
  ::google::protobuf::int64 pubklen_;
  mutable ::google::protobuf::internal::CachedSize _cached_size_;
  friend struct ::protobuf_csr_2eproto::TableStruct;
};
// -------------------------------------------------------------------

class MCSR : public ::google::protobuf::Message /* @@protoc_insertion_point(class_definition:CSR.MCSR) */ {
 public:
  MCSR();
  virtual ~MCSR();

  MCSR(const MCSR& from);

  inline MCSR& operator=(const MCSR& from) {
    CopyFrom(from);
    return *this;
  }
  #if LANG_CXX11
  MCSR(MCSR&& from) noexcept
    : MCSR() {
    *this = ::std::move(from);
  }

  inline MCSR& operator=(MCSR&& from) noexcept {
    if (GetArenaNoVirtual() == from.GetArenaNoVirtual()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }
  #endif
  static const ::google::protobuf::Descriptor* descriptor();
  static const MCSR& default_instance();

  static void InitAsDefaultInstance();  // FOR INTERNAL USE ONLY
  static inline const MCSR* internal_default_instance() {
    return reinterpret_cast<const MCSR*>(
               &_MCSR_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    1;

  void Swap(MCSR* other);
  friend void swap(MCSR& a, MCSR& b) {
    a.Swap(&b);
  }

  // implements Message ----------------------------------------------

  inline MCSR* New() const final {
    return CreateMaybeMessage<MCSR>(NULL);
  }

  MCSR* New(::google::protobuf::Arena* arena) const final {
    return CreateMaybeMessage<MCSR>(arena);
  }
  void CopyFrom(const ::google::protobuf::Message& from) final;
  void MergeFrom(const ::google::protobuf::Message& from) final;
  void CopyFrom(const MCSR& from);
  void MergeFrom(const MCSR& from);
  void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input) final;
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const final;
  ::google::protobuf::uint8* InternalSerializeWithCachedSizesToArray(
      bool deterministic, ::google::protobuf::uint8* target) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(MCSR* other);
  private:
  inline ::google::protobuf::Arena* GetArenaNoVirtual() const {
    return NULL;
  }
  inline void* MaybeArenaPtr() const {
    return NULL;
  }
  public:

  ::google::protobuf::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // string curveID = 3;
  void clear_curveid();
  static const int kCurveIDFieldNumber = 3;
  const ::std::string& curveid() const;
  void set_curveid(const ::std::string& value);
  #if LANG_CXX11
  void set_curveid(::std::string&& value);
  #endif
  void set_curveid(const char* value);
  void set_curveid(const char* value, size_t size);
  ::std::string* mutable_curveid();
  ::std::string* release_curveid();
  void set_allocated_curveid(::std::string* curveid);

  // string hashID = 4;
  void clear_hashid();
  static const int kHashIDFieldNumber = 4;
  const ::std::string& hashid() const;
  void set_hashid(const ::std::string& value);
  #if LANG_CXX11
  void set_hashid(::std::string&& value);
  #endif
  void set_hashid(const char* value);
  void set_hashid(const char* value, size_t size);
  ::std::string* mutable_hashid();
  ::std::string* release_hashid();
  void set_allocated_hashid(::std::string* hashid);

  // bytes sig = 7;
  void clear_sig();
  static const int kSigFieldNumber = 7;
  const ::std::string& sig() const;
  void set_sig(const ::std::string& value);
  #if LANG_CXX11
  void set_sig(::std::string&& value);
  #endif
  void set_sig(const char* value);
  void set_sig(const void* value, size_t size);
  ::std::string* mutable_sig();
  ::std::string* release_sig();
  void set_allocated_sig(::std::string* sig);

  // int64 deviceID = 1;
  void clear_deviceid();
  static const int kDeviceIDFieldNumber = 1;
  ::google::protobuf::int64 deviceid() const;
  void set_deviceid(::google::protobuf::int64 value);

  // int64 orgID = 2;
  void clear_orgid();
  static const int kOrgIDFieldNumber = 2;
  ::google::protobuf::int64 orgid() const;
  void set_orgid(::google::protobuf::int64 value);

  // int64 pubKLen = 5;
  void clear_pubklen();
  static const int kPubKLenFieldNumber = 5;
  ::google::protobuf::int64 pubklen() const;
  void set_pubklen(::google::protobuf::int64 value);

  // int64 sigL = 6;
  void clear_sigl();
  static const int kSigLFieldNumber = 6;
  ::google::protobuf::int64 sigl() const;
  void set_sigl(::google::protobuf::int64 value);

  // @@protoc_insertion_point(class_scope:CSR.MCSR)
 private:

  ::google::protobuf::internal::InternalMetadataWithArena _internal_metadata_;
  ::google::protobuf::internal::ArenaStringPtr curveid_;
  ::google::protobuf::internal::ArenaStringPtr hashid_;
  ::google::protobuf::internal::ArenaStringPtr sig_;
  ::google::protobuf::int64 deviceid_;
  ::google::protobuf::int64 orgid_;
  ::google::protobuf::int64 pubklen_;
  ::google::protobuf::int64 sigl_;
  mutable ::google::protobuf::internal::CachedSize _cached_size_;
  friend struct ::protobuf_csr_2eproto::TableStruct;
};
// -------------------------------------------------------------------

class CA : public ::google::protobuf::Message /* @@protoc_insertion_point(class_definition:CSR.CA) */ {
 public:
  CA();
  virtual ~CA();

  CA(const CA& from);

  inline CA& operator=(const CA& from) {
    CopyFrom(from);
    return *this;
  }
  #if LANG_CXX11
  CA(CA&& from) noexcept
    : CA() {
    *this = ::std::move(from);
  }

  inline CA& operator=(CA&& from) noexcept {
    if (GetArenaNoVirtual() == from.GetArenaNoVirtual()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }
  #endif
  static const ::google::protobuf::Descriptor* descriptor();
  static const CA& default_instance();

  static void InitAsDefaultInstance();  // FOR INTERNAL USE ONLY
  static inline const CA* internal_default_instance() {
    return reinterpret_cast<const CA*>(
               &_CA_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    2;

  void Swap(CA* other);
  friend void swap(CA& a, CA& b) {
    a.Swap(&b);
  }

  // implements Message ----------------------------------------------

  inline CA* New() const final {
    return CreateMaybeMessage<CA>(NULL);
  }

  CA* New(::google::protobuf::Arena* arena) const final {
    return CreateMaybeMessage<CA>(arena);
  }
  void CopyFrom(const ::google::protobuf::Message& from) final;
  void MergeFrom(const ::google::protobuf::Message& from) final;
  void CopyFrom(const CA& from);
  void MergeFrom(const CA& from);
  void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input) final;
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const final;
  ::google::protobuf::uint8* InternalSerializeWithCachedSizesToArray(
      bool deterministic, ::google::protobuf::uint8* target) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(CA* other);
  private:
  inline ::google::protobuf::Arena* GetArenaNoVirtual() const {
    return NULL;
  }
  inline void* MaybeArenaPtr() const {
    return NULL;
  }
  public:

  ::google::protobuf::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // string curveID = 3;
  void clear_curveid();
  static const int kCurveIDFieldNumber = 3;
  const ::std::string& curveid() const;
  void set_curveid(const ::std::string& value);
  #if LANG_CXX11
  void set_curveid(::std::string&& value);
  #endif
  void set_curveid(const char* value);
  void set_curveid(const char* value, size_t size);
  ::std::string* mutable_curveid();
  ::std::string* release_curveid();
  void set_allocated_curveid(::std::string* curveid);

  // string hashID = 4;
  void clear_hashid();
  static const int kHashIDFieldNumber = 4;
  const ::std::string& hashid() const;
  void set_hashid(const ::std::string& value);
  #if LANG_CXX11
  void set_hashid(::std::string&& value);
  #endif
  void set_hashid(const char* value);
  void set_hashid(const char* value, size_t size);
  ::std::string* mutable_hashid();
  ::std::string* release_hashid();
  void set_allocated_hashid(::std::string* hashid);

  // int64 deviceID = 1;
  void clear_deviceid();
  static const int kDeviceIDFieldNumber = 1;
  ::google::protobuf::int64 deviceid() const;
  void set_deviceid(::google::protobuf::int64 value);

  // int64 orgID = 2;
  void clear_orgid();
  static const int kOrgIDFieldNumber = 2;
  ::google::protobuf::int64 orgid() const;
  void set_orgid(::google::protobuf::int64 value);

  // int64 pubKLen = 5;
  void clear_pubklen();
  static const int kPubKLenFieldNumber = 5;
  ::google::protobuf::int64 pubklen() const;
  void set_pubklen(::google::protobuf::int64 value);

  // int64 certSNO = 6;
  void clear_certsno();
  static const int kCertSNOFieldNumber = 6;
  ::google::protobuf::int64 certsno() const;
  void set_certsno(::google::protobuf::int64 value);

  // int64 caID = 7;
  void clear_caid();
  static const int kCaIDFieldNumber = 7;
  ::google::protobuf::int64 caid() const;
  void set_caid(::google::protobuf::int64 value);

  // int64 validF = 8;
  void clear_validf();
  static const int kValidFFieldNumber = 8;
  ::google::protobuf::int64 validf() const;
  void set_validf(::google::protobuf::int64 value);

  // int64 validFor = 9;
  void clear_validfor();
  static const int kValidForFieldNumber = 9;
  ::google::protobuf::int64 validfor() const;
  void set_validfor(::google::protobuf::int64 value);

  // @@protoc_insertion_point(class_scope:CSR.CA)
 private:

  ::google::protobuf::internal::InternalMetadataWithArena _internal_metadata_;
  ::google::protobuf::internal::ArenaStringPtr curveid_;
  ::google::protobuf::internal::ArenaStringPtr hashid_;
  ::google::protobuf::int64 deviceid_;
  ::google::protobuf::int64 orgid_;
  ::google::protobuf::int64 pubklen_;
  ::google::protobuf::int64 certsno_;
  ::google::protobuf::int64 caid_;
  ::google::protobuf::int64 validf_;
  ::google::protobuf::int64 validfor_;
  mutable ::google::protobuf::internal::CachedSize _cached_size_;
  friend struct ::protobuf_csr_2eproto::TableStruct;
};
// ===================================================================


// ===================================================================

#ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// CSTBS

// int64 deviceID = 1;
inline void CSTBS::clear_deviceid() {
  deviceid_ = GOOGLE_LONGLONG(0);
}
inline ::google::protobuf::int64 CSTBS::deviceid() const {
  // @@protoc_insertion_point(field_get:CSR.CSTBS.deviceID)
  return deviceid_;
}
inline void CSTBS::set_deviceid(::google::protobuf::int64 value) {
  
  deviceid_ = value;
  // @@protoc_insertion_point(field_set:CSR.CSTBS.deviceID)
}

// int64 orgID = 2;
inline void CSTBS::clear_orgid() {
  orgid_ = GOOGLE_LONGLONG(0);
}
inline ::google::protobuf::int64 CSTBS::orgid() const {
  // @@protoc_insertion_point(field_get:CSR.CSTBS.orgID)
  return orgid_;
}
inline void CSTBS::set_orgid(::google::protobuf::int64 value) {
  
  orgid_ = value;
  // @@protoc_insertion_point(field_set:CSR.CSTBS.orgID)
}

// string curveID = 3;
inline void CSTBS::clear_curveid() {
  curveid_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline const ::std::string& CSTBS::curveid() const {
  // @@protoc_insertion_point(field_get:CSR.CSTBS.curveID)
  return curveid_.GetNoArena();
}
inline void CSTBS::set_curveid(const ::std::string& value) {
  
  curveid_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
  // @@protoc_insertion_point(field_set:CSR.CSTBS.curveID)
}
#if LANG_CXX11
inline void CSTBS::set_curveid(::std::string&& value) {
  
  curveid_.SetNoArena(
    &::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:CSR.CSTBS.curveID)
}
#endif
inline void CSTBS::set_curveid(const char* value) {
  GOOGLE_DCHECK(value != NULL);
  
  curveid_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:CSR.CSTBS.curveID)
}
inline void CSTBS::set_curveid(const char* value, size_t size) {
  
  curveid_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:CSR.CSTBS.curveID)
}
inline ::std::string* CSTBS::mutable_curveid() {
  
  // @@protoc_insertion_point(field_mutable:CSR.CSTBS.curveID)
  return curveid_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline ::std::string* CSTBS::release_curveid() {
  // @@protoc_insertion_point(field_release:CSR.CSTBS.curveID)
  
  return curveid_.ReleaseNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void CSTBS::set_allocated_curveid(::std::string* curveid) {
  if (curveid != NULL) {
    
  } else {
    
  }
  curveid_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), curveid);
  // @@protoc_insertion_point(field_set_allocated:CSR.CSTBS.curveID)
}

// string hashID = 4;
inline void CSTBS::clear_hashid() {
  hashid_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline const ::std::string& CSTBS::hashid() const {
  // @@protoc_insertion_point(field_get:CSR.CSTBS.hashID)
  return hashid_.GetNoArena();
}
inline void CSTBS::set_hashid(const ::std::string& value) {
  
  hashid_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
  // @@protoc_insertion_point(field_set:CSR.CSTBS.hashID)
}
#if LANG_CXX11
inline void CSTBS::set_hashid(::std::string&& value) {
  
  hashid_.SetNoArena(
    &::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:CSR.CSTBS.hashID)
}
#endif
inline void CSTBS::set_hashid(const char* value) {
  GOOGLE_DCHECK(value != NULL);
  
  hashid_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:CSR.CSTBS.hashID)
}
inline void CSTBS::set_hashid(const char* value, size_t size) {
  
  hashid_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:CSR.CSTBS.hashID)
}
inline ::std::string* CSTBS::mutable_hashid() {
  
  // @@protoc_insertion_point(field_mutable:CSR.CSTBS.hashID)
  return hashid_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline ::std::string* CSTBS::release_hashid() {
  // @@protoc_insertion_point(field_release:CSR.CSTBS.hashID)
  
  return hashid_.ReleaseNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void CSTBS::set_allocated_hashid(::std::string* hashid) {
  if (hashid != NULL) {
    
  } else {
    
  }
  hashid_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), hashid);
  // @@protoc_insertion_point(field_set_allocated:CSR.CSTBS.hashID)
}

// int64 pubKLen = 5;
inline void CSTBS::clear_pubklen() {
  pubklen_ = GOOGLE_LONGLONG(0);
}
inline ::google::protobuf::int64 CSTBS::pubklen() const {
  // @@protoc_insertion_point(field_get:CSR.CSTBS.pubKLen)
  return pubklen_;
}
inline void CSTBS::set_pubklen(::google::protobuf::int64 value) {
  
  pubklen_ = value;
  // @@protoc_insertion_point(field_set:CSR.CSTBS.pubKLen)
}

// -------------------------------------------------------------------

// MCSR

// int64 deviceID = 1;
inline void MCSR::clear_deviceid() {
  deviceid_ = GOOGLE_LONGLONG(0);
}
inline ::google::protobuf::int64 MCSR::deviceid() const {
  // @@protoc_insertion_point(field_get:CSR.MCSR.deviceID)
  return deviceid_;
}
inline void MCSR::set_deviceid(::google::protobuf::int64 value) {
  
  deviceid_ = value;
  // @@protoc_insertion_point(field_set:CSR.MCSR.deviceID)
}

// int64 orgID = 2;
inline void MCSR::clear_orgid() {
  orgid_ = GOOGLE_LONGLONG(0);
}
inline ::google::protobuf::int64 MCSR::orgid() const {
  // @@protoc_insertion_point(field_get:CSR.MCSR.orgID)
  return orgid_;
}
inline void MCSR::set_orgid(::google::protobuf::int64 value) {
  
  orgid_ = value;
  // @@protoc_insertion_point(field_set:CSR.MCSR.orgID)
}

// string curveID = 3;
inline void MCSR::clear_curveid() {
  curveid_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline const ::std::string& MCSR::curveid() const {
  // @@protoc_insertion_point(field_get:CSR.MCSR.curveID)
  return curveid_.GetNoArena();
}
inline void MCSR::set_curveid(const ::std::string& value) {
  
  curveid_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
  // @@protoc_insertion_point(field_set:CSR.MCSR.curveID)
}
#if LANG_CXX11
inline void MCSR::set_curveid(::std::string&& value) {
  
  curveid_.SetNoArena(
    &::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:CSR.MCSR.curveID)
}
#endif
inline void MCSR::set_curveid(const char* value) {
  GOOGLE_DCHECK(value != NULL);
  
  curveid_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:CSR.MCSR.curveID)
}
inline void MCSR::set_curveid(const char* value, size_t size) {
  
  curveid_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:CSR.MCSR.curveID)
}
inline ::std::string* MCSR::mutable_curveid() {
  
  // @@protoc_insertion_point(field_mutable:CSR.MCSR.curveID)
  return curveid_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline ::std::string* MCSR::release_curveid() {
  // @@protoc_insertion_point(field_release:CSR.MCSR.curveID)
  
  return curveid_.ReleaseNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void MCSR::set_allocated_curveid(::std::string* curveid) {
  if (curveid != NULL) {
    
  } else {
    
  }
  curveid_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), curveid);
  // @@protoc_insertion_point(field_set_allocated:CSR.MCSR.curveID)
}

// string hashID = 4;
inline void MCSR::clear_hashid() {
  hashid_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline const ::std::string& MCSR::hashid() const {
  // @@protoc_insertion_point(field_get:CSR.MCSR.hashID)
  return hashid_.GetNoArena();
}
inline void MCSR::set_hashid(const ::std::string& value) {
  
  hashid_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
  // @@protoc_insertion_point(field_set:CSR.MCSR.hashID)
}
#if LANG_CXX11
inline void MCSR::set_hashid(::std::string&& value) {
  
  hashid_.SetNoArena(
    &::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:CSR.MCSR.hashID)
}
#endif
inline void MCSR::set_hashid(const char* value) {
  GOOGLE_DCHECK(value != NULL);
  
  hashid_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:CSR.MCSR.hashID)
}
inline void MCSR::set_hashid(const char* value, size_t size) {
  
  hashid_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:CSR.MCSR.hashID)
}
inline ::std::string* MCSR::mutable_hashid() {
  
  // @@protoc_insertion_point(field_mutable:CSR.MCSR.hashID)
  return hashid_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline ::std::string* MCSR::release_hashid() {
  // @@protoc_insertion_point(field_release:CSR.MCSR.hashID)
  
  return hashid_.ReleaseNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void MCSR::set_allocated_hashid(::std::string* hashid) {
  if (hashid != NULL) {
    
  } else {
    
  }
  hashid_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), hashid);
  // @@protoc_insertion_point(field_set_allocated:CSR.MCSR.hashID)
}

// int64 pubKLen = 5;
inline void MCSR::clear_pubklen() {
  pubklen_ = GOOGLE_LONGLONG(0);
}
inline ::google::protobuf::int64 MCSR::pubklen() const {
  // @@protoc_insertion_point(field_get:CSR.MCSR.pubKLen)
  return pubklen_;
}
inline void MCSR::set_pubklen(::google::protobuf::int64 value) {
  
  pubklen_ = value;
  // @@protoc_insertion_point(field_set:CSR.MCSR.pubKLen)
}

// int64 sigL = 6;
inline void MCSR::clear_sigl() {
  sigl_ = GOOGLE_LONGLONG(0);
}
inline ::google::protobuf::int64 MCSR::sigl() const {
  // @@protoc_insertion_point(field_get:CSR.MCSR.sigL)
  return sigl_;
}
inline void MCSR::set_sigl(::google::protobuf::int64 value) {
  
  sigl_ = value;
  // @@protoc_insertion_point(field_set:CSR.MCSR.sigL)
}

// bytes sig = 7;
inline void MCSR::clear_sig() {
  sig_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline const ::std::string& MCSR::sig() const {
  // @@protoc_insertion_point(field_get:CSR.MCSR.sig)
  return sig_.GetNoArena();
}
inline void MCSR::set_sig(const ::std::string& value) {
  
  sig_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
  // @@protoc_insertion_point(field_set:CSR.MCSR.sig)
}
#if LANG_CXX11
inline void MCSR::set_sig(::std::string&& value) {
  
  sig_.SetNoArena(
    &::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:CSR.MCSR.sig)
}
#endif
inline void MCSR::set_sig(const char* value) {
  GOOGLE_DCHECK(value != NULL);
  
  sig_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:CSR.MCSR.sig)
}
inline void MCSR::set_sig(const void* value, size_t size) {
  
  sig_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:CSR.MCSR.sig)
}
inline ::std::string* MCSR::mutable_sig() {
  
  // @@protoc_insertion_point(field_mutable:CSR.MCSR.sig)
  return sig_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline ::std::string* MCSR::release_sig() {
  // @@protoc_insertion_point(field_release:CSR.MCSR.sig)
  
  return sig_.ReleaseNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void MCSR::set_allocated_sig(::std::string* sig) {
  if (sig != NULL) {
    
  } else {
    
  }
  sig_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), sig);
  // @@protoc_insertion_point(field_set_allocated:CSR.MCSR.sig)
}

// -------------------------------------------------------------------

// CA

// int64 deviceID = 1;
inline void CA::clear_deviceid() {
  deviceid_ = GOOGLE_LONGLONG(0);
}
inline ::google::protobuf::int64 CA::deviceid() const {
  // @@protoc_insertion_point(field_get:CSR.CA.deviceID)
  return deviceid_;
}
inline void CA::set_deviceid(::google::protobuf::int64 value) {
  
  deviceid_ = value;
  // @@protoc_insertion_point(field_set:CSR.CA.deviceID)
}

// int64 orgID = 2;
inline void CA::clear_orgid() {
  orgid_ = GOOGLE_LONGLONG(0);
}
inline ::google::protobuf::int64 CA::orgid() const {
  // @@protoc_insertion_point(field_get:CSR.CA.orgID)
  return orgid_;
}
inline void CA::set_orgid(::google::protobuf::int64 value) {
  
  orgid_ = value;
  // @@protoc_insertion_point(field_set:CSR.CA.orgID)
}

// string curveID = 3;
inline void CA::clear_curveid() {
  curveid_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline const ::std::string& CA::curveid() const {
  // @@protoc_insertion_point(field_get:CSR.CA.curveID)
  return curveid_.GetNoArena();
}
inline void CA::set_curveid(const ::std::string& value) {
  
  curveid_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
  // @@protoc_insertion_point(field_set:CSR.CA.curveID)
}
#if LANG_CXX11
inline void CA::set_curveid(::std::string&& value) {
  
  curveid_.SetNoArena(
    &::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:CSR.CA.curveID)
}
#endif
inline void CA::set_curveid(const char* value) {
  GOOGLE_DCHECK(value != NULL);
  
  curveid_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:CSR.CA.curveID)
}
inline void CA::set_curveid(const char* value, size_t size) {
  
  curveid_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:CSR.CA.curveID)
}
inline ::std::string* CA::mutable_curveid() {
  
  // @@protoc_insertion_point(field_mutable:CSR.CA.curveID)
  return curveid_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline ::std::string* CA::release_curveid() {
  // @@protoc_insertion_point(field_release:CSR.CA.curveID)
  
  return curveid_.ReleaseNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void CA::set_allocated_curveid(::std::string* curveid) {
  if (curveid != NULL) {
    
  } else {
    
  }
  curveid_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), curveid);
  // @@protoc_insertion_point(field_set_allocated:CSR.CA.curveID)
}

// string hashID = 4;
inline void CA::clear_hashid() {
  hashid_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline const ::std::string& CA::hashid() const {
  // @@protoc_insertion_point(field_get:CSR.CA.hashID)
  return hashid_.GetNoArena();
}
inline void CA::set_hashid(const ::std::string& value) {
  
  hashid_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
  // @@protoc_insertion_point(field_set:CSR.CA.hashID)
}
#if LANG_CXX11
inline void CA::set_hashid(::std::string&& value) {
  
  hashid_.SetNoArena(
    &::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:CSR.CA.hashID)
}
#endif
inline void CA::set_hashid(const char* value) {
  GOOGLE_DCHECK(value != NULL);
  
  hashid_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:CSR.CA.hashID)
}
inline void CA::set_hashid(const char* value, size_t size) {
  
  hashid_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:CSR.CA.hashID)
}
inline ::std::string* CA::mutable_hashid() {
  
  // @@protoc_insertion_point(field_mutable:CSR.CA.hashID)
  return hashid_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline ::std::string* CA::release_hashid() {
  // @@protoc_insertion_point(field_release:CSR.CA.hashID)
  
  return hashid_.ReleaseNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void CA::set_allocated_hashid(::std::string* hashid) {
  if (hashid != NULL) {
    
  } else {
    
  }
  hashid_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), hashid);
  // @@protoc_insertion_point(field_set_allocated:CSR.CA.hashID)
}

// int64 pubKLen = 5;
inline void CA::clear_pubklen() {
  pubklen_ = GOOGLE_LONGLONG(0);
}
inline ::google::protobuf::int64 CA::pubklen() const {
  // @@protoc_insertion_point(field_get:CSR.CA.pubKLen)
  return pubklen_;
}
inline void CA::set_pubklen(::google::protobuf::int64 value) {
  
  pubklen_ = value;
  // @@protoc_insertion_point(field_set:CSR.CA.pubKLen)
}

// int64 certSNO = 6;
inline void CA::clear_certsno() {
  certsno_ = GOOGLE_LONGLONG(0);
}
inline ::google::protobuf::int64 CA::certsno() const {
  // @@protoc_insertion_point(field_get:CSR.CA.certSNO)
  return certsno_;
}
inline void CA::set_certsno(::google::protobuf::int64 value) {
  
  certsno_ = value;
  // @@protoc_insertion_point(field_set:CSR.CA.certSNO)
}

// int64 caID = 7;
inline void CA::clear_caid() {
  caid_ = GOOGLE_LONGLONG(0);
}
inline ::google::protobuf::int64 CA::caid() const {
  // @@protoc_insertion_point(field_get:CSR.CA.caID)
  return caid_;
}
inline void CA::set_caid(::google::protobuf::int64 value) {
  
  caid_ = value;
  // @@protoc_insertion_point(field_set:CSR.CA.caID)
}

// int64 validF = 8;
inline void CA::clear_validf() {
  validf_ = GOOGLE_LONGLONG(0);
}
inline ::google::protobuf::int64 CA::validf() const {
  // @@protoc_insertion_point(field_get:CSR.CA.validF)
  return validf_;
}
inline void CA::set_validf(::google::protobuf::int64 value) {
  
  validf_ = value;
  // @@protoc_insertion_point(field_set:CSR.CA.validF)
}

// int64 validFor = 9;
inline void CA::clear_validfor() {
  validfor_ = GOOGLE_LONGLONG(0);
}
inline ::google::protobuf::int64 CA::validfor() const {
  // @@protoc_insertion_point(field_get:CSR.CA.validFor)
  return validfor_;
}
inline void CA::set_validfor(::google::protobuf::int64 value) {
  
  validfor_ = value;
  // @@protoc_insertion_point(field_set:CSR.CA.validFor)
}

#ifdef __GNUC__
  #pragma GCC diagnostic pop
#endif  // __GNUC__
// -------------------------------------------------------------------

// -------------------------------------------------------------------


// @@protoc_insertion_point(namespace_scope)

}  // namespace CSR

// @@protoc_insertion_point(global_scope)

#endif  // PROTOBUF_INCLUDED_csr_2eproto
