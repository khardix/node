// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "tls_wrap.h"
#include "async_wrap-inl.h"
#include "debug_utils.h"
#include "memory_tracker-inl.h"
#include "node_buffer.h"  // Buffer
#include "node_crypto.h"  // SecureContext
#include "node_crypto_bio.h"  // NodeBIO
// ClientHelloParser
#include "node_crypto_clienthello-inl.h"
#include "stream_base-inl.h"
#include "util-inl.h"

namespace node {

using crypto::SecureContext;
using crypto::SSLWrap;
using v8::Context;
using v8::DontDelete;
using v8::EscapableHandleScope;
using v8::Exception;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::ReadOnly;
using v8::Signature;
using v8::String;
using v8::Value;

TLSWrap::TLSWrap(Environment* env,
                 Local<Object> obj,
                 Kind kind,
                 StreamBase* stream,
                 SecureContext* sc)
    : AsyncWrap(env, obj, AsyncWrap::PROVIDER_TLSWRAP),
      SSLWrap<TLSWrap>(env, sc, kind),
      StreamBase(env),
      sc_(sc) {
  MakeWeak();
  StreamBase::AttachToObject(GetObject());

  // sc comes from an Unwrap. Make sure it was assigned.
  CHECK_NOT_NULL(sc);

  // We've our own session callbacks
  SSL_CTX_sess_set_get_cb(sc_->ctx_.get(),
                          SSLWrap<TLSWrap>::GetSessionCallback);
  SSL_CTX_sess_set_new_cb(sc_->ctx_.get(),
                          SSLWrap<TLSWrap>::NewSessionCallback);

  stream->PushStreamListener(this);

  InitSSL();
  Debug(this, "Created new TLSWrap");
}


TLSWrap::~TLSWrap() {
  Debug(this, "~TLSWrap()");
  sc_ = nullptr;
}


bool TLSWrap::InvokeQueued(int status, const char* error_str) {
  Debug(this, "InvokeQueued(%d, %s)", status, error_str);
  if (!write_callback_scheduled_)
    return false;

  if (current_write_ != nullptr) {
    WriteWrap* w = current_write_;
    current_write_ = nullptr;
    w->Done(status, error_str);
  }

  return true;
}


void TLSWrap::NewSessionDoneCb() {
  Debug(this, "NewSessionDoneCb()");
  Cycle();
}


void TLSWrap::InitSSL() {
  // Initialize SSL – OpenSSL takes ownership of these.
  enc_in_ = crypto::NodeBIO::New(env()).release();
  enc_out_ = crypto::NodeBIO::New(env()).release();

  SSL_set_bio(ssl_.get(), enc_in_, enc_out_);

  // NOTE: This could be overridden in SetVerifyMode
  SSL_set_verify(ssl_.get(), SSL_VERIFY_NONE, crypto::VerifyCallback);

#ifdef SSL_MODE_RELEASE_BUFFERS
  SSL_set_mode(ssl_.get(), SSL_MODE_RELEASE_BUFFERS);
#endif  // SSL_MODE_RELEASE_BUFFERS

  // This is default in 1.1.1, but set it anyway, Cycle() doesn't currently
  // re-call ClearIn() if SSL_read() returns SSL_ERROR_WANT_READ, so data can be
  // left sitting in the incoming enc_in_ and never get processed.
  // - https://wiki.openssl.org/index.php/TLS1.3#Non-application_data_records
  SSL_set_mode(ssl_.get(), SSL_MODE_AUTO_RETRY);

  SSL_set_app_data(ssl_.get(), this);
  // Using InfoCallback isn't how we are supposed to check handshake progress:
  //   https://github.com/openssl/openssl/issues/7199#issuecomment-420915993
  //
  // Note on when this gets called on various openssl versions:
  //   https://github.com/openssl/openssl/issues/7199#issuecomment-420670544
  SSL_set_info_callback(ssl_.get(), SSLInfoCallback);

  if (is_server()) {
    SSL_CTX_set_tlsext_servername_callback(sc_->ctx_.get(),
                                           SelectSNIContextCallback);
  }

  ConfigureSecureContext(sc_);

  SSL_set_cert_cb(ssl_.get(), SSLWrap<TLSWrap>::SSLCertCallback, this);

  if (is_server()) {
    SSL_set_accept_state(ssl_.get());
  } else if (is_client()) {
    // Enough space for server response (hello, cert)
    crypto::NodeBIO::FromBIO(enc_in_)->set_initial(kInitialClientBufferLength);
    SSL_set_connect_state(ssl_.get());
  } else {
    // Unexpected
    ABORT();
  }
}


void TLSWrap::Wrap(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  CHECK_EQ(args.Length(), 3);
  CHECK(args[0]->IsObject());
  CHECK(args[1]->IsObject());
  CHECK(args[2]->IsBoolean());

  Local<Object> sc = args[1].As<Object>();
  Kind kind = args[2]->IsTrue() ? SSLWrap<TLSWrap>::kServer :
                                  SSLWrap<TLSWrap>::kClient;

  StreamBase* stream = StreamBase::FromObject(args[0].As<Object>());
  CHECK_NOT_NULL(stream);

  Local<Object> obj;
  if (!env->tls_wrap_constructor_function()
           ->NewInstance(env->context())
           .ToLocal(&obj)) {
    return;
  }

  TLSWrap* res = new TLSWrap(env, obj, kind, stream, Unwrap<SecureContext>(sc));

  args.GetReturnValue().Set(res->object());
}


void TLSWrap::Receive(const FunctionCallbackInfo<Value>& args) {
  TLSWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  ArrayBufferViewContents<char> buffer(args[0]);
  const char* data = buffer.data();
  size_t len = buffer.length();
  Debug(wrap, "Receiving %zu bytes injected from JS", len);

  // Copy given buffer entirely or partiall if handle becomes closed
  while (len > 0 && wrap->IsAlive() && !wrap->IsClosing()) {
    uv_buf_t buf = wrap->OnStreamAlloc(len);
    size_t copy = buf.len > len ? len : buf.len;
    memcpy(buf.base, data, copy);
    buf.len = copy;
    wrap->OnStreamRead(copy, buf);

    data += copy;
    len -= copy;
  }
}


void TLSWrap::Start(const FunctionCallbackInfo<Value>& args) {
  TLSWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  CHECK(!wrap->started_);

  wrap->started_ = true;

  // Send ClientHello handshake
  CHECK(wrap->is_client());
  // Seems odd to read when when we want to send, but SSL_read() triggers a
  // handshake if a session isn't established, and handshake will cause
  // encrypted data to become available for output.
  wrap->ClearOut();
  wrap->EncOut();
}


void TLSWrap::SSLInfoCallback(const SSL* ssl_, int where, int ret) {
  if (!(where & (SSL_CB_HANDSHAKE_START | SSL_CB_HANDSHAKE_DONE)))
    return;

  // SSL_renegotiate_pending() should take `const SSL*`, but it does not.
  SSL* ssl = const_cast<SSL*>(ssl_);
  TLSWrap* c = static_cast<TLSWrap*>(SSL_get_app_data(ssl_));
  Environment* env = c->env();
  HandleScope handle_scope(env->isolate());
  Context::Scope context_scope(env->context());
  Local<Object> object = c->object();

  if (where & SSL_CB_HANDSHAKE_START) {
    Debug(c, "SSLInfoCallback(SSL_CB_HANDSHAKE_START);");
    // Start is tracked to limit number and frequency of renegotiation attempts,
    // since excessive renegotiation may be an attack.
    Local<Value> callback;

    if (object->Get(env->context(), env->onhandshakestart_string())
          .ToLocal(&callback) && callback->IsFunction()) {
      Local<Value> argv[] = { env->GetNow() };
      c->MakeCallback(callback.As<Function>(), arraysize(argv), argv);
    }
  }

  // SSL_CB_HANDSHAKE_START and SSL_CB_HANDSHAKE_DONE are called
  // sending HelloRequest in OpenSSL-1.1.1.
  // We need to check whether this is in a renegotiation state or not.
  if (where & SSL_CB_HANDSHAKE_DONE && !SSL_renegotiate_pending(ssl)) {
    Debug(c, "SSLInfoCallback(SSL_CB_HANDSHAKE_DONE);");
    CHECK(!SSL_renegotiate_pending(ssl));
    Local<Value> callback;

    c->established_ = true;

    if (object->Get(env->context(), env->onhandshakedone_string())
          .ToLocal(&callback) && callback->IsFunction()) {
      c->MakeCallback(callback.As<Function>(), 0, nullptr);
    }
  }
}


void TLSWrap::EncOut() {
  Debug(this, "Trying to write encrypted output");

  // Ignore cycling data if ClientHello wasn't yet parsed
  if (!hello_parser_.IsEnded()) {
    Debug(this, "Returning from EncOut(), hello_parser_ active");
    return;
  }

  // Write in progress
  if (write_size_ != 0) {
    Debug(this, "Returning from EncOut(), write currently in progress");
    return;
  }

  // Wait for `newSession` callback to be invoked
  if (is_awaiting_new_session()) {
    Debug(this, "Returning from EncOut(), awaiting new session");
    return;
  }

  // Split-off queue
  if (established_ && current_write_ != nullptr) {
    Debug(this, "EncOut() setting write_callback_scheduled_");
    write_callback_scheduled_ = true;
  }

  if (ssl_ == nullptr) {
    Debug(this, "Returning from EncOut(), ssl_ == nullptr");
    return;
  }

  // No encrypted output ready to write to the underlying stream.
  if (BIO_pending(enc_out_) == 0) {
    Debug(this, "No pending encrypted output");
    if (pending_cleartext_input_.size() == 0) {
      if (!in_dowrite_) {
        Debug(this, "No pending cleartext input, not inside DoWrite()");
        InvokeQueued(0);
      } else {
        Debug(this, "No pending cleartext input, inside DoWrite()");
        // TODO(@sam-github, @addaleax) If in_dowrite_ is true, appdata was
        // passed to SSL_write().  If we are here, the data was not encrypted to
        // enc_out_ yet.  Calling Done() "works", but since the write is not
        // flushed, its too soon.  Just returning and letting the next EncOut()
        // call Done() passes the test suite, but without more careful analysis,
        // its not clear if it is always correct. Not calling Done() could block
        // data flow, so for now continue to call Done(), just do it in the next
        // tick.
        env()->SetImmediate([this](Environment* env) {
          InvokeQueued(0);
        }, object());
      }
    }
    return;
  }

  char* data[kSimultaneousBufferCount];
  size_t size[arraysize(data)];
  size_t count = arraysize(data);
  write_size_ = crypto::NodeBIO::FromBIO(enc_out_)->PeekMultiple(data,
                                                                 size,
                                                                 &count);
  CHECK(write_size_ != 0 && count != 0);

  uv_buf_t buf[arraysize(data)];
  uv_buf_t* bufs = buf;
  for (size_t i = 0; i < count; i++)
    buf[i] = uv_buf_init(data[i], size[i]);

  Debug(this, "Writing %zu buffers to the underlying stream", count);
  StreamWriteResult res = underlying_stream()->Write(bufs, count);
  if (res.err != 0) {
    InvokeQueued(res.err);
    return;
  }

  if (!res.async) {
    Debug(this, "Write finished synchronously");
    HandleScope handle_scope(env()->isolate());

    // Simulate asynchronous finishing, TLS cannot handle this at the moment.
    env()->SetImmediate([this](Environment* env) {
      OnStreamAfterWrite(nullptr, 0);
    }, object());
  }
}


void TLSWrap::OnStreamAfterWrite(WriteWrap* req_wrap, int status) {
  Debug(this, "OnStreamAfterWrite(status = %d)", status);
  if (current_empty_write_ != nullptr) {
    Debug(this, "Had empty write");
    WriteWrap* finishing = current_empty_write_;
    current_empty_write_ = nullptr;
    finishing->Done(status);
    return;
  }

  if (ssl_ == nullptr) {
    Debug(this, "ssl_ == nullptr, marking as cancelled");
    status = UV_ECANCELED;
  }

  // Handle error
  if (status) {
    if (shutdown_) {
      Debug(this, "Ignoring error after shutdown");
      return;
    }

    // Notify about error
    InvokeQueued(status);
    return;
  }

  // Commit
  crypto::NodeBIO::FromBIO(enc_out_)->Read(nullptr, write_size_);

  // Ensure that the progress will be made and `InvokeQueued` will be called.
  ClearIn();

  // Try writing more data
  write_size_ = 0;
  EncOut();
}


Local<Value> TLSWrap::GetSSLError(int status, int* err, std::string* msg) {
  EscapableHandleScope scope(env()->isolate());

  // ssl_ is already destroyed in reading EOF by close notify alert.
  if (ssl_ == nullptr)
    return Local<Value>();

  *err = SSL_get_error(ssl_.get(), status);
  switch (*err) {
    case SSL_ERROR_NONE:
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_X509_LOOKUP:
      return Local<Value>();

    case SSL_ERROR_ZERO_RETURN:
      return scope.Escape(env()->zero_return_string());

    case SSL_ERROR_SSL:
    case SSL_ERROR_SYSCALL:
      {
        unsigned long ssl_err = ERR_peek_error();  // NOLINT(runtime/int)
        BIO* bio = BIO_new(BIO_s_mem());
        ERR_print_errors(bio);

        BUF_MEM* mem;
        BIO_get_mem_ptr(bio, &mem);

        Isolate* isolate = env()->isolate();
        Local<Context> context = isolate->GetCurrentContext();

        Local<String> message =
            OneByteString(isolate, mem->data, mem->length);
        Local<Value> exception = Exception::Error(message);
        Local<Object> obj = exception->ToObject(context).ToLocalChecked();

        const char* ls = ERR_lib_error_string(ssl_err);
        const char* fs = ERR_func_error_string(ssl_err);
        const char* rs = ERR_reason_error_string(ssl_err);

        if (ls != nullptr)
          obj->Set(context, env()->library_string(),
                   OneByteString(isolate, ls)).Check();
        if (fs != nullptr)
          obj->Set(context, env()->function_string(),
                   OneByteString(isolate, fs)).Check();
        if (rs != nullptr) {
          obj->Set(context, env()->reason_string(),
                   OneByteString(isolate, rs)).Check();

          // SSL has no API to recover the error name from the number, so we
          // transform reason strings like "this error" to "ERR_SSL_THIS_ERROR",
          // which ends up being close to the original error macro name.
          std::string code(rs);

          for (auto& c : code) {
            if (c == ' ')
              c = '_';
            else
              c = ToUpper(c);
          }
          obj->Set(context, env()->code_string(),
                   OneByteString(isolate, ("ERR_SSL_" + code).c_str()))
                     .Check();
        }

        if (msg != nullptr)
          msg->assign(mem->data, mem->data + mem->length);

        BIO_free_all(bio);

        return scope.Escape(exception);
      }

    default:
      UNREACHABLE();
  }
  UNREACHABLE();
}


void TLSWrap::ClearOut() {
  Debug(this, "Trying to read cleartext output");
  // Ignore cycling data if ClientHello wasn't yet parsed
  if (!hello_parser_.IsEnded()) {
    Debug(this, "Returning from ClearOut(), hello_parser_ active");
    return;
  }

  // No reads after EOF
  if (eof_) {
    Debug(this, "Returning from ClearOut(), EOF reached");
    return;
  }

  if (ssl_ == nullptr) {
    Debug(this, "Returning from ClearOut(), ssl_ == nullptr");
    return;
  }

  crypto::MarkPopErrorOnReturn mark_pop_error_on_return;

  char out[kClearOutChunkSize];
  int read;
  for (;;) {
    read = SSL_read(ssl_.get(), out, sizeof(out));
    Debug(this, "Read %d bytes of cleartext output", read);

    if (read <= 0)
      break;

    char* current = out;
    while (read > 0) {
      int avail = read;

      uv_buf_t buf = EmitAlloc(avail);
      if (static_cast<int>(buf.len) < avail)
        avail = buf.len;
      memcpy(buf.base, current, avail);
      EmitRead(avail, buf);

      // Caveat emptor: OnRead() calls into JS land which can result in
      // the SSL context object being destroyed.  We have to carefully
      // check that ssl_ != nullptr afterwards.
      if (ssl_ == nullptr) {
        Debug(this, "Returning from read loop, ssl_ == nullptr");
        return;
      }

      read -= avail;
      current += avail;
    }
  }

  int flags = SSL_get_shutdown(ssl_.get());
  if (!eof_ && flags & SSL_RECEIVED_SHUTDOWN) {
    eof_ = true;
    EmitRead(UV_EOF);
  }

  // We need to check whether an error occurred or the connection was
  // shutdown cleanly (SSL_ERROR_ZERO_RETURN) even when read == 0.
  // See node#1642 and SSL_read(3SSL) for details.
  if (read <= 0) {
    HandleScope handle_scope(env()->isolate());
    int err;
    Local<Value> arg = GetSSLError(read, &err, nullptr);

    // Ignore ZERO_RETURN after EOF, it is basically not a error
    if (err == SSL_ERROR_ZERO_RETURN && eof_)
      return;

    if (!arg.IsEmpty()) {
      Debug(this, "Got SSL error (%d), calling onerror", err);
      // When TLS Alert are stored in wbio,
      // it should be flushed to socket before destroyed.
      if (BIO_pending(enc_out_) != 0)
        EncOut();

      MakeCallback(env()->onerror_string(), 1, &arg);
    }
  }
}


void TLSWrap::ClearIn() {
  Debug(this, "Trying to write cleartext input");
  // Ignore cycling data if ClientHello wasn't yet parsed
  if (!hello_parser_.IsEnded()) {
    Debug(this, "Returning from ClearIn(), hello_parser_ active");
    return;
  }

  if (ssl_ == nullptr) {
    Debug(this, "Returning from ClearIn(), ssl_ == nullptr");
    return;
  }

  if (pending_cleartext_input_.size() == 0) {
    Debug(this, "Returning from ClearIn(), no pending data");
    return;
  }

  AllocatedBuffer data = std::move(pending_cleartext_input_);
  crypto::MarkPopErrorOnReturn mark_pop_error_on_return;

  int written = SSL_write(ssl_.get(), data.data(), data.size());
  Debug(this, "Writing %zu bytes, written = %d", data.size(), written);
  CHECK(written == -1 || written == static_cast<int>(data.size()));

  // All written
  if (written != -1) {
    Debug(this, "Successfully wrote all data to SSL");
    return;
  }

  // Error or partial write
  HandleScope handle_scope(env()->isolate());
  Context::Scope context_scope(env()->context());

  int err;
  std::string error_str;
  Local<Value> arg = GetSSLError(written, &err, &error_str);
  if (!arg.IsEmpty()) {
    Debug(this, "Got SSL error (%d)", err);
    write_callback_scheduled_ = true;
    // TODO(@sam-github) Should forward an error object with
    // .code/.function/.etc, if possible.
    InvokeQueued(UV_EPROTO, error_str.c_str());
  } else {
    Debug(this, "Pushing data back");
    // Push back the not-yet-written data. This can be skipped in the error
    // case because no further writes would succeed anyway.
    pending_cleartext_input_ = std::move(data);
  }
}


std::string TLSWrap::diagnostic_name() const {
  std::string name = "TLSWrap ";
  if (is_server())
    name += "server (";
  else
    name += "client (";
  name += std::to_string(static_cast<int64_t>(get_async_id())) + ")";
  return name;
}


AsyncWrap* TLSWrap::GetAsyncWrap() {
  return static_cast<AsyncWrap*>(this);
}


bool TLSWrap::IsIPCPipe() {
  return underlying_stream()->IsIPCPipe();
}


int TLSWrap::GetFD() {
  return underlying_stream()->GetFD();
}


bool TLSWrap::IsAlive() {
  return ssl_ != nullptr &&
      stream_ != nullptr &&
      underlying_stream()->IsAlive();
}


bool TLSWrap::IsClosing() {
  return underlying_stream()->IsClosing();
}



int TLSWrap::ReadStart() {
  Debug(this, "ReadStart()");
  if (stream_ != nullptr)
    return stream_->ReadStart();
  return 0;
}


int TLSWrap::ReadStop() {
  Debug(this, "ReadStop()");
  if (stream_ != nullptr)
    return stream_->ReadStop();
  return 0;
}


const char* TLSWrap::Error() const {
  return error_.empty() ? nullptr : error_.c_str();
}


void TLSWrap::ClearError() {
  error_.clear();
}


// Called by StreamBase::Write() to request async write of clear text into SSL.
// TODO(@sam-github) Should there be a TLSWrap::DoTryWrite()?
int TLSWrap::DoWrite(WriteWrap* w,
                     uv_buf_t* bufs,
                     size_t count,
                     uv_stream_t* send_handle) {
  CHECK_NULL(send_handle);
  Debug(this, "DoWrite()");

  if (ssl_ == nullptr) {
    ClearError();
    error_ = "Write after DestroySSL";
    return UV_EPROTO;
  }

  size_t length = 0;
  size_t i;
  for (i = 0; i < count; i++)
    length += bufs[i].len;

  // We want to trigger a Write() on the underlying stream to drive the stream
  // system, but don't want to encrypt empty buffers into a TLS frame, so see
  // if we can find something to Write().
  // First, call ClearOut(). It does an SSL_read(), which might cause handshake
  // or other internal messages to be encrypted. If it does, write them later
  // with EncOut().
  // If there is still no encrypted output, call Write(bufs) on the underlying
  // stream. Since the bufs are empty, it won't actually write non-TLS data
  // onto the socket, we just want the side-effects. After, make sure the
  // WriteWrap was accepted by the stream, or that we call Done() on it.
  if (length == 0) {
    Debug(this, "Empty write");
    ClearOut();
    if (BIO_pending(enc_out_) == 0) {
      Debug(this, "No pending encrypted output, writing to underlying stream");
      CHECK_NULL(current_empty_write_);
      current_empty_write_ = w;
      StreamWriteResult res =
          underlying_stream()->Write(bufs, count, send_handle);
      if (!res.async) {
        env()->SetImmediate([this](Environment* env) {
          OnStreamAfterWrite(current_empty_write_, 0);
        }, object());
      }
      return 0;
    }
  }

  // Store the current write wrap
  CHECK_NULL(current_write_);
  current_write_ = w;

  // Write encrypted data to underlying stream and call Done().
  if (length == 0) {
    EncOut();
    return 0;
  }

  AllocatedBuffer data;
  crypto::MarkPopErrorOnReturn mark_pop_error_on_return;

  int written = 0;
  if (count != 1) {
    data = env()->AllocateManaged(length);
    size_t offset = 0;
    for (i = 0; i < count; i++) {
      memcpy(data.data() + offset, bufs[i].base, bufs[i].len);
      offset += bufs[i].len;
    }
    written = SSL_write(ssl_.get(), data.data(), length);
  } else {
    // Only one buffer: try to write directly, only store if it fails
    written = SSL_write(ssl_.get(), bufs[0].base, bufs[0].len);
    if (written == -1) {
      data = env()->AllocateManaged(length);
      memcpy(data.data(), bufs[0].base, bufs[0].len);
    }
  }

  CHECK(written == -1 || written == static_cast<int>(length));
  Debug(this, "Writing %zu bytes, written = %d", length, written);

  if (written == -1) {
    int err;
    Local<Value> arg = GetSSLError(written, &err, &error_);

    // If we stopped writing because of an error, it's fatal, discard the data.
    if (!arg.IsEmpty()) {
      Debug(this, "Got SSL error (%d), returning UV_EPROTO", err);
      current_write_ = nullptr;
      return UV_EPROTO;
    }

    Debug(this, "Saving data for later write");
    // Otherwise, save unwritten data so it can be written later by ClearIn().
    CHECK_EQ(pending_cleartext_input_.size(), 0);
    pending_cleartext_input_ = std::move(data);
  }

  // Write any encrypted/handshake output that may be ready.
  // Guard against sync call of current_write_->Done(), its unsupported.
  in_dowrite_ = true;
  EncOut();
  in_dowrite_ = false;

  return 0;
}


uv_buf_t TLSWrap::OnStreamAlloc(size_t suggested_size) {
  CHECK_NOT_NULL(ssl_);

  size_t size = suggested_size;
  char* base = crypto::NodeBIO::FromBIO(enc_in_)->PeekWritable(&size);
  return uv_buf_init(base, size);
}


void TLSWrap::OnStreamRead(ssize_t nread, const uv_buf_t& buf) {
  Debug(this, "Read %zd bytes from underlying stream", nread);
  if (nread < 0)  {
    // Error should be emitted only after all data was read
    ClearOut();

    // Ignore EOF if received close_notify
    if (nread == UV_EOF) {
      if (eof_)
        return;
      eof_ = true;
    }

    EmitRead(nread);
    return;
  }

  // DestroySSL() is the only thing that un-sets ssl_, but that also removes
  // this TLSWrap as a stream listener, so we should not receive OnStreamRead()
  // calls anymore.
  CHECK(ssl_);

  // Commit the amount of data actually read into the peeked/allocated buffer
  // from the underlying stream.
  crypto::NodeBIO* enc_in = crypto::NodeBIO::FromBIO(enc_in_);
  enc_in->Commit(nread);

  // Parse ClientHello first, if we need to. It's only parsed if session event
  // listeners are used on the server side.  "ended" is the initial state, so
  // can mean parsing was never started, or that parsing is finished. Either
  // way, ended means we can give the buffered data to SSL.
  if (!hello_parser_.IsEnded()) {
    size_t avail = 0;
    uint8_t* data = reinterpret_cast<uint8_t*>(enc_in->Peek(&avail));
    CHECK_IMPLIES(data == nullptr, avail == 0);
    Debug(this, "Passing %zu bytes to the hello parser", avail);
    return hello_parser_.Parse(data, avail);
  }

  // Cycle OpenSSL's state
  Cycle();
}


ShutdownWrap* TLSWrap::CreateShutdownWrap(Local<Object> req_wrap_object) {
  return underlying_stream()->CreateShutdownWrap(req_wrap_object);
}


int TLSWrap::DoShutdown(ShutdownWrap* req_wrap) {
  Debug(this, "DoShutdown()");
  crypto::MarkPopErrorOnReturn mark_pop_error_on_return;

  if (ssl_ && SSL_shutdown(ssl_.get()) == 0)
    SSL_shutdown(ssl_.get());

  shutdown_ = true;
  EncOut();
  return stream_->DoShutdown(req_wrap);
}


void TLSWrap::SetVerifyMode(const FunctionCallbackInfo<Value>& args) {
  TLSWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  CHECK_EQ(args.Length(), 2);
  CHECK(args[0]->IsBoolean());
  CHECK(args[1]->IsBoolean());
  CHECK_NOT_NULL(wrap->ssl_);

  int verify_mode;
  if (wrap->is_server()) {
    bool request_cert = args[0]->IsTrue();
    if (!request_cert) {
      // If no cert is requested, there will be none to reject as unauthorized.
      verify_mode = SSL_VERIFY_NONE;
    } else {
      bool reject_unauthorized = args[1]->IsTrue();
      verify_mode = SSL_VERIFY_PEER;
      if (reject_unauthorized)
        verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }
  } else {
    // Servers always send a cert if the cipher is not anonymous (anon is
    // disabled by default), so use VERIFY_NONE and check the cert after the
    // handshake has completed.
    verify_mode = SSL_VERIFY_NONE;
  }

  // Always allow a connection. We'll reject in javascript.
  SSL_set_verify(wrap->ssl_.get(), verify_mode, crypto::VerifyCallback);
}


void TLSWrap::EnableSessionCallbacks(
    const FunctionCallbackInfo<Value>& args) {
  TLSWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());
  CHECK_NOT_NULL(wrap->ssl_);
  wrap->enable_session_callbacks();

  // Clients don't use the HelloParser.
  if (wrap->is_client())
    return;

  crypto::NodeBIO::FromBIO(wrap->enc_in_)->set_initial(kMaxHelloLength);
  wrap->hello_parser_.Start(SSLWrap<TLSWrap>::OnClientHello,
                            OnClientHelloParseEnd,
                            wrap);
}

void TLSWrap::EnableKeylogCallback(
    const FunctionCallbackInfo<Value>& args) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  TLSWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());
  CHECK_NOT_NULL(wrap->sc_);
  SSL_CTX_set_keylog_callback(wrap->sc_->ctx_.get(),
      SSLWrap<TLSWrap>::KeylogCallback);
#endif // OPENSSL_VERSION_NUMBER >= 0x10100000L
}

// Check required capabilities were not excluded from the OpenSSL build:
// - OPENSSL_NO_SSL_TRACE excludes SSL_trace()
// - OPENSSL_NO_STDIO excludes BIO_new_fp()
// HAVE_SSL_TRACE is available on the internal tcp_wrap binding for the tests.
#if defined(OPENSSL_NO_SSL_TRACE) || defined(OPENSSL_NO_STDIO)
# define HAVE_SSL_TRACE 0
#else
# define HAVE_SSL_TRACE 1
#endif

void TLSWrap::EnableTrace(
    const FunctionCallbackInfo<Value>& args) {
  TLSWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

#if HAVE_SSL_TRACE
  if (wrap->ssl_) {
    wrap->bio_trace_.reset(BIO_new_fp(stderr,  BIO_NOCLOSE | BIO_FP_TEXT));
    SSL_set_msg_callback(wrap->ssl_.get(), [](int write_p, int version, int
          content_type, const void* buf, size_t len, SSL* ssl, void* arg)
        -> void {
        // BIO_write(), etc., called by SSL_trace, may error. The error should
        // be ignored, trace is a "best effort", and its usually because stderr
        // is a non-blocking pipe, and its buffer has overflowed. Leaving errors
        // on the stack that can get picked up by later SSL_ calls causes
        // unwanted failures in SSL_ calls, so keep the error stack unchanged.
        crypto::MarkPopErrorOnReturn mark_pop_error_on_return;
        SSL_trace(write_p,  version, content_type, buf, len, ssl, arg);
    });
    SSL_set_msg_callback_arg(wrap->ssl_.get(), wrap->bio_trace_.get());
  }
#endif
}

void TLSWrap::DestroySSL(const FunctionCallbackInfo<Value>& args) {
  TLSWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());
  Debug(wrap, "DestroySSL()");

  // If there is a write happening, mark it as finished.
  wrap->write_callback_scheduled_ = true;

  // And destroy
  wrap->InvokeQueued(UV_ECANCELED, "Canceled because of SSL destruction");

  // Destroy the SSL structure and friends
  wrap->SSLWrap<TLSWrap>::DestroySSL();
  wrap->enc_in_ = nullptr;
  wrap->enc_out_ = nullptr;

  if (wrap->stream_ != nullptr)
    wrap->stream_->RemoveStreamListener(wrap);
  Debug(wrap, "DestroySSL() finished");
}


void TLSWrap::EnableCertCb(const FunctionCallbackInfo<Value>& args) {
  TLSWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());
  wrap->WaitForCertCb(OnClientHelloParseEnd, wrap);
}


void TLSWrap::OnClientHelloParseEnd(void* arg) {
  TLSWrap* c = static_cast<TLSWrap*>(arg);
  Debug(c, "OnClientHelloParseEnd()");
  c->Cycle();
}


void TLSWrap::GetServername(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  TLSWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  CHECK_NOT_NULL(wrap->ssl_);

  const char* servername = SSL_get_servername(wrap->ssl_.get(),
                                              TLSEXT_NAMETYPE_host_name);
  if (servername != nullptr) {
    args.GetReturnValue().Set(OneByteString(env->isolate(), servername));
  } else {
    args.GetReturnValue().Set(false);
  }
}


void TLSWrap::SetServername(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  TLSWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  CHECK_EQ(args.Length(), 1);
  CHECK(args[0]->IsString());
  CHECK(!wrap->started_);
  CHECK(wrap->is_client());

  CHECK_NOT_NULL(wrap->ssl_);

  node::Utf8Value servername(env->isolate(), args[0].As<String>());
  SSL_set_tlsext_host_name(wrap->ssl_.get(), *servername);
}


int TLSWrap::SelectSNIContextCallback(SSL* s, int* ad, void* arg) {
  TLSWrap* p = static_cast<TLSWrap*>(SSL_get_app_data(s));
  Environment* env = p->env();

  const char* servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);

  if (servername == nullptr)
    return SSL_TLSEXT_ERR_OK;

  HandleScope handle_scope(env->isolate());
  Context::Scope context_scope(env->context());

  // Call the SNI callback and use its return value as context
  Local<Object> object = p->object();
  Local<Value> ctx;

  // Set the servername as early as possible
  Local<Object> owner = p->GetOwner();
  if (!owner->Set(env->context(),
                  env->servername_string(),
                  OneByteString(env->isolate(), servername)).FromMaybe(false)) {
    return SSL_TLSEXT_ERR_NOACK;
  }

  if (!object->Get(env->context(), env->sni_context_string()).ToLocal(&ctx))
    return SSL_TLSEXT_ERR_NOACK;

  // Not an object, probably undefined or null
  if (!ctx->IsObject())
    return SSL_TLSEXT_ERR_NOACK;

  Local<FunctionTemplate> cons = env->secure_context_constructor_template();
  if (!cons->HasInstance(ctx)) {
    // Failure: incorrect SNI context object
    Local<Value> err = Exception::TypeError(env->sni_context_err_string());
    p->MakeCallback(env->onerror_string(), 1, &err);
    return SSL_TLSEXT_ERR_NOACK;
  }

  p->sni_context_.Reset(env->isolate(), ctx);

  SecureContext* sc = Unwrap<SecureContext>(ctx.As<Object>());
  CHECK_NOT_NULL(sc);
  p->SetSNIContext(sc);
  return SSL_TLSEXT_ERR_OK;
}


void TLSWrap::GetWriteQueueSize(const FunctionCallbackInfo<Value>& info) {
  TLSWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, info.This());

  if (wrap->ssl_ == nullptr) {
    info.GetReturnValue().Set(0);
    return;
  }

  uint32_t write_queue_size = BIO_pending(wrap->enc_out_);
  info.GetReturnValue().Set(write_queue_size);
}


void TLSWrap::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("error", error_);
  tracker->TrackFieldWithSize("pending_cleartext_input",
                              pending_cleartext_input_.size(),
                              "AllocatedBuffer");
  if (enc_in_ != nullptr)
    tracker->TrackField("enc_in", crypto::NodeBIO::FromBIO(enc_in_));
  if (enc_out_ != nullptr)
    tracker->TrackField("enc_out", crypto::NodeBIO::FromBIO(enc_out_));
}


void TLSWrap::Initialize(Local<Object> target,
                         Local<Value> unused,
                         Local<Context> context,
                         void* priv) {
  Environment* env = Environment::GetCurrent(context);

  env->SetMethod(target, "wrap", TLSWrap::Wrap);

  NODE_DEFINE_CONSTANT(target, HAVE_SSL_TRACE);

  Local<FunctionTemplate> t = BaseObject::MakeLazilyInitializedJSTemplate(env);
  Local<String> tlsWrapString =
      FIXED_ONE_BYTE_STRING(env->isolate(), "TLSWrap");
  t->SetClassName(tlsWrapString);
  t->InstanceTemplate()
    ->SetInternalFieldCount(StreamBase::kStreamBaseFieldCount);

  Local<FunctionTemplate> get_write_queue_size =
      FunctionTemplate::New(env->isolate(),
                            GetWriteQueueSize,
                            env->as_callback_data(),
                            Signature::New(env->isolate(), t));
  t->PrototypeTemplate()->SetAccessorProperty(
      env->write_queue_size_string(),
      get_write_queue_size,
      Local<FunctionTemplate>(),
      static_cast<PropertyAttribute>(ReadOnly | DontDelete));

  t->Inherit(AsyncWrap::GetConstructorTemplate(env));
  env->SetProtoMethod(t, "receive", Receive);
  env->SetProtoMethod(t, "start", Start);
  env->SetProtoMethod(t, "setVerifyMode", SetVerifyMode);
  env->SetProtoMethod(t, "enableSessionCallbacks", EnableSessionCallbacks);
  env->SetProtoMethod(t, "enableKeylogCallback", EnableKeylogCallback);
  env->SetProtoMethod(t, "enableTrace", EnableTrace);
  env->SetProtoMethod(t, "destroySSL", DestroySSL);
  env->SetProtoMethod(t, "enableCertCb", EnableCertCb);

  StreamBase::AddMethods(env, t);
  SSLWrap<TLSWrap>::AddMethods(env, t);

  env->SetProtoMethod(t, "getServername", GetServername);
  env->SetProtoMethod(t, "setServername", SetServername);

  env->set_tls_wrap_constructor_function(
      t->GetFunction(env->context()).ToLocalChecked());

  target->Set(env->context(),
              tlsWrapString,
              t->GetFunction(env->context()).ToLocalChecked()).Check();
}

}  // namespace node

NODE_MODULE_CONTEXT_AWARE_INTERNAL(tls_wrap, node::TLSWrap::Initialize)
