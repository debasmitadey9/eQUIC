import datetime
import ipaddress
import logging
import os
import ssl
import struct
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from functools import partial
from typing import (
    Any,
    Callable,
    Dict,
    Generator,
    List,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
    cast,
)

import time


import certifi
import service_identity
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    padding,
    rsa,
    x448,
    x25519,
)
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPublicKeyTypes,
    PrivateKeyTypes,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from OpenSSL import crypto

from .buffer import Buffer, BufferReadError

TLS_VERSION_1_2 = 0x0303
TLS_VERSION_1_3 = 0x0304
TLS_VERSION_1_3_DRAFT_28 = 0x7F1C
TLS_VERSION_1_3_DRAFT_27 = 0x7F1B
TLS_VERSION_1_3_DRAFT_26 = 0x7F1A

CLIENT_CONTEXT_STRING = b"TLS 1.3, client CertificateVerify"
SERVER_CONTEXT_STRING = b"TLS 1.3, server CertificateVerify"

T = TypeVar("T")


# facilitate mocking for the test suite
def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class AlertDescription(IntEnum):
    close_notify = 0
    unexpected_message = 10
    bad_record_mac = 20
    record_overflow = 22
    handshake_failure = 40
    bad_certificate = 42
    unsupported_certificate = 43
    certificate_revoked = 44
    certificate_expired = 45
    certificate_unknown = 46
    illegal_parameter = 47
    unknown_ca = 48
    access_denied = 49
    decode_error = 50
    decrypt_error = 51
    protocol_version = 70
    insufficient_security = 71
    internal_error = 80
    inappropriate_fallback = 86
    user_canceled = 90
    missing_extension = 109
    unsupported_extension = 110
    unrecognized_name = 112
    bad_certificate_status_response = 113
    unknown_psk_identity = 115
    certificate_required = 116
    no_application_protocol = 120


class Alert(Exception):
    description: AlertDescription


class AlertBadCertificate(Alert):
    description = AlertDescription.bad_certificate


class AlertCertificateExpired(Alert):
    description = AlertDescription.certificate_expired


class AlertDecodeError(Alert):
    description = AlertDescription.decode_error


class AlertDecryptError(Alert):
    description = AlertDescription.decrypt_error


class AlertHandshakeFailure(Alert):
    description = AlertDescription.handshake_failure


class AlertIllegalParameter(Alert):
    description = AlertDescription.illegal_parameter


class AlertInternalError(Alert):
    description = AlertDescription.internal_error


class AlertProtocolVersion(Alert):
    description = AlertDescription.protocol_version


class AlertUnexpectedMessage(Alert):
    description = AlertDescription.unexpected_message


class Direction(Enum):
    DECRYPT = 0
    ENCRYPT = 1


class Epoch(Enum):
    INITIAL = 0
    ZERO_RTT = 1
    HANDSHAKE = 2
    ONE_RTT = 3


class State(Enum):
    CLIENT_HANDSHAKE_START = 0
    CLIENT_EXPECT_SERVER_HELLO = 1
    CLIENT_EXPECT_ENCRYPTED_EXTENSIONS = 2
    CLIENT_EXPECT_CERTIFICATE_REQUEST_OR_CERTIFICATE = 3
    CLIENT_EXPECT_CERTIFICATE = 4
    CLIENT_EXPECT_CERTIFICATE_VERIFY = 5
    CLIENT_EXPECT_FINISHED = 6
    CLIENT_POST_HANDSHAKE = 7

    SERVER_EXPECT_CLIENT_HELLO = 8
    SERVER_EXPECT_CERTIFICATE = 9
    SERVER_EXPECT_CERTIFICATE_VERIFY = 10
    SERVER_EXPECT_FINISHED = 11
    SERVER_POST_HANDSHAKE = 12


def hkdf_label(label: bytes, hash_value: bytes, length: int) -> bytes:
    full_label = b"tls13 " + label
    return (
        struct.pack("!HB", length, len(full_label))
        + full_label
        + struct.pack("!B", len(hash_value))
        + hash_value
    )


def hkdf_expand_label(
    algorithm: hashes.HashAlgorithm,
    secret: bytes,
    label: bytes,
    hash_value: bytes,
    length: int,
) -> bytes:
    return HKDFExpand(
        algorithm=algorithm,
        length=length,
        info=hkdf_label(label, hash_value, length),
    ).derive(secret)


def hkdf_extract(
    algorithm: hashes.HashAlgorithm, salt: bytes, key_material: bytes
) -> bytes:
    h = hmac.HMAC(salt, algorithm)
    h.update(key_material)
    return h.finalize()


def load_pem_private_key(
    data: bytes, password: Optional[bytes] = None
) -> PrivateKeyTypes:
    """
    Load a PEM-encoded private key.
    """
    return serialization.load_pem_private_key(data, password=password)


def load_pem_x509_certificates(data: bytes) -> List[x509.Certificate]:
    """
    Load a chain of PEM-encoded X509 certificates.
    """
    boundary = b"-----END CERTIFICATE-----\n"
    certificates = []
    for chunk in data.split(boundary):
        if chunk:
            certificates.append(x509.load_pem_x509_certificate(chunk + boundary))
    return certificates


def verify_certificate(
    certificate: x509.Certificate,
    chain: List[x509.Certificate] = [],
    server_name: Optional[str] = None,
    cadata: Optional[bytes] = None,
    cafile: Optional[str] = None,
    capath: Optional[str] = None,
) -> None:
    # verify dates
    now = utcnow()
    if now < certificate.not_valid_before_utc:
        raise AlertCertificateExpired("Certificate is not valid yet")
    if now > certificate.not_valid_after_utc:
        raise AlertCertificateExpired("Certificate is no longer valid")

    # verify subject
    if server_name is not None:
        try:
            ipaddress.ip_address(server_name)
        except ValueError:
            is_ip = False
        else:
            is_ip = True

        try:
            if is_ip:
                service_identity.cryptography.verify_certificate_ip_address(
                    certificate, server_name
                )
            else:
                service_identity.cryptography.verify_certificate_hostname(
                    certificate, server_name
                )

        except (
            service_identity.CertificateError,
            service_identity.VerificationError,
        ) as exc:
            patterns = service_identity.cryptography.extract_patterns(certificate)
            if len(patterns) == 0:
                errmsg = str(exc)
            elif len(patterns) == 1:
                errmsg = f"hostname {server_name!r} doesn't match {patterns[0]!r}"
            else:
                patterns_repr = ", ".join(repr(pattern) for pattern in patterns)
                errmsg = (
                    f"hostname {server_name!r} doesn't match "
                    f"either of {patterns_repr}"
                )

            raise AlertBadCertificate(errmsg) from exc

    # load CAs
    store = crypto.X509Store()

    if cadata is None and cafile is None and capath is None:
        # Load defaults from certifi.
        store.load_locations(certifi.where())

    if cadata is not None:
        for cert in load_pem_x509_certificates(cadata):
            store.add_cert(crypto.X509.from_cryptography(cert))

    if cafile is not None or capath is not None:
        store.load_locations(cafile, capath)

    # verify certificate chain
    store_ctx = crypto.X509StoreContext(
        store,
        crypto.X509.from_cryptography(certificate),
        [crypto.X509.from_cryptography(cert) for cert in chain],
    )
    try:
        store_ctx.verify_certificate()
    except crypto.X509StoreContextError as exc:
        raise AlertBadCertificate(exc.args[0])


class CipherSuite(IntEnum):
    AES_128_GCM_SHA256 = 0x1301
    AES_256_GCM_SHA384 = 0x1302
    CHACHA20_POLY1305_SHA256 = 0x1303
    EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF


class CompressionMethod(IntEnum):
    NULL = 0


class ExtensionType(IntEnum):
    SERVER_NAME = 0
    STATUS_REQUEST = 5
    SUPPORTED_GROUPS = 10
    SIGNATURE_ALGORITHMS = 13
    ALPN = 16
    COMPRESS_CERTIFICATE = 27
    PRE_SHARED_KEY = 41
    EARLY_DATA = 42
    SUPPORTED_VERSIONS = 43
    COOKIE = 44
    PSK_KEY_EXCHANGE_MODES = 45
    KEY_SHARE = 51
    QUIC_TRANSPORT_PARAMETERS = 0x0039
    QUIC_TRANSPORT_PARAMETERS_DRAFT = 0xFFA5
    ENCRYPTED_SERVER_NAME = 65486


class Group(IntEnum):
    SECP256R1 = 0x0017
    SECP384R1 = 0x0018
    SECP521R1 = 0x0019
    X25519 = 0x001D
    X448 = 0x001E
    GREASE = 0xAAAA


class HandshakeType(IntEnum):
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    NEW_SESSION_TICKET = 4
    END_OF_EARLY_DATA = 5
    ENCRYPTED_EXTENSIONS = 8
    CERTIFICATE = 11
    CERTIFICATE_REQUEST = 13
    CERTIFICATE_VERIFY = 15
    FINISHED = 20
    KEY_UPDATE = 24
    COMPRESSED_CERTIFICATE = 25
    MESSAGE_HASH = 254


class NameType(IntEnum):
    HOST_NAME = 0


class PskKeyExchangeMode(IntEnum):
    PSK_KE = 0
    PSK_DHE_KE = 1


class SignatureAlgorithm(IntEnum):
    ECDSA_SECP256R1_SHA256 = 0x0403
    ECDSA_SECP384R1_SHA384 = 0x0503
    ECDSA_SECP521R1_SHA512 = 0x0603
    ED25519 = 0x0807
    ED448 = 0x0808
    RSA_PKCS1_SHA256 = 0x0401
    RSA_PKCS1_SHA384 = 0x0501
    RSA_PKCS1_SHA512 = 0x0601
    RSA_PSS_PSS_SHA256 = 0x0809
    RSA_PSS_PSS_SHA384 = 0x080A
    RSA_PSS_PSS_SHA512 = 0x080B
    RSA_PSS_RSAE_SHA256 = 0x0804
    RSA_PSS_RSAE_SHA384 = 0x0805
    RSA_PSS_RSAE_SHA512 = 0x0806

    # legacy
    RSA_PKCS1_SHA1 = 0x0201
    SHA1_DSA = 0x0202
    ECDSA_SHA1 = 0x0203


# BLOCKS


@contextmanager
def pull_block(buf: Buffer, capacity: int) -> Generator:
    length = int.from_bytes(buf.pull_bytes(capacity), byteorder="big")
    end = buf.tell() + length
    yield length
    if buf.tell() != end:
        # There was trailing garbage or our parsing was bad.
        raise AlertDecodeError("extra bytes at the end of a block")


@contextmanager
def push_block(buf: Buffer, capacity: int) -> Generator:
    """
    Context manager to push a variable-length block, with `capacity` bytes
    to write the length.
    """
    start = buf.tell() + capacity
    buf.seek(start)
    yield
    end = buf.tell()
    length = end - start
    buf.seek(start - capacity)
    buf.push_bytes(length.to_bytes(capacity, byteorder="big"))
    buf.seek(end)


# LISTS


class SkipItem(Exception):
    "There is nothing to append for this invocation of a pull_list() func"


def pull_list(buf: Buffer, capacity: int, func: Callable[[], T]) -> List[T]:
    """
    Pull a list of items.

    If the callable raises SkipItem, then iteration continues but nothing
    is added to the list.
    """
    items = []
    with pull_block(buf, capacity) as length:
        end = buf.tell() + length
        while buf.tell() < end:
            try:
                items.append(func())
            except SkipItem:
                pass
    return items


def push_list(
    buf: Buffer, capacity: int, func: Callable[[T], None], values: Sequence[T]
) -> None:
    """
    Push a list of items.
    """
    with push_block(buf, capacity):
        for value in values:
            func(value)


def pull_opaque(buf: Buffer, capacity: int) -> bytes:
    """
    Pull an opaque value prefixed by a length.
    """
    with pull_block(buf, capacity) as length:
        return buf.pull_bytes(length)


def push_opaque(buf: Buffer, capacity: int, value: bytes) -> None:
    """
    Push an opaque value prefix by a length.
    """
    with push_block(buf, capacity):
        buf.push_bytes(value)


@contextmanager
def push_extension(buf: Buffer, extension_type: int) -> Generator:
    buf.push_uint16(extension_type)
    with push_block(buf, 2):
        yield


# ServerName


def pull_server_name(buf: Buffer) -> str:
    with pull_block(buf, 2):
        name_type = buf.pull_uint8()
        if name_type != NameType.HOST_NAME:
            # We don't know this name_type.
            raise AlertIllegalParameter(
                f"ServerName has an unknown name type {name_type}"
            )
        return pull_opaque(buf, 2).decode("ascii")


def push_server_name(buf: Buffer, server_name: str) -> None:
    with push_block(buf, 2):
        buf.push_uint8(NameType.HOST_NAME)
        push_opaque(buf, 2, server_name.encode("ascii"))


# KeyShareEntry


KeyShareEntry = Tuple[int, bytes]


def pull_key_share(buf: Buffer) -> KeyShareEntry:
    group = buf.pull_uint16()
    data = pull_opaque(buf, 2)
    return (group, data)


def push_key_share(buf: Buffer, value: KeyShareEntry) -> None:
    buf.push_uint16(value[0])
    push_opaque(buf, 2, value[1])


# ALPN


def pull_alpn_protocol(buf: Buffer) -> str:
    try:
        return pull_opaque(buf, 1).decode("ascii")
    except UnicodeDecodeError:
        # We can get arbitrary bytes values for alpns from greasing,
        # but we expect them to be strings in the rest of the API, so
        # we ignore them if they don't decode as ASCII.
        raise SkipItem


def push_alpn_protocol(buf: Buffer, protocol: str) -> None:
    push_opaque(buf, 1, protocol.encode("ascii"))


# PRE SHARED KEY

PskIdentity = Tuple[bytes, int]


@dataclass
class OfferedPsks:
    identities: List[PskIdentity]
    binders: List[bytes]


def pull_psk_identity(buf: Buffer) -> PskIdentity:
    identity = pull_opaque(buf, 2)
    obfuscated_ticket_age = buf.pull_uint32()
    return (identity, obfuscated_ticket_age)


def push_psk_identity(buf: Buffer, entry: PskIdentity) -> None:
    push_opaque(buf, 2, entry[0])
    buf.push_uint32(entry[1])


def pull_psk_binder(buf: Buffer) -> bytes:
    return pull_opaque(buf, 1)


def push_psk_binder(buf: Buffer, binder: bytes) -> None:
    push_opaque(buf, 1, binder)


def pull_offered_psks(buf: Buffer) -> OfferedPsks:
    return OfferedPsks(
        identities=pull_list(buf, 2, partial(pull_psk_identity, buf)),
        binders=pull_list(buf, 2, partial(pull_psk_binder, buf)),
    )


def push_offered_psks(buf: Buffer, pre_shared_key: OfferedPsks) -> None:
    push_list(
        buf,
        2,
        partial(push_psk_identity, buf),
        pre_shared_key.identities,
    )
    push_list(
        buf,
        2,
        partial(push_psk_binder, buf),
        pre_shared_key.binders,
    )


# MESSAGES

Extension = Tuple[int, bytes]


@dataclass
class ClientHello:
    random: bytes
    legacy_session_id: bytes
    cipher_suites: List[int]
    legacy_compression_methods: List[int]

    # extensions
    alpn_protocols: Optional[List[str]] = None
    early_data: bool = False
    key_share: Optional[List[KeyShareEntry]] = None
    pre_shared_key: Optional[OfferedPsks] = None
    psk_key_exchange_modes: Optional[List[int]] = None
    server_name: Optional[str] = None
    signature_algorithms: Optional[List[int]] = None
    supported_groups: Optional[List[int]] = None
    supported_versions: Optional[List[int]] = None

    other_extensions: List[Extension] = field(default_factory=list)


def pull_handshake_type(buf: Buffer, expected_type: HandshakeType) -> None:
    """
    Pull the message type and assert it is the expected one.

    If it is not, we have a programming error.
    """
    message_type = buf.pull_uint8()
    assert message_type == expected_type


def pull_client_hello(buf: Buffer) -> ClientHello:
    pull_handshake_type(buf, HandshakeType.CLIENT_HELLO)
    with pull_block(buf, 3):
        if buf.pull_uint16() != TLS_VERSION_1_2:
            raise AlertDecodeError("ClientHello version is not 1.2")

        hello = ClientHello(
            random=buf.pull_bytes(32),
            legacy_session_id=pull_opaque(buf, 1),
            cipher_suites=pull_list(buf, 2, buf.pull_uint16),
            legacy_compression_methods=pull_list(buf, 1, buf.pull_uint8),
        )

        # extensions
        after_psk = False

        def pull_extension() -> None:
            # pre_shared_key MUST be last
            nonlocal after_psk
            if after_psk:
                # the alert is Illegal Parameter per RFC 8446 section 4.2.11.
                raise AlertIllegalParameter("PreSharedKey is not the last extension")

            extension_type = buf.pull_uint16()
            extension_length = buf.pull_uint16()
            if extension_type == ExtensionType.KEY_SHARE:
                hello.key_share = pull_list(buf, 2, partial(pull_key_share, buf))
            elif extension_type == ExtensionType.SUPPORTED_VERSIONS:
                hello.supported_versions = pull_list(buf, 1, buf.pull_uint16)
            elif extension_type == ExtensionType.SIGNATURE_ALGORITHMS:
                hello.signature_algorithms = pull_list(buf, 2, buf.pull_uint16)
            elif extension_type == ExtensionType.SUPPORTED_GROUPS:
                hello.supported_groups = pull_list(buf, 2, buf.pull_uint16)
            elif extension_type == ExtensionType.PSK_KEY_EXCHANGE_MODES:
                hello.psk_key_exchange_modes = pull_list(buf, 1, buf.pull_uint8)
            elif extension_type == ExtensionType.SERVER_NAME:
                hello.server_name = pull_server_name(buf)
            elif extension_type == ExtensionType.ALPN:
                hello.alpn_protocols = pull_list(
                    buf, 2, partial(pull_alpn_protocol, buf)
                )
            elif extension_type == ExtensionType.EARLY_DATA:
                hello.early_data = True
            elif extension_type == ExtensionType.PRE_SHARED_KEY:
                hello.pre_shared_key = pull_offered_psks(buf)
                after_psk = True
            else:
                hello.other_extensions.append(
                    (extension_type, buf.pull_bytes(extension_length))
                )

        pull_list(buf, 2, pull_extension)

    return hello


def push_client_hello(buf: Buffer, hello: ClientHello) -> None:
    buf.push_uint8(HandshakeType.CLIENT_HELLO)
    with push_block(buf, 3):
        buf.push_uint16(TLS_VERSION_1_2)
        buf.push_bytes(hello.random)
        push_opaque(buf, 1, hello.legacy_session_id)
        push_list(buf, 2, buf.push_uint16, hello.cipher_suites)
        push_list(buf, 1, buf.push_uint8, hello.legacy_compression_methods)

        # extensions
        with push_block(buf, 2):
            with push_extension(buf, ExtensionType.KEY_SHARE):
                push_list(buf, 2, partial(push_key_share, buf), hello.key_share)

            with push_extension(buf, ExtensionType.SUPPORTED_VERSIONS):
                push_list(buf, 1, buf.push_uint16, hello.supported_versions)

            with push_extension(buf, ExtensionType.SIGNATURE_ALGORITHMS):
                push_list(buf, 2, buf.push_uint16, hello.signature_algorithms)

            with push_extension(buf, ExtensionType.SUPPORTED_GROUPS):
                push_list(buf, 2, buf.push_uint16, hello.supported_groups)

            if hello.psk_key_exchange_modes is not None:
                with push_extension(buf, ExtensionType.PSK_KEY_EXCHANGE_MODES):
                    push_list(buf, 1, buf.push_uint8, hello.psk_key_exchange_modes)

            if hello.server_name is not None:
                with push_extension(buf, ExtensionType.SERVER_NAME):
                    push_server_name(buf, hello.server_name)

            if hello.alpn_protocols is not None:
                with push_extension(buf, ExtensionType.ALPN):
                    push_list(
                        buf, 2, partial(push_alpn_protocol, buf), hello.alpn_protocols
                    )

            for extension_type, extension_value in hello.other_extensions:
                with push_extension(buf, extension_type):
                    buf.push_bytes(extension_value)

            if hello.early_data:
                with push_extension(buf, ExtensionType.EARLY_DATA):
                    pass

            # pre_shared_key MUST be last
            if hello.pre_shared_key is not None:
                with push_extension(buf, ExtensionType.PRE_SHARED_KEY):
                    push_offered_psks(buf, hello.pre_shared_key)


@dataclass
class ServerHello:
    random: bytes
    legacy_session_id: bytes
    cipher_suite: int
    compression_method: int

    # extensions
    key_share: Optional[KeyShareEntry] = None
    pre_shared_key: Optional[int] = None
    supported_version: Optional[int] = None
    other_extensions: List[Tuple[int, bytes]] = field(default_factory=list)


def pull_server_hello(buf: Buffer) -> ServerHello:
    pull_handshake_type(buf, HandshakeType.SERVER_HELLO)
    with pull_block(buf, 3):
        if buf.pull_uint16() != TLS_VERSION_1_2:
            raise AlertDecodeError("ServerHello version is not 1.2")

        hello = ServerHello(
            random=buf.pull_bytes(32),
            legacy_session_id=pull_opaque(buf, 1),
            cipher_suite=buf.pull_uint16(),
            compression_method=buf.pull_uint8(),
        )

        # extensions
        def pull_extension() -> None:
            extension_type = buf.pull_uint16()
            extension_length = buf.pull_uint16()
            if extension_type == ExtensionType.SUPPORTED_VERSIONS:
                hello.supported_version = buf.pull_uint16()
            elif extension_type == ExtensionType.KEY_SHARE:
                hello.key_share = pull_key_share(buf)
            elif extension_type == ExtensionType.PRE_SHARED_KEY:
                hello.pre_shared_key = buf.pull_uint16()
            else:
                hello.other_extensions.append(
                    (extension_type, buf.pull_bytes(extension_length))
                )

        pull_list(buf, 2, pull_extension)

    return hello


def push_server_hello(buf: Buffer, hello: ServerHello) -> None:
    buf.push_uint8(HandshakeType.SERVER_HELLO)
    with push_block(buf, 3):
        buf.push_uint16(TLS_VERSION_1_2)
        buf.push_bytes(hello.random)

        push_opaque(buf, 1, hello.legacy_session_id)
        buf.push_uint16(hello.cipher_suite)
        buf.push_uint8(hello.compression_method)

        # extensions
        with push_block(buf, 2):
            if hello.supported_version is not None:
                with push_extension(buf, ExtensionType.SUPPORTED_VERSIONS):
                    buf.push_uint16(hello.supported_version)

            if hello.key_share is not None:
                with push_extension(buf, ExtensionType.KEY_SHARE):
                    push_key_share(buf, hello.key_share)

            if hello.pre_shared_key is not None:
                with push_extension(buf, ExtensionType.PRE_SHARED_KEY):
                    buf.push_uint16(hello.pre_shared_key)

            for extension_type, extension_value in hello.other_extensions:
                with push_extension(buf, extension_type):
                    buf.push_bytes(extension_value)


@dataclass
class NewSessionTicket:
    ticket_lifetime: int = 0
    ticket_age_add: int = 0
    ticket_nonce: bytes = b""
    ticket: bytes = b""

    # extensions
    max_early_data_size: Optional[int] = None
    other_extensions: List[Tuple[int, bytes]] = field(default_factory=list)


def pull_new_session_ticket(buf: Buffer) -> NewSessionTicket:
    new_session_ticket = NewSessionTicket()

    pull_handshake_type(buf, HandshakeType.NEW_SESSION_TICKET)
    with pull_block(buf, 3):
        new_session_ticket.ticket_lifetime = buf.pull_uint32()
        new_session_ticket.ticket_age_add = buf.pull_uint32()
        new_session_ticket.ticket_nonce = pull_opaque(buf, 1)
        new_session_ticket.ticket = pull_opaque(buf, 2)

        def pull_extension() -> None:
            extension_type = buf.pull_uint16()
            extension_length = buf.pull_uint16()
            if extension_type == ExtensionType.EARLY_DATA:
                new_session_ticket.max_early_data_size = buf.pull_uint32()
            else:
                new_session_ticket.other_extensions.append(
                    (extension_type, buf.pull_bytes(extension_length))
                )

        pull_list(buf, 2, pull_extension)

    return new_session_ticket


def push_new_session_ticket(buf: Buffer, new_session_ticket: NewSessionTicket) -> None:
    buf.push_uint8(HandshakeType.NEW_SESSION_TICKET)
    with push_block(buf, 3):
        buf.push_uint32(new_session_ticket.ticket_lifetime)
        buf.push_uint32(new_session_ticket.ticket_age_add)
        push_opaque(buf, 1, new_session_ticket.ticket_nonce)
        push_opaque(buf, 2, new_session_ticket.ticket)

        with push_block(buf, 2):
            if new_session_ticket.max_early_data_size is not None:
                with push_extension(buf, ExtensionType.EARLY_DATA):
                    buf.push_uint32(new_session_ticket.max_early_data_size)

            for extension_type, extension_value in new_session_ticket.other_extensions:
                with push_extension(buf, extension_type):
                    buf.push_bytes(extension_value)


@dataclass
class EncryptedExtensions:
    alpn_protocol: Optional[str] = None
    early_data: bool = False

    other_extensions: List[Tuple[int, bytes]] = field(default_factory=list)


def pull_encrypted_extensions(buf: Buffer) -> EncryptedExtensions:
    extensions = EncryptedExtensions()

    pull_handshake_type(buf, HandshakeType.ENCRYPTED_EXTENSIONS)
    with pull_block(buf, 3):

        def pull_extension() -> None:
            extension_type = buf.pull_uint16()
            extension_length = buf.pull_uint16()
            if extension_type == ExtensionType.ALPN:
                extensions.alpn_protocol = pull_list(
                    buf, 2, partial(pull_alpn_protocol, buf)
                )[0]
            elif extension_type == ExtensionType.EARLY_DATA:
                extensions.early_data = True
            else:
                extensions.other_extensions.append(
                    (extension_type, buf.pull_bytes(extension_length))
                )

        pull_list(buf, 2, pull_extension)

    return extensions


def push_encrypted_extensions(buf: Buffer, extensions: EncryptedExtensions) -> None:
    buf.push_uint8(HandshakeType.ENCRYPTED_EXTENSIONS)
    with push_block(buf, 3):
        with push_block(buf, 2):
            if extensions.alpn_protocol is not None:
                with push_extension(buf, ExtensionType.ALPN):
                    push_list(
                        buf,
                        2,
                        partial(push_alpn_protocol, buf),
                        [extensions.alpn_protocol],
                    )

            if extensions.early_data:
                with push_extension(buf, ExtensionType.EARLY_DATA):
                    pass

            for extension_type, extension_value in extensions.other_extensions:
                with push_extension(buf, extension_type):
                    buf.push_bytes(extension_value)


CertificateEntry = Tuple[bytes, bytes]


@dataclass
class Certificate:
    request_context: bytes = b""
    certificates: List[CertificateEntry] = field(default_factory=list)


def pull_certificate(buf: Buffer) -> Certificate:
    certificate = Certificate()

    pull_handshake_type(buf, HandshakeType.CERTIFICATE)
    with pull_block(buf, 3):
        certificate.request_context = pull_opaque(buf, 1)

        def pull_certificate_entry(buf: Buffer) -> CertificateEntry:
            data = pull_opaque(buf, 3)
            extensions = pull_opaque(buf, 2)
            return (data, extensions)

        certificate.certificates = pull_list(
            buf, 3, partial(pull_certificate_entry, buf)
        )

    return certificate


def push_certificate(buf: Buffer, certificate: Certificate) -> None:
    buf.push_uint8(HandshakeType.CERTIFICATE)
    with push_block(buf, 3):
        push_opaque(buf, 1, certificate.request_context)

        def push_certificate_entry(buf: Buffer, entry: CertificateEntry) -> None:
            push_opaque(buf, 3, entry[0])
            push_opaque(buf, 2, entry[1])

        push_list(
            buf, 3, partial(push_certificate_entry, buf), certificate.certificates
        )


@dataclass
class CertificateRequest:
    request_context: bytes = b""
    signature_algorithms: Optional[List[int]] = None
    other_extensions: List[Tuple[int, bytes]] = field(default_factory=list)


def pull_certificate_request(buf: Buffer) -> CertificateRequest:
    certificate_request = CertificateRequest()

    pull_handshake_type(buf, HandshakeType.CERTIFICATE_REQUEST)
    with pull_block(buf, 3):
        certificate_request.request_context = pull_opaque(buf, 1)

        def pull_extension() -> None:
            extension_type = buf.pull_uint16()
            extension_length = buf.pull_uint16()
            if extension_type == ExtensionType.SIGNATURE_ALGORITHMS:
                certificate_request.signature_algorithms = pull_list(
                    buf, 2, buf.pull_uint16
                )
            else:
                certificate_request.other_extensions.append(
                    (extension_type, buf.pull_bytes(extension_length))
                )

        pull_list(buf, 2, pull_extension)

    return certificate_request


def push_certificate_request(
    buf: Buffer, certificate_request: CertificateRequest
) -> None:
    buf.push_uint8(HandshakeType.CERTIFICATE_REQUEST)
    with push_block(buf, 3):
        push_opaque(buf, 1, certificate_request.request_context)

        with push_block(buf, 2):
            with push_extension(buf, ExtensionType.SIGNATURE_ALGORITHMS):
                push_list(
                    buf, 2, buf.push_uint16, certificate_request.signature_algorithms
                )

            for extension_type, extension_value in certificate_request.other_extensions:
                with push_extension(buf, extension_type):
                    buf.push_bytes(extension_value)


@dataclass
class CertificateVerify:
    algorithm: int
    signature: bytes


def pull_certificate_verify(buf: Buffer) -> CertificateVerify:
    pull_handshake_type(buf, HandshakeType.CERTIFICATE_VERIFY)
    with pull_block(buf, 3):
        algorithm = buf.pull_uint16()
        signature = pull_opaque(buf, 2)

    return CertificateVerify(algorithm=algorithm, signature=signature)


def push_certificate_verify(buf: Buffer, verify: CertificateVerify) -> None:
    buf.push_uint8(HandshakeType.CERTIFICATE_VERIFY)
    with push_block(buf, 3):
        buf.push_uint16(verify.algorithm)
        push_opaque(buf, 2, verify.signature)


@dataclass
class Finished:
    verify_data: bytes = b""


def pull_finished(buf: Buffer) -> Finished:
    finished = Finished()

    pull_handshake_type(buf, HandshakeType.FINISHED)
    finished.verify_data = pull_opaque(buf, 3)

    return finished


def push_finished(buf: Buffer, finished: Finished) -> None:
    buf.push_uint8(HandshakeType.FINISHED)
    push_opaque(buf, 3, finished.verify_data)


# CONTEXT


class KeySchedule:
    def __init__(self, cipher_suite: CipherSuite):
        self.algorithm = cipher_suite_hash(cipher_suite)
        self.cipher_suite = cipher_suite
        self.generation = 0
        self.hash = hashes.Hash(self.algorithm)
        self.hash_empty_value = self.hash.copy().finalize()
        self.secret = bytes(self.algorithm.digest_size)

    def certificate_verify_data(self, context_string: bytes) -> bytes:
        return b" " * 64 + context_string + b"\x00" + self.hash.copy().finalize()

    def finished_verify_data(self, secret: bytes) -> bytes:
        hmac_key = hkdf_expand_label(
            algorithm=self.algorithm,
            secret=secret,
            label=b"finished",
            hash_value=b"",
            length=self.algorithm.digest_size,
        )

        h = hmac.HMAC(hmac_key, algorithm=self.algorithm)
        h.update(self.hash.copy().finalize())
        return h.finalize()

    def derive_secret(self, label: bytes) -> bytes:
        return hkdf_expand_label(
            algorithm=self.algorithm,
            secret=self.secret,
            label=label,
            hash_value=self.hash.copy().finalize(),
            length=self.algorithm.digest_size,
        )

    def extract(self, key_material: Optional[bytes] = None) -> None:
        if key_material is None:
            key_material = bytes(self.algorithm.digest_size)

        if self.generation:
            self.secret = hkdf_expand_label(
                algorithm=self.algorithm,
                secret=self.secret,
                label=b"derived",
                hash_value=self.hash_empty_value,
                length=self.algorithm.digest_size,
            )

        self.generation += 1
        self.secret = hkdf_extract(
            algorithm=self.algorithm, salt=self.secret, key_material=key_material
        )

    def update_hash(self, data: bytes) -> None:
        self.hash.update(data)


class KeyScheduleProxy:
    def __init__(self, cipher_suites: List[CipherSuite]):
        self.__schedules = dict(map(lambda c: (c, KeySchedule(c)), cipher_suites))

    def extract(self, key_material: Optional[bytes] = None) -> None:
        for k in self.__schedules.values():
            k.extract(key_material)

    def select(self, cipher_suite: CipherSuite) -> KeySchedule:
        return self.__schedules[cipher_suite]

    def update_hash(self, data: bytes) -> None:
        for k in self.__schedules.values():
            k.update_hash(data)


CIPHER_SUITES: Dict = {
    CipherSuite.AES_128_GCM_SHA256: hashes.SHA256,
    CipherSuite.AES_256_GCM_SHA384: hashes.SHA384,
    CipherSuite.CHACHA20_POLY1305_SHA256: hashes.SHA256,
}

SIGNATURE_ALGORITHMS: Dict = {
    SignatureAlgorithm.ECDSA_SECP256R1_SHA256: (None, hashes.SHA256),
    SignatureAlgorithm.ECDSA_SECP384R1_SHA384: (None, hashes.SHA384),
    SignatureAlgorithm.ECDSA_SECP521R1_SHA512: (None, hashes.SHA512),
    SignatureAlgorithm.RSA_PKCS1_SHA1: (padding.PKCS1v15, hashes.SHA1),
    SignatureAlgorithm.RSA_PKCS1_SHA256: (padding.PKCS1v15, hashes.SHA256),
    SignatureAlgorithm.RSA_PKCS1_SHA384: (padding.PKCS1v15, hashes.SHA384),
    SignatureAlgorithm.RSA_PKCS1_SHA512: (padding.PKCS1v15, hashes.SHA512),
    SignatureAlgorithm.RSA_PSS_RSAE_SHA256: (padding.PSS, hashes.SHA256),
    SignatureAlgorithm.RSA_PSS_RSAE_SHA384: (padding.PSS, hashes.SHA384),
    SignatureAlgorithm.RSA_PSS_RSAE_SHA512: (padding.PSS, hashes.SHA512),
}

GROUP_TO_CURVE: Dict = {
    Group.SECP256R1: ec.SECP256R1,
    Group.SECP384R1: ec.SECP384R1,
    Group.SECP521R1: ec.SECP521R1,
}
CURVE_TO_GROUP = dict((v, k) for k, v in GROUP_TO_CURVE.items())


def cipher_suite_hash(cipher_suite: CipherSuite) -> hashes.HashAlgorithm:
    return CIPHER_SUITES[cipher_suite]()


def decode_public_key(
    key_share: KeyShareEntry,
) -> Union[ec.EllipticCurvePublicKey, x25519.X25519PublicKey, x448.X448PublicKey, None]:
    if key_share[0] == Group.X25519:
        return x25519.X25519PublicKey.from_public_bytes(key_share[1])
    elif key_share[0] == Group.X448:
        return x448.X448PublicKey.from_public_bytes(key_share[1])
    elif key_share[0] in GROUP_TO_CURVE:
        return ec.EllipticCurvePublicKey.from_encoded_point(
            GROUP_TO_CURVE[key_share[0]](), key_share[1]
        )
    else:
        return None


def encode_public_key(
    public_key: Union[
        ec.EllipticCurvePublicKey, x25519.X25519PublicKey, x448.X448PublicKey
    ],
) -> KeyShareEntry:
    if isinstance(public_key, x25519.X25519PublicKey):
        return (Group.X25519, public_key.public_bytes(Encoding.Raw, PublicFormat.Raw))
    elif isinstance(public_key, x448.X448PublicKey):
        return (Group.X448, public_key.public_bytes(Encoding.Raw, PublicFormat.Raw))
    return (
        CURVE_TO_GROUP[public_key.curve.__class__],
        public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint),
    )


def negotiate(
    supported: List[T], offered: Optional[List[Any]], exc: Optional[Alert] = None
) -> T:
    if offered is not None:
        for c in supported:
            if c in offered:
                return c

    if exc is not None:
        raise exc
    return None


def signature_algorithm_params(signature_algorithm: int) -> Tuple:
    if signature_algorithm in (SignatureAlgorithm.ED25519, SignatureAlgorithm.ED448):
        return tuple()

    padding_cls, algorithm_cls = SIGNATURE_ALGORITHMS[signature_algorithm]
    algorithm = algorithm_cls()
    if padding_cls is None:
        return (ec.ECDSA(algorithm),)
    elif padding_cls == padding.PSS:
        padding_obj = padding_cls(
            mgf=padding.MGF1(algorithm), salt_length=algorithm.digest_size
        )
    else:
        padding_obj = padding_cls()
    return padding_obj, algorithm


@contextmanager
def push_message(
    key_schedule: Union[KeySchedule, KeyScheduleProxy], buf: Buffer
) -> Generator:
    hash_start = buf.tell()
    yield
    key_schedule.update_hash(buf.data_slice(hash_start, buf.tell()))


# callback types


@dataclass
class SessionTicket:
    """
    A TLS session ticket for session resumption.
    """

    age_add: int
    cipher_suite: CipherSuite
    not_valid_after: datetime.datetime
    not_valid_before: datetime.datetime
    resumption_secret: bytes
    server_name: str
    ticket: bytes

    max_early_data_size: Optional[int] = None
    other_extensions: List[Tuple[int, bytes]] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        now = utcnow()
        return now >= self.not_valid_before and now <= self.not_valid_after

    @property
    def obfuscated_age(self) -> int:
        age = int((utcnow() - self.not_valid_before).total_seconds() * 1000)
        return (age + self.age_add) % (1 << 32)


AlpnHandler = Callable[[str], None]
SessionTicketFetcher = Callable[[bytes], Optional[SessionTicket]]
SessionTicketHandler = Callable[[SessionTicket], None]


class Context:
    
    def __init__(
        self,
        is_client: bool,
        alpn_protocols: Optional[List[str]] = None,
        cadata: Optional[bytes] = None,
        cafile: Optional[str] = None,
        capath: Optional[str] = None,
        cipher_suites: Optional[List[CipherSuite]] = None,
        logger: Optional[Union[logging.Logger, logging.LoggerAdapter]] = None,
        max_early_data: Optional[int] = None,
        server_name: Optional[str] = None,
        verify_mode: Optional[int] = None,
    ):
        # configuration
        self._alpn_protocols = alpn_protocols
        self._cadata = cadata
        self._cafile = cafile
        self._capath = capath
        self.certificate: Optional[x509.Certificate] = None
        self.certificate_chain: List[x509.Certificate] = []
        self.certificate_private_key: Optional[
            Union[dsa.DSAPrivateKey, ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey]
        ] = None
        self.handshake_extensions: List[Extension] = []
        self._is_client = is_client
        self._max_early_data = max_early_data
        self.session_ticket: Optional[SessionTicket] = None
        self._request_client_certificate = False  # For test purposes only
        self._server_name = server_name
        if verify_mode is not None:
            self._verify_mode = verify_mode
        else:
            self._verify_mode = ssl.CERT_REQUIRED if is_client else ssl.CERT_NONE

        # callbacks
        self.alpn_cb: Optional[AlpnHandler] = None
        self.get_session_ticket_cb: Optional[SessionTicketFetcher] = None
        self.new_session_ticket_cb: Optional[SessionTicketHandler] = None
        self.update_traffic_key_cb: Callable[
            [Direction, Epoch, CipherSuite, bytes], None
        ] = lambda d, e, c, s: None

        # supported parameters
        if cipher_suites is not None:
            self._cipher_suites = cipher_suites
        else:
            self._cipher_suites = [
                CipherSuite.AES_256_GCM_SHA384,
                CipherSuite.AES_128_GCM_SHA256,
                CipherSuite.CHACHA20_POLY1305_SHA256,
            ]
        self._legacy_compression_methods: List[int] = [CompressionMethod.NULL]
        self._psk_key_exchange_modes: List[int] = [PskKeyExchangeMode.PSK_DHE_KE]
        self._signature_algorithms: List[int] = [
            SignatureAlgorithm.ECDSA_SECP256R1_SHA256,
            SignatureAlgorithm.RSA_PSS_RSAE_SHA256,
            SignatureAlgorithm.RSA_PKCS1_SHA256,
            SignatureAlgorithm.ECDSA_SECP384R1_SHA384,
            SignatureAlgorithm.RSA_PSS_RSAE_SHA384,
            SignatureAlgorithm.RSA_PKCS1_SHA384,
            SignatureAlgorithm.RSA_PKCS1_SHA1,
        ]
        if default_backend().ed25519_supported():
            self._signature_algorithms.append(SignatureAlgorithm.ED25519)
        if default_backend().ed448_supported():
            self._signature_algorithms.append(SignatureAlgorithm.ED448)
        self._supported_groups = [Group.SECP256R1, Group.SECP384R1]
        if default_backend().x25519_supported():
            self._supported_groups.append(Group.X25519)
        if default_backend().x448_supported():
            self._supported_groups.append(Group.X448)
        self._supported_versions = [TLS_VERSION_1_3]

        # state
        self.alpn_negotiated: Optional[str] = None
        self.early_data_accepted = False
        self.key_schedule: Optional[KeySchedule] = None
        self.received_extensions: Optional[List[Extension]] = None
        self._certificate_request: Optional[CertificateRequest] = None
        self._key_schedule_psk: Optional[KeySchedule] = None
        self._key_schedule_proxy: Optional[KeyScheduleProxy] = None
        self._new_session_ticket: Optional[NewSessionTicket] = None
        self._peer_certificate: Optional[x509.Certificate] = None
        self._peer_certificate_chain: List[x509.Certificate] = []
        self._psk_key_exchange_mode: Optional[int] = None
        self._receive_buffer = b""
        self._session_resumed = False
        self._enc_key: Optional[bytes] = None
        self._dec_key: Optional[bytes] = None
        self.__logger = logger

        self._ec_private_keys: List[ec.EllipticCurvePrivateKey] = []
        self._x25519_private_key: Optional[x25519.X25519PrivateKey] = None
        self._x448_private_key: Optional[x448.X448PrivateKey] = None

        if is_client:
            self.client_random = os.urandom(32)
            self.legacy_session_id = b""
            self.state = State.CLIENT_HANDSHAKE_START
        else:
            self.client_random = None
            self.legacy_session_id = None
            self.state = State.SERVER_EXPECT_CLIENT_HELLO

    @property
    def session_resumed(self) -> bool:
        """
        Returns True if session resumption was successfully used.
        """
        return self._session_resumed

    def handle_message(
        self, input_data: bytes, output_buf: Dict[Epoch, Buffer]
    ) -> None:
        if self.state == State.CLIENT_HANDSHAKE_START:
            self._client_send_hello(output_buf[Epoch.INITIAL])
            return

        self._receive_buffer += input_data
        while len(self._receive_buffer) >= 4:
            # determine message length
            message_type = self._receive_buffer[0]
            message_length = 4 + int.from_bytes(
                self._receive_buffer[1:4], byteorder="big"
            )

            # check message is complete
            if len(self._receive_buffer) < message_length:
                break
            message = self._receive_buffer[:message_length]
            self._receive_buffer = self._receive_buffer[message_length:]

            # process the message
            try:
                self._handle_reassembled_message(
                    message_type=message_type,
                    input_buf=Buffer(data=message),
                    output_buf=output_buf,
                )
            except BufferReadError:
                raise AlertDecodeError("Could not parse TLS message")

    def _handle_reassembled_message(
        self, message_type: int, input_buf: Buffer, output_buf: Dict[Epoch, Buffer]
    ) -> None:
        # client states

        if self.state == State.CLIENT_EXPECT_SERVER_HELLO:
            if message_type == HandshakeType.SERVER_HELLO:
                self._client_handle_hello(input_buf, output_buf[Epoch.INITIAL])
            else:
                raise AlertUnexpectedMessage
        elif self.state == State.CLIENT_EXPECT_ENCRYPTED_EXTENSIONS:
            if message_type == HandshakeType.ENCRYPTED_EXTENSIONS:
                self._client_handle_encrypted_extensions(input_buf)
            else:
                raise AlertUnexpectedMessage
        elif self.state == State.CLIENT_EXPECT_CERTIFICATE_REQUEST_OR_CERTIFICATE:
            if message_type == HandshakeType.CERTIFICATE:
                self._client_handle_certificate(input_buf)
            elif message_type == HandshakeType.CERTIFICATE_REQUEST:
                self._client_handle_certificate_request(input_buf)
            else:
                raise AlertUnexpectedMessage
        elif self.state == State.CLIENT_EXPECT_CERTIFICATE:
            if message_type == HandshakeType.CERTIFICATE:
                self._client_handle_certificate(input_buf)
            else:
                raise AlertUnexpectedMessage
        elif self.state == State.CLIENT_EXPECT_CERTIFICATE_VERIFY:
            if message_type == HandshakeType.CERTIFICATE_VERIFY:
                self._client_handle_certificate_verify(input_buf)
            else:
                raise AlertUnexpectedMessage
        elif self.state == State.CLIENT_EXPECT_FINISHED:
            if message_type == HandshakeType.FINISHED:
                self._client_handle_finished(input_buf, output_buf[Epoch.HANDSHAKE])
            else:
                raise AlertUnexpectedMessage
        elif self.state == State.CLIENT_POST_HANDSHAKE:
            if message_type == HandshakeType.NEW_SESSION_TICKET:
                self._client_handle_new_session_ticket(input_buf)
            else:
                raise AlertUnexpectedMessage

        # server states

        elif self.state == State.SERVER_EXPECT_CLIENT_HELLO:
            if message_type == HandshakeType.CLIENT_HELLO:
                self._server_handle_hello(
                    input_buf,
                    output_buf[Epoch.INITIAL],
                    output_buf[Epoch.HANDSHAKE],
                    output_buf[Epoch.ONE_RTT],
                )
            else:
                raise AlertUnexpectedMessage
        elif self.state == State.SERVER_EXPECT_CERTIFICATE:
            if message_type == HandshakeType.CERTIFICATE:
                self._server_handle_certificate(input_buf, output_buf[Epoch.ONE_RTT])
            else:
                raise AlertUnexpectedMessage
        elif self.state == State.SERVER_EXPECT_CERTIFICATE_VERIFY:
            if message_type == HandshakeType.CERTIFICATE_VERIFY:
                self._server_handle_certificate_verify(
                    input_buf, output_buf[Epoch.ONE_RTT]
                )
            else:
                raise AlertUnexpectedMessage
        elif self.state == State.SERVER_EXPECT_FINISHED:
            if message_type == HandshakeType.FINISHED:
                self._server_handle_finished(input_buf, output_buf[Epoch.ONE_RTT])
            else:
                raise AlertUnexpectedMessage
        elif self.state == State.SERVER_POST_HANDSHAKE:
            raise AlertUnexpectedMessage

        # This condition should never be reached, because if the message
        # contains any extra bytes, the `pull_block` inside the message
        # parser will raise `AlertDecodeError`.
        assert input_buf.eof()

    def _build_session_ticket(
        self, new_session_ticket: NewSessionTicket, other_extensions: List[Extension]
    ) -> SessionTicket:
        resumption_master_secret = self.key_schedule.derive_secret(b"res master")
        resumption_secret = hkdf_expand_label(
            algorithm=self.key_schedule.algorithm,
            secret=resumption_master_secret,
            label=b"resumption",
            hash_value=new_session_ticket.ticket_nonce,
            length=self.key_schedule.algorithm.digest_size,
        )

        timestamp = utcnow()
        return SessionTicket(
            age_add=new_session_ticket.ticket_age_add,
            cipher_suite=self.key_schedule.cipher_suite,
            max_early_data_size=new_session_ticket.max_early_data_size,
            not_valid_after=timestamp
            + datetime.timedelta(seconds=new_session_ticket.ticket_lifetime),
            not_valid_before=timestamp,
            other_extensions=other_extensions,
            resumption_secret=resumption_secret,
            server_name=self._server_name,
            ticket=new_session_ticket.ticket,
        )

    def _check_certificate_verify_signature(self, verify: CertificateVerify) -> None:
        if verify.algorithm not in self._signature_algorithms:
            raise AlertDecryptError(
                "CertificateVerify has a signature algorithm we did not advertise"
            )

        try:
            # The type of public_key() is CertificatePublicKeyTypes, but along with
            # ed25519 and ed448, which are fine, this type includes
            # x25519 and x448 which can be public keys but can't sign.  We know
            # we won't get x25519 and x448 as they are not on our list of
            # signature algorithms, so we can cast public key to
            # CertificateIssuerPublicKeyTypes safely and make mypy happy.
            public_key = cast(
                CertificateIssuerPublicKeyTypes, self._peer_certificate.public_key()
            )
            public_key.verify(
                verify.signature,
                self.key_schedule.certificate_verify_data(
                    SERVER_CONTEXT_STRING if self._is_client else CLIENT_CONTEXT_STRING
                ),
                *signature_algorithm_params(verify.algorithm),
            )
        except InvalidSignature:
            raise AlertDecryptError

    def _client_send_hello(self, output_buf: Buffer) -> None:
        key_share: List[KeyShareEntry] = []
        supported_groups: List[int] = []

        for group in self._supported_groups:
            if group == Group.X25519:
                self._x25519_private_key = x25519.X25519PrivateKey.generate()
                key_share.append(
                    encode_public_key(self._x25519_private_key.public_key())
                )
                supported_groups.append(Group.X25519)
            elif group == Group.X448:
                self._x448_private_key = x448.X448PrivateKey.generate()
                key_share.append(encode_public_key(self._x448_private_key.public_key()))
                supported_groups.append(Group.X448)
            elif group == Group.GREASE:
                key_share.append((Group.GREASE, b"\x00"))
                supported_groups.append(Group.GREASE)
            elif group in GROUP_TO_CURVE:
                ec_private_key = ec.generate_private_key(GROUP_TO_CURVE[group]())
                self._ec_private_keys.append(ec_private_key)
                key_share.append(encode_public_key(ec_private_key.public_key()))
                supported_groups.append(group)

        assert len(key_share), "no key share entries"

        # Literal IPv4 and IPv6 addresses are not permitted in
        # Server Name Indication (SNI) hostname.
        try:
            ipaddress.ip_address(self._server_name)
        except ValueError:
            server_name = self._server_name
        else:
            server_name = None

        hello = ClientHello(
            random=self.client_random,
            legacy_session_id=self.legacy_session_id,
            cipher_suites=[int(x) for x in self._cipher_suites],
            legacy_compression_methods=self._legacy_compression_methods,
            alpn_protocols=self._alpn_protocols,
            key_share=key_share,
            psk_key_exchange_modes=(
                self._psk_key_exchange_modes
                if (self.session_ticket or self.new_session_ticket_cb is not None)
                else None
            ),
            server_name=server_name,
            signature_algorithms=self._signature_algorithms,
            supported_groups=supported_groups,
            supported_versions=self._supported_versions,
            other_extensions=self.handshake_extensions,
        )

        # PSK
        if self.session_ticket and self.session_ticket.is_valid:
            self._key_schedule_psk = KeySchedule(self.session_ticket.cipher_suite)
            self._key_schedule_psk.extract(self.session_ticket.resumption_secret)
            binder_key = self._key_schedule_psk.derive_secret(b"res binder")
            binder_length = self._key_schedule_psk.algorithm.digest_size

            # update hello
            if self.session_ticket.max_early_data_size is not None:
                hello.early_data = True
            hello.pre_shared_key = OfferedPsks(
                identities=[
                    (self.session_ticket.ticket, self.session_ticket.obfuscated_age)
                ],
                binders=[bytes(binder_length)],
            )

            # serialize hello without binder
            tmp_buf = Buffer(capacity=1024)
            push_client_hello(tmp_buf, hello)

            # calculate binder
            hash_offset = tmp_buf.tell() - binder_length - 3
            self._key_schedule_psk.update_hash(tmp_buf.data_slice(0, hash_offset))
            binder = self._key_schedule_psk.finished_verify_data(binder_key)
            hello.pre_shared_key.binders[0] = binder
            self._key_schedule_psk.update_hash(
                tmp_buf.data_slice(hash_offset, hash_offset + 3) + binder
            )

            # calculate early data key
            if hello.early_data:
                early_key = self._key_schedule_psk.derive_secret(b"c e traffic")
                self.update_traffic_key_cb(
                    Direction.ENCRYPT,
                    Epoch.ZERO_RTT,
                    self._key_schedule_psk.cipher_suite,
                    early_key,
                )

        self._key_schedule_proxy = KeyScheduleProxy(self._cipher_suites)
        self._key_schedule_proxy.extract(None)

        with push_message(self._key_schedule_proxy, output_buf):
            push_client_hello(output_buf, hello)

        self._set_state(State.CLIENT_EXPECT_SERVER_HELLO)

    def _client_handle_hello(self, input_buf: Buffer, output_buf: Buffer) -> None:
        peer_hello = pull_server_hello(input_buf)

        cipher_suite = negotiate(
            self._cipher_suites,
            [peer_hello.cipher_suite],
            AlertHandshakeFailure("Unsupported cipher suite"),
        )
        if peer_hello.compression_method not in self._legacy_compression_methods:
            raise AlertIllegalParameter(
                "ServerHello has a compression method we did not advertise"
            )
        if peer_hello.supported_version not in self._supported_versions:
            raise AlertIllegalParameter(
                "ServerHello has a version we did not advertise"
            )

        # select key schedule
        if peer_hello.pre_shared_key is not None:
            if (
                self._key_schedule_psk is None
                or peer_hello.pre_shared_key != 0
                or cipher_suite != self._key_schedule_psk.cipher_suite
            ):
                raise AlertIllegalParameter
            self.key_schedule = self._key_schedule_psk
            self._session_resumed = True
        else:
            self.key_schedule = self._key_schedule_proxy.select(cipher_suite)
        self._key_schedule_psk = None
        self._key_schedule_proxy = None

        # perform key exchange
        peer_public_key = decode_public_key(peer_hello.key_share)
        shared_key: Optional[bytes] = None
        if (
            isinstance(peer_public_key, x25519.X25519PublicKey)
            and self._x25519_private_key is not None
        ):
            shared_key = self._x25519_private_key.exchange(peer_public_key)
        elif (
            isinstance(peer_public_key, x448.X448PublicKey)
            and self._x448_private_key is not None
        ):
            shared_key = self._x448_private_key.exchange(peer_public_key)
        elif isinstance(peer_public_key, ec.EllipticCurvePublicKey):
            for ec_private_key in self._ec_private_keys:
                if (
                    ec_private_key.public_key().curve.__class__
                    == peer_public_key.curve.__class__
                ):
                    shared_key = ec_private_key.exchange(ec.ECDH(), peer_public_key)
        assert shared_key is not None

        self.key_schedule.update_hash(input_buf.data)
        self.key_schedule.extract(shared_key)

        self._setup_traffic_protection(
            Direction.DECRYPT, Epoch.HANDSHAKE, b"s hs traffic"
        )

        self._set_state(State.CLIENT_EXPECT_ENCRYPTED_EXTENSIONS)

    def _client_handle_encrypted_extensions(self, input_buf: Buffer) -> None:
        encrypted_extensions = pull_encrypted_extensions(input_buf)

        self.alpn_negotiated = encrypted_extensions.alpn_protocol
        self.early_data_accepted = encrypted_extensions.early_data
        self.received_extensions = encrypted_extensions.other_extensions

        # notify application
        if self.alpn_cb:
            self.alpn_cb(self.alpn_negotiated)

        self._setup_traffic_protection(
            Direction.ENCRYPT, Epoch.HANDSHAKE, b"c hs traffic"
        )
        self.key_schedule.update_hash(input_buf.data)

        # if the server accepted our PSK we are done, other we want its certificate
        if self._session_resumed:
            self._set_state(State.CLIENT_EXPECT_FINISHED)
        else:
            self._set_state(State.CLIENT_EXPECT_CERTIFICATE_REQUEST_OR_CERTIFICATE)

    def _client_handle_certificate_request(self, input_buf: Buffer) -> None:
        self._certificate_request = pull_certificate_request(input_buf)
        self.key_schedule.update_hash(input_buf.data)
        self._set_state(State.CLIENT_EXPECT_CERTIFICATE)

    def _client_handle_certificate(self, input_buf: Buffer) -> None:
        certificate = pull_certificate(input_buf)
        self.key_schedule.update_hash(input_buf.data)

        self._set_peer_certificate(certificate)
        self._set_state(State.CLIENT_EXPECT_CERTIFICATE_VERIFY)

    def _client_handle_certificate_verify(self, input_buf: Buffer) -> None:
        verify = pull_certificate_verify(input_buf)

        # check signature
        self._check_certificate_verify_signature(verify)

        # check certificate
        if self._verify_mode != ssl.CERT_NONE:
            verify_certificate(
                cadata=self._cadata,
                cafile=self._cafile,
                capath=self._capath,
                certificate=self._peer_certificate,
                chain=self._peer_certificate_chain,
                server_name=self._server_name,
            )

        self.key_schedule.update_hash(input_buf.data)
        self._set_state(State.CLIENT_EXPECT_FINISHED)

    def _client_handle_finished(self, input_buf: Buffer, output_buf: Buffer) -> None:
        finished = pull_finished(input_buf)

        # check verify data
        expected_verify_data = self.key_schedule.finished_verify_data(self._dec_key)
        if finished.verify_data != expected_verify_data:
            raise AlertDecryptError
        self.key_schedule.update_hash(input_buf.data)

        # prepare traffic keys
        assert self.key_schedule.generation == 2
        self.key_schedule.extract(None)
        self._setup_traffic_protection(
            Direction.DECRYPT, Epoch.ONE_RTT, b"s ap traffic"
        )
        next_enc_key = self.key_schedule.derive_secret(b"c ap traffic")

        if self._certificate_request is not None:
            # check whether we have a suitable signature algorithm
            if (
                self.certificate is not None
                and self.certificate_private_key is not None
            ):
                signature_algorithm = negotiate(
                    self._signature_algorithms_for_private_key(),
                    self._certificate_request.signature_algorithms,
                )
            else:
                signature_algorithm = None

            # send certificate
            with push_message(self.key_schedule, output_buf):
                push_certificate(
                    output_buf,
                    Certificate(
                        request_context=self._certificate_request.request_context,
                        certificates=(
                            [
                                (x.public_bytes(Encoding.DER), b"")
                                for x in [self.certificate] + self.certificate_chain
                            ]
                            if signature_algorithm
                            else []
                        ),
                    ),
                )

            # send certificate verify
            if signature_algorithm:
                signature = self.certificate_private_key.sign(
                    self.key_schedule.certificate_verify_data(CLIENT_CONTEXT_STRING),
                    *signature_algorithm_params(signature_algorithm),
                )
                with push_message(self.key_schedule, output_buf):
                    push_certificate_verify(
                        output_buf,
                        CertificateVerify(
                            algorithm=signature_algorithm, signature=signature
                        ),
                    )

        # send finished
        with push_message(self.key_schedule, output_buf):
            push_finished(
                output_buf,
                Finished(
                    verify_data=self.key_schedule.finished_verify_data(self._enc_key)
                ),
            )

        # commit traffic key
        self._enc_key = next_enc_key
        self.update_traffic_key_cb(
            Direction.ENCRYPT,
            Epoch.ONE_RTT,
            self.key_schedule.cipher_suite,
            self._enc_key,
        )

        self._set_state(State.CLIENT_POST_HANDSHAKE)

    def _client_handle_new_session_ticket(self, input_buf: Buffer) -> None:
        new_session_ticket = pull_new_session_ticket(input_buf)

        # notify application
        if self.new_session_ticket_cb is not None:
            ticket = self._build_session_ticket(
                new_session_ticket, self.received_extensions
            )
            self.new_session_ticket_cb(ticket)

    def _server_expect_finished(self, onertt_buf: Buffer):
        # anticipate client's FINISHED
        self._expected_verify_data = self.key_schedule.finished_verify_data(
            self._dec_key
        )
        buf = Buffer(capacity=64)
        push_finished(buf, Finished(verify_data=self._expected_verify_data))
        self.key_schedule.update_hash(buf.data)

        # create a new session ticket
        if (
            self.new_session_ticket_cb is not None
            and self._psk_key_exchange_mode is not None
        ):
            self._new_session_ticket = NewSessionTicket(
                ticket_lifetime=86400,
                ticket_age_add=struct.unpack("I", os.urandom(4))[0],
                ticket_nonce=b"",
                ticket=os.urandom(64),
                max_early_data_size=self._max_early_data,
            )

            # send message
            push_new_session_ticket(onertt_buf, self._new_session_ticket)

            # notify application
            ticket = self._build_session_ticket(
                self._new_session_ticket, self.handshake_extensions
            )
            self.new_session_ticket_cb(ticket)

        self._set_state(State.SERVER_EXPECT_FINISHED)

    def _server_handle_hello(
        self,
        input_buf: Buffer,
        initial_buf: Buffer,
        handshake_buf: Buffer,
        onertt_buf: Buffer,
    ) -> None:
        peer_hello = pull_client_hello(input_buf)

        # negotiate parameters
        cipher_suite = negotiate(
            self._cipher_suites,
            peer_hello.cipher_suites,
            AlertHandshakeFailure("No supported cipher suite"),
        )
        compression_method = negotiate(
            self._legacy_compression_methods,
            peer_hello.legacy_compression_methods,
            AlertHandshakeFailure("No supported compression method"),
        )
        psk_key_exchange_mode = negotiate(
            self._psk_key_exchange_modes, peer_hello.psk_key_exchange_modes
        )
        signature_algorithm = negotiate(
            self._signature_algorithms_for_private_key(),
            peer_hello.signature_algorithms,
            AlertHandshakeFailure("No supported signature algorithm"),
        )
        supported_version = negotiate(
            self._supported_versions,
            peer_hello.supported_versions,
            AlertProtocolVersion("No supported protocol version"),
        )

        # negotiate ALPN
        if self._alpn_protocols is not None:
            self.alpn_negotiated = negotiate(
                self._alpn_protocols,
                peer_hello.alpn_protocols,
                AlertHandshakeFailure("No common ALPN protocols"),
            )

        self.client_random = peer_hello.random
        self.server_random = os.urandom(32)
        self.legacy_session_id = peer_hello.legacy_session_id
        self.received_extensions = peer_hello.other_extensions

        # notify application
        if self.alpn_cb:
            self.alpn_cb(self.alpn_negotiated)

        # select key schedule
        pre_shared_key = None
        if (
            self.get_session_ticket_cb is not None
            and psk_key_exchange_mode is not None
            and peer_hello.pre_shared_key is not None
            and len(peer_hello.pre_shared_key.identities) == 1
            and len(peer_hello.pre_shared_key.binders) == 1
        ):
            # ask application to find session ticket
            identity = peer_hello.pre_shared_key.identities[0]
            session_ticket = self.get_session_ticket_cb(identity[0])

            # validate session ticket
            if (
                session_ticket is not None
                and session_ticket.is_valid
                and session_ticket.cipher_suite == cipher_suite
            ):
                self.key_schedule = KeySchedule(cipher_suite)
                self.key_schedule.extract(session_ticket.resumption_secret)

                binder_key = self.key_schedule.derive_secret(b"res binder")
                binder_length = self.key_schedule.algorithm.digest_size

                hash_offset = input_buf.tell() - binder_length - 3
                binder = input_buf.data_slice(
                    hash_offset + 3, hash_offset + 3 + binder_length
                )

                self.key_schedule.update_hash(input_buf.data_slice(0, hash_offset))
                expected_binder = self.key_schedule.finished_verify_data(binder_key)

                if binder != expected_binder:
                    raise AlertHandshakeFailure("PSK validation failed")

                self.key_schedule.update_hash(
                    input_buf.data_slice(hash_offset, hash_offset + 3 + binder_length)
                )
                self._session_resumed = True

                # calculate early data key
                if peer_hello.early_data:
                    early_key = self.key_schedule.derive_secret(b"c e traffic")
                    self.early_data_accepted = True
                    self.update_traffic_key_cb(
                        Direction.DECRYPT,
                        Epoch.ZERO_RTT,
                        self.key_schedule.cipher_suite,
                        early_key,
                    )

                pre_shared_key = 0

        # if PSK is not used, initialize key schedule
        if pre_shared_key is None:
            self.key_schedule = KeySchedule(cipher_suite)
            self.key_schedule.extract(None)
            self.key_schedule.update_hash(input_buf.data)

        # perform key exchange
        public_key: Union[
            ec.EllipticCurvePublicKey, x25519.X25519PublicKey, x448.X448PublicKey
        ]
        shared_key: Optional[bytes] = None
        for key_share in peer_hello.key_share:
            peer_public_key = decode_public_key(key_share)
            if isinstance(peer_public_key, x25519.X25519PublicKey):
                self._x25519_private_key = x25519.X25519PrivateKey.generate()
                public_key = self._x25519_private_key.public_key()
                shared_key = self._x25519_private_key.exchange(peer_public_key)
                break
            elif isinstance(peer_public_key, x448.X448PublicKey):
                self._x448_private_key = x448.X448PrivateKey.generate()
                public_key = self._x448_private_key.public_key()
                shared_key = self._x448_private_key.exchange(peer_public_key)
                break
            elif isinstance(peer_public_key, ec.EllipticCurvePublicKey):
                ec_private_key = ec.generate_private_key(GROUP_TO_CURVE[key_share[0]]())
                self._ec_private_keys.append(ec_private_key)
                public_key = ec_private_key.public_key()
                shared_key = ec_private_key.exchange(ec.ECDH(), peer_public_key)
                break
        assert shared_key is not None

        # send hello
        hello = ServerHello(
            random=self.server_random,
            legacy_session_id=self.legacy_session_id,
            cipher_suite=cipher_suite,
            compression_method=compression_method,
            key_share=encode_public_key(public_key),
            pre_shared_key=pre_shared_key,
            supported_version=supported_version,
        )
        with push_message(self.key_schedule, initial_buf):
            push_server_hello(initial_buf, hello)
        self.key_schedule.extract(shared_key)

        self._setup_traffic_protection(
            Direction.ENCRYPT, Epoch.HANDSHAKE, b"s hs traffic"
        )
        self._setup_traffic_protection(
            Direction.DECRYPT, Epoch.HANDSHAKE, b"c hs traffic"
        )

        # send encrypted extensions
        with push_message(self.key_schedule, handshake_buf):
            push_encrypted_extensions(
                handshake_buf,
                EncryptedExtensions(
                    alpn_protocol=self.alpn_negotiated,
                    early_data=self.early_data_accepted,
                    other_extensions=self.handshake_extensions,
                ),
            )

        if pre_shared_key is None:
            # send certificate request
            if self._request_client_certificate:
                with push_message(self.key_schedule, handshake_buf):
                    push_certificate_request(
                        handshake_buf,
                        CertificateRequest(
                            request_context=b"",
                            signature_algorithms=self._signature_algorithms,
                        ),
                    )

            # send certificate
            with push_message(self.key_schedule, handshake_buf):
                push_certificate(
                    handshake_buf,
                    Certificate(
                        request_context=b"",
                        certificates=[
                            (x.public_bytes(Encoding.DER), b"")
                            for x in [self.certificate] + self.certificate_chain
                        ],
                    ),
                )

            # send certificate verify
            signature = self.certificate_private_key.sign(
                self.key_schedule.certificate_verify_data(SERVER_CONTEXT_STRING),
                *signature_algorithm_params(signature_algorithm),
            )
            with push_message(self.key_schedule, handshake_buf):
                push_certificate_verify(
                    handshake_buf,
                    CertificateVerify(
                        algorithm=signature_algorithm, signature=signature
                    ),
                )

        # send finished
        with push_message(self.key_schedule, handshake_buf):
            push_finished(
                handshake_buf,
                Finished(
                    verify_data=self.key_schedule.finished_verify_data(self._enc_key)
                ),
            )

        # prepare traffic keys
        assert self.key_schedule.generation == 2
        self.key_schedule.extract(None)
        self._setup_traffic_protection(
            Direction.ENCRYPT, Epoch.ONE_RTT, b"s ap traffic"
        )
        self._next_dec_key = self.key_schedule.derive_secret(b"c ap traffic")

        self._psk_key_exchange_mode = psk_key_exchange_mode
        if self._request_client_certificate:
            self._set_state(State.SERVER_EXPECT_CERTIFICATE)
        else:
            self._server_expect_finished(onertt_buf)

    def _server_handle_certificate(self, input_buf: Buffer, output_buf: Buffer) -> None:
        certificate = pull_certificate(input_buf)
        self.key_schedule.update_hash(input_buf.data)

        if certificate.certificates:
            self._set_peer_certificate(certificate)
            self._set_state(State.SERVER_EXPECT_CERTIFICATE_VERIFY)
        else:
            self._server_expect_finished(output_buf)

    def _server_handle_certificate_verify(
        self, input_buf: Buffer, output_buf: Buffer
    ) -> None:
        verify = pull_certificate_verify(input_buf)

        # check signature
        self._check_certificate_verify_signature(verify)

        self.key_schedule.update_hash(input_buf.data)
        self._server_expect_finished(output_buf)

    def _server_handle_finished(self, input_buf: Buffer, output_buf: Buffer) -> None:
        finished = pull_finished(input_buf)

        # check verify data
        if finished.verify_data != self._expected_verify_data:
            raise AlertDecryptError

        # commit traffic key
        self._dec_key = self._next_dec_key
        self._next_dec_key = None
        self.update_traffic_key_cb(
            Direction.DECRYPT,
            Epoch.ONE_RTT,
            self.key_schedule.cipher_suite,
            self._dec_key,
        )

        self._set_state(State.SERVER_POST_HANDSHAKE)

    def _setup_traffic_protection(
        self, direction: Direction, epoch: Epoch, label: bytes
    ) -> None:
        key = self.key_schedule.derive_secret(label)

        if direction == Direction.ENCRYPT:
            self._enc_key = key
        else:
            self._dec_key = key

        self.update_traffic_key_cb(
            direction, epoch, self.key_schedule.cipher_suite, key
        )

    def _set_peer_certificate(self, certificate: Certificate) -> None:
        self._peer_certificate = x509.load_der_x509_certificate(
            certificate.certificates[0][0]
        )
        self._peer_certificate_chain = [
            x509.load_der_x509_certificate(certificate.certificates[i][0])
            for i in range(1, len(certificate.certificates))
        ]

    def _set_state(self, state: State) -> None:
        if self.__logger:
            self.__logger.debug("TLS %s -> %s", self.state, state)
        self.state = state

    def _signature_algorithms_for_private_key(self) -> List[SignatureAlgorithm]:
        signature_algorithms: List[SignatureAlgorithm] = []
        if isinstance(self.certificate_private_key, rsa.RSAPrivateKey):
            signature_algorithms = [
                SignatureAlgorithm.RSA_PSS_RSAE_SHA256,
                SignatureAlgorithm.RSA_PKCS1_SHA256,
                SignatureAlgorithm.RSA_PSS_RSAE_SHA384,
                SignatureAlgorithm.RSA_PKCS1_SHA384,
                SignatureAlgorithm.RSA_PKCS1_SHA1,
            ]
        elif isinstance(
            self.certificate_private_key, ec.EllipticCurvePrivateKey
        ) and isinstance(self.certificate_private_key.curve, ec.SECP256R1):
            signature_algorithms = [SignatureAlgorithm.ECDSA_SECP256R1_SHA256]
        elif isinstance(
            self.certificate_private_key, ec.EllipticCurvePrivateKey
        ) and isinstance(self.certificate_private_key.curve, ec.SECP384R1):
            signature_algorithms = [SignatureAlgorithm.ECDSA_SECP384R1_SHA384]
        elif isinstance(self.certificate_private_key, ed25519.Ed25519PrivateKey):
            signature_algorithms = [SignatureAlgorithm.ED25519]
        elif isinstance(self.certificate_private_key, ed448.Ed448PrivateKey):
            signature_algorithms = [SignatureAlgorithm.ED448]
        return signature_algorithms


    