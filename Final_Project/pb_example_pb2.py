# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: pb-example.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='pb-example.proto',
  package='',
  syntax='proto3',
  serialized_pb=_b('\n\x10pb-example.proto\"\xc8\x02\n\x07Request\x12\x0f\n\x07version\x18\x01 \x01(\x05\x12\x0c\n\x04seqn\x18\x02 \x01(\x05\x12\x1b\n\x04type\x18\x03 \x01(\x0e\x32\r.Request.Type\x12\x0f\n\x07payload\x18\x04 \x01(\t\x12\x10\n\x08username\x18\x05 \x01(\t\x12\x10\n\x08nonce_r1\x18\x06 \x01(\t\x12\x10\n\x08nonce_r2\x18\x07 \x01(\t\x12\x0c\n\x04hash\x18\x08 \x01(\t\x12\x12\n\nsecret_key\x18\t \x01(\t\x12\x14\n\x0ctalk_to_user\x18\n \x01(\t\x12\x0c\n\x04port\x18\x0b \x01(\t\x12\n\n\x02ip\x18\x0c \x01(\t\"h\n\x04Type\x12\x08\n\x04SIGN\x10\x00\x12\x08\n\x04LIST\x10\x01\x12\x08\n\x04SEND\x10\x03\x12\n\n\x06LOGOUT\x10\x04\x12\x08\n\x04TALK\x10\x05\x12\t\n\x05POF_1\x10\x06\x12\t\n\x05POF_2\x10\x07\x12\n\n\x06SEND_1\x10\x08\x12\n\n\x06SEND_2\x10\t\"\xab\x04\n\x05Reply\x12\x0f\n\x07version\x18\x01 \x01(\x05\x12\x0c\n\x04seqn\x18\x02 \x01(\x05\x12\x19\n\x04type\x18\x03 \x01(\x0e\x32\x0b.Reply.Type\x12\x0f\n\x07payload\x18\x04 \x01(\t\x12\x10\n\x08nonce_r1\x18\x05 \x01(\t\x12\x10\n\x08nonce_r2\x18\x06 \x01(\t\x12\x0c\n\x04hash\x18\x07 \x01(\t\x12\x12\n\nsecret_key\x18\x08 \x01(\t\x12\x17\n\x0fsign_in_success\x18\t \x01(\x08\x12\x10\n\x08key_salt\x18\n \x01(\t\x12\x16\n\x0elogout_success\x18\x0b \x01(\x08\x12\x15\n\rpublic_key_u1\x18\x0c \x01(\t\x12\x15\n\rpublic_key_u2\x18\r \x01(\t\x12\x10\n\x08username\x18\x0e \x01(\t\x12\x13\n\x0bpof_success\x18\x0f \x01(\x08\x12\n\n\x02ip\x18\x10 \x01(\t\x12\x0c\n\x04port\x18\x11 \x01(\t\x12\x10\n\x08udp_port\x18\x12 \x01(\x05\x12\x14\n\x0c\x64h_component\x18\x13 \x01(\t\x12\x17\n\x0fticket_username\x18\x14 \x01(\t\x12\x11\n\tsignature\x18\x15 \x01(\t\x12\x11\n\tdh_object\x18\x16 \x01(\t\x12\x0f\n\x07message\x18\x17 \x01(\t\"g\n\x04Type\x12\x08\n\x04SIGN\x10\x00\x12\x08\n\x04LIST\x10\x01\x12\x08\n\x04SEND\x10\x03\x12\n\n\x06LOGOUT\x10\x04\x12\x08\n\x04TALK\x10\x05\x12\x07\n\x03POF\x10\x06\x12\n\n\x06SEND_1\x10\x07\x12\n\n\x06SEND_2\x10\x08\x12\n\n\x06SEND_3\x10\tb\x06proto3')
)



_REQUEST_TYPE = _descriptor.EnumDescriptor(
  name='Type',
  full_name='Request.Type',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='SIGN', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='LIST', index=1, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SEND', index=2, number=3,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='LOGOUT', index=3, number=4,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='TALK', index=4, number=5,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='POF_1', index=5, number=6,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='POF_2', index=6, number=7,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SEND_1', index=7, number=8,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SEND_2', index=8, number=9,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=245,
  serialized_end=349,
)
_sym_db.RegisterEnumDescriptor(_REQUEST_TYPE)

_REPLY_TYPE = _descriptor.EnumDescriptor(
  name='Type',
  full_name='Reply.Type',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='SIGN', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='LIST', index=1, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SEND', index=2, number=3,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='LOGOUT', index=3, number=4,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='TALK', index=4, number=5,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='POF', index=5, number=6,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SEND_1', index=6, number=7,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SEND_2', index=7, number=8,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SEND_3', index=8, number=9,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=804,
  serialized_end=907,
)
_sym_db.RegisterEnumDescriptor(_REPLY_TYPE)


_REQUEST = _descriptor.Descriptor(
  name='Request',
  full_name='Request',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='version', full_name='Request.version', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='seqn', full_name='Request.seqn', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='type', full_name='Request.type', index=2,
      number=3, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='payload', full_name='Request.payload', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='username', full_name='Request.username', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='nonce_r1', full_name='Request.nonce_r1', index=5,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='nonce_r2', full_name='Request.nonce_r2', index=6,
      number=7, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='hash', full_name='Request.hash', index=7,
      number=8, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='secret_key', full_name='Request.secret_key', index=8,
      number=9, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='talk_to_user', full_name='Request.talk_to_user', index=9,
      number=10, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='port', full_name='Request.port', index=10,
      number=11, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='ip', full_name='Request.ip', index=11,
      number=12, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _REQUEST_TYPE,
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=21,
  serialized_end=349,
)


_REPLY = _descriptor.Descriptor(
  name='Reply',
  full_name='Reply',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='version', full_name='Reply.version', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='seqn', full_name='Reply.seqn', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='type', full_name='Reply.type', index=2,
      number=3, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='payload', full_name='Reply.payload', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='nonce_r1', full_name='Reply.nonce_r1', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='nonce_r2', full_name='Reply.nonce_r2', index=5,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='hash', full_name='Reply.hash', index=6,
      number=7, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='secret_key', full_name='Reply.secret_key', index=7,
      number=8, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='sign_in_success', full_name='Reply.sign_in_success', index=8,
      number=9, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='key_salt', full_name='Reply.key_salt', index=9,
      number=10, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='logout_success', full_name='Reply.logout_success', index=10,
      number=11, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='public_key_u1', full_name='Reply.public_key_u1', index=11,
      number=12, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='public_key_u2', full_name='Reply.public_key_u2', index=12,
      number=13, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='username', full_name='Reply.username', index=13,
      number=14, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='pof_success', full_name='Reply.pof_success', index=14,
      number=15, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='ip', full_name='Reply.ip', index=15,
      number=16, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='port', full_name='Reply.port', index=16,
      number=17, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='udp_port', full_name='Reply.udp_port', index=17,
      number=18, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='dh_component', full_name='Reply.dh_component', index=18,
      number=19, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='ticket_username', full_name='Reply.ticket_username', index=19,
      number=20, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='signature', full_name='Reply.signature', index=20,
      number=21, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='dh_object', full_name='Reply.dh_object', index=21,
      number=22, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='message', full_name='Reply.message', index=22,
      number=23, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _REPLY_TYPE,
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=352,
  serialized_end=907,
)

_REQUEST.fields_by_name['type'].enum_type = _REQUEST_TYPE
_REQUEST_TYPE.containing_type = _REQUEST
_REPLY.fields_by_name['type'].enum_type = _REPLY_TYPE
_REPLY_TYPE.containing_type = _REPLY
DESCRIPTOR.message_types_by_name['Request'] = _REQUEST
DESCRIPTOR.message_types_by_name['Reply'] = _REPLY
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Request = _reflection.GeneratedProtocolMessageType('Request', (_message.Message,), dict(
  DESCRIPTOR = _REQUEST,
  __module__ = 'pb_example_pb2'
  # @@protoc_insertion_point(class_scope:Request)
  ))
_sym_db.RegisterMessage(Request)

Reply = _reflection.GeneratedProtocolMessageType('Reply', (_message.Message,), dict(
  DESCRIPTOR = _REPLY,
  __module__ = 'pb_example_pb2'
  # @@protoc_insertion_point(class_scope:Reply)
  ))
_sym_db.RegisterMessage(Reply)


# @@protoc_insertion_point(module_scope)