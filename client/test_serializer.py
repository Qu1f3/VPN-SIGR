from protocol.serializer import *


seq = 10
number = 2

result = encode_sequence_number(number)

print(result)
print(len(result))

# seq_bytes = serialize_sequence_number(seq)

# print(seq_bytes)
# print(len(seq_bytes))


# nonce = generate_nonce(seq)

# print(nonce)
# print(len(nonce))