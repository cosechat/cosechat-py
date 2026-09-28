"""
Propagation nodes (like LXMF's): hold messages for peers that are offline,
and hand them over when those peers ask.

A propagation node says so in its announce (field 7, services bit 1). Both
depositing and fetching happen over a link to it, so the propagation node
knows exactly who is fetching (the link authenticated them) and only ever
holds ciphertext it cannot read.

Link body fields used:

  15  deposit  [recipient address, packet type, payload]   with 6: deposit receipt secret
  12  fetch    true                                         "give me what you hold for me"
  13  item     [index, packet type, payload]
  14  end      count                                         the batch had this many items
  16  ack      count                                         "got them all": the batch can go

A deposit is confirmed like a message: the propagation node sends a RECEIPT
with receipt_tag(secret, its own address). The secret is separate from the
message's, so the propagation node cannot fake the recipient's receipt.
"""

SERVICE_PROPAGATION = 1

P_FETCH = 12
P_ITEM = 13
P_END = 14
P_DEPOSIT = 15
P_ACK = 16

FIELDS = {P_FETCH, P_ITEM, P_END, P_DEPOSIT, P_ACK}
BATCH = 64  # items handed over per fetch
