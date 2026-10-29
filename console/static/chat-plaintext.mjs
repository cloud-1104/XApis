// X's plaintext MessageCreateEvent and v7 signature format. No account keys
// or message content leave the worker except in the intended send payload.
const encoder = new TextEncoder();
const concat = (...parts) => {
  const result = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; }
  return result;
};
const number = (value, bytes) => {
  const result = new Uint8Array(bytes);
  const view = new DataView(result.buffer);
  if (bytes === 2) view.setInt16(0, value);
  else view.setInt32(0, value);
  return result;
};
const field = (type, id, value) => concat(Uint8Array.of(type), number(id, 2), value);
const binary = bytes => concat(number(bytes.length, 4), bytes);
const string = value => binary(encoder.encode(value));
const struct = (...fields) => concat(...fields, Uint8Array.of(0));
const base64 = bytes => {
  let value = "";
  for (let i = 0; i < bytes.length; i += 32768) value += String.fromCharCode(...bytes.subarray(i, i + 32768));
  return btoa(value);
};

export function plaintextPayload(chat, {conversationId, senderId, keyVersion, text, messageId = crypto.randomUUID()}) {
  if (!/^\d+:\d+$/.test(conversationId) || !/^\d+$/.test(senderId) || !conversationId.split(":").includes(senderId) || !/^\d+$/.test(keyVersion))
    throw new Error("会话或签名信息无效");
  const emptyStructList = concat(Uint8Array.of(12), number(0, 4));
  const message = struct(field(11, 1, string(text)), field(15, 2, emptyStructList),
    field(15, 3, emptyStructList), field(8, 7, number(1, 4)));
  const content = struct(field(12, 1, struct(field(12, 1, message))));
  const create = struct(field(11, 100, binary(content)), field(2, 102, Uint8Array.of(1)),
    field(2, 105, Uint8Array.of(0)), field(8, 106, number(1, 4)));
  const signed = `MessageCreateEvent,${messageId},${senderId},${conversationId},null,${base64(content).replace(/=+$/, "")}`;
  const signature = base64(chat.sign(encoder.encode(signed))).replace(/=+$/, "");
  const signer = struct(field(11, 1, string(senderId)), field(11, 2, string(keyVersion)));
  const signerList = concat(Uint8Array.of(12), number(1, 4), signer);
  const signatureEvent = struct(field(11, 1, string(signature)), field(11, 2, string(keyVersion)),
    field(11, 3, string("7")), field(15, 5, signerList));
  return {messageId, encodedMessageCreateEvent:base64(create), encodedMessageEventSignature:base64(signatureEvent)};
}
