// Pure adapters: private keys and plaintext never enter web API payloads.
export function sendPayload(conversationId, payload) {
  return {conversation_id: conversationId, message_id: payload.messageId,
    encoded_message_create_event: payload.encodedMessageCreateEvent,
    encoded_message_event_signature: payload.encodedMessageEventSignature};
}
export function keyPayload(prepared) {
  return {conversation_id: prepared.conversationId,
    conversation_key_version: prepared.conversationKeyVersion,
    conversation_participant_keys: prepared.conversationParticipantKeys.map(k => ({user_id:k.userId,
      public_key_version:k.publicKeyVersion, encrypted_conversation_key:k.encryptedConversationKey})),
    action_signatures: prepared.actionSignatures.map(s => ({message_id:s.messageId,
      encoded_message_event_detail:s.encodedMessageEventDetail,
      message_event_signature:{public_key_version:s.messageEventSignature.publicKeyVersion,
        signature_version:s.messageEventSignature.signatureVersion,signature:s.messageEventSignature.signature,
        signing_public_key:s.messageEventSignature.signingPublicKey}}))};
}

// Some X conversations contain plaintext events without a verifiable signature.
// Show only those messages as unverified; never import their keys or trust them
// when preparing an encrypted send.
export function decryptForDisplay(chat, events) {
  const decoded = chat.decryptEvents({events});
  const errors = {...decoded.errors};
  const messages = [...decoded.messages];
  chat.setRejectUnverified(false);
  try {
    for (const index of Object.keys(errors)) {
      try {
        const event = chat.decryptEvent({eventB64:events[Number(index)]});
        if (event.type === "message" && event.verified === false && !event.conversationKeyVersion) {
          messages.push({originalB64:events[Number(index)], event});
          delete errors[index];
        }
      } catch { /* Keep the original validation error. */ }
    }
  } finally { chat.setRejectUnverified(true); }
  return {...decoded, messages, errors};
}
export function messageView(decoded, pageEvents = null) {
  const events = decoded.messages.map(m => m.event);
  const pageSet = pageEvents ? new Set(pageEvents) : null;
  const cursorEvents = pageSet ? decoded.messages.filter(m => pageSet.has(m.originalB64)).map(m => m.event) : events;
  const minimum = values => values.filter(v => /^\d+$/.test(v || "")).reduce((a,b) => !a || BigInt(b)<BigInt(a) ? b : a,null);
  return {messages:events.filter(e => e.type === "message" && e.content?.contentType !== "reaction" && e.content?.contentType !== "reactionRemoved").map(e => ({
    id:e.id || e.sequenceId, sequence:e.sequenceId, sender_id:e.senderId,
    text:e.content?.text || e.content?.newText || "[附件或其他消息类型]",
    created:e.createdAtMsec ? e.createdAtMsec/1000 : null, verified:e.verified,
    encrypted:!!e.conversationKeyVersion,
  })), before:minimum(cursorEvents.map(e => e.sequenceId)), key_before:minimum(events.filter(e => e.type === "keyChange").map(e => e.conversationKeyVersion)),
    encrypted_ready:events.some(e => (e.type === "keyChange" || (e.type === "message" && e.conversationKeyVersion)) && e.verified === true),
    failed_count:Object.keys(decoded.errors || {}).length};
}
