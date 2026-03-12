/**
 * ChatScreen — Main messaging interface for Tenebra Web.
 *
 * Layout (Tailwind, dark theme):
 *   ┌──────────────┬───────────────────────────────────┐
 *   │  Sidebar     │  Header (contact name)            │
 *   │  contacts    ├───────────────────────────────────┤
 *   │              │  Messages (scrollable)            │
 *   │              ├───────────────────────────────────┤
 *   │              │  Input bar                        │
 *   └──────────────┴───────────────────────────────────┘
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  ArrowLeft,
  MessageSquarePlus,
  Send,
  UserPlus,
  AlertCircle,
  Wifi,
  WifiOff,
  X,
  Paperclip,
  Download,
  FileIcon,
  Loader2,
  ZoomIn,
  ZoomOut,
  RotateCw,
} from 'lucide-react';
import { db } from '@/db/db';
import type { Contact, DecryptedMessage, AttachmentMeta } from '@/db/db';
import {
  sendMessage,
  processIncomingMessage,
  fetchAndProcessOfflineMessages,
  loadMessages,
  resolveUsername,
  resolveUserId,
} from '@/services/MessagingService';
import {
  generateFileKey,
  encryptFile,
  decryptFile,
  exportKeyToBase64,
  importKeyFromBase64,
  ivToBase64,
  ivFromBase64,
} from '@/services/FileCryptoService';
import { uploadEncryptedFile, downloadEncryptedFile } from '@/services/FileService';
import {
  connectSocket,
  disconnectSocket,
  onNewMessage,
  isConnected,
} from '@/services/SocketService';
import type { IncomingMessagePayload } from '@/services/SocketService';
import { registerForPushNotifications } from '@/services/PushService';

// ─── Props ─────────────────────────────────────────────────────────────────────

interface ChatScreenProps {
  /** Authenticated user info. */
  user: { id: string; username: string };
  /** Derived AES encryption key (in-memory). */
  encryptionKey: CryptoKey;
}

// ─── Component ─────────────────────────────────────────────────────────────────

export default function ChatScreen({ user, encryptionKey }: ChatScreenProps) {
  // ── State ────────────────────────────────────────────────────────────────
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [selectedContact, setSelectedContact] = useState<Contact | null>(null);
  const [messages, setMessages] = useState<DecryptedMessage[]>([]);
  const [inputText, setInputText] = useState('');
  const [sending, setSending] = useState(false);
  const [error, setError] = useState('');
  const [connected, setConnected] = useState(false);

  // New-chat modal
  const [showNewChat, setShowNewChat] = useState(false);
  const [newUsername, setNewUsername] = useState('');
  const [resolving, setResolving] = useState(false);

  // Attachment state
  const [pendingFile, setPendingFile] = useState<File | null>(null);
  /** objectURL cache for decrypted image attachments, keyed by message ID. */
  const [imageUrls, setImageUrls] = useState<Record<string, string>>({});
  const imageUrlsRef = useRef(imageUrls);

  // Lightbox state
  const [lightboxSrc, setLightboxSrc] = useState<string | null>(null);
  const [lightboxScale, setLightboxScale] = useState(1);
  const [lightboxRotation, setLightboxRotation] = useState(0);

  // Drag-and-drop state
  const [dragging, setDragging] = useState(false);
  const dragCounter = useRef(0);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // ── Load contacts ────────────────────────────────────────────────────────
  const refreshContacts = useCallback(async () => {
    const list = await db.contacts.toArray();
    setContacts(list);
  }, []);

  // ── Ensure contact exists ────────────────────────────────────────────────
  const ensureContact = useCallback(
    async (userId: string, username?: string) => {
      const existing = await db.contacts.get(userId);
      if (existing) return existing;

      // Resolve username from backend if not provided
      let resolvedName = username;
      if (!resolvedName) {
        try {
          const resolved = await resolveUserId(userId);
          resolvedName = resolved.username;
        } catch {
          resolvedName = userId.slice(0, 8); // fallback
        }
      }

      const contact: Contact = { userId, username: resolvedName };
      await db.contacts.put(contact);
      await refreshContacts();
      return contact;
    },
    [refreshContacts]
  );

  // ── Handle incoming message ──────────────────────────────────────────────
  const handleIncoming = useCallback(
    async (payload: IncomingMessagePayload) => {
      try {
        const msg = await processIncomingMessage(
          payload.senderId,
          payload.ciphertext,
          payload.type,
          new Date(payload.timestamp).getTime(),
          encryptionKey
        );

        // Ensure contact exists (resolve username by userId from API)
        let contact = await db.contacts.get(payload.senderId);
        if (!contact) {
          try {
            const resolved = await resolveUserId(payload.senderId);
            contact = {
              userId: payload.senderId,
              username: resolved.username,
            };
          } catch {
            contact = {
              userId: payload.senderId,
              username: payload.senderId.slice(0, 8),
            };
          }
          await db.contacts.put(contact);
          await refreshContacts();
        }

        // If the currently selected contact matches, update the message list
        if (selectedContact?.userId === payload.senderId) {
          setMessages((prev) => [...prev, msg]);
        }
      } catch (err) {
        console.error('[Chat] Failed to process incoming message:', err);
      }
    },
    [encryptionKey, refreshContacts, selectedContact]
  );

  // ── Socket lifecycle ─────────────────────────────────────────────────────
  useEffect(() => {
    const sock = connectSocket();

    const updateStatus = () => setConnected(isConnected());
    sock.on('connect', updateStatus);
    sock.on('disconnect', updateStatus);
    updateStatus();

    return () => {
      sock.off('connect', updateStatus);
      sock.off('disconnect', updateStatus);
      disconnectSocket();
    };
  }, []);

  useEffect(() => {
    const unsub = onNewMessage(handleIncoming);
    return unsub;
  }, [handleIncoming]);

  // ── Fetch offline messages on mount ──────────────────────────────────────
  useEffect(() => {
    // Register for push notifications (non-blocking, best-effort)
    registerForPushNotifications();
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const msgs = await fetchAndProcessOfflineMessages(encryptionKey);

        // Ensure contacts exist for all senders
        const senderIds = [...new Set(msgs.map((m) => m.contactId))];
        for (const sid of senderIds) {
          await ensureContact(sid);
        }

        await refreshContacts();

        // Update current conversation if applicable
        if (selectedContact) {
          const updated = await loadMessages(selectedContact.userId, encryptionKey);
          setMessages(updated);
        }
      } catch (err) {
        console.error('[Chat] Failed to fetch offline messages:', err);
      }
    })();
    // Only run once on mount
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Load contacts on mount ───────────────────────────────────────────────
  useEffect(() => {
    refreshContacts();
  }, [refreshContacts]);

  // ── Load messages when contact changes ───────────────────────────────────
  useEffect(() => {
    if (!selectedContact) {
      setMessages([]);
      return;
    }
    loadMessages(selectedContact.userId, encryptionKey).then(setMessages);
  }, [selectedContact, encryptionKey]);

  // ── Auto-scroll to bottom ────────────────────────────────────────────────
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // ── Send a message ───────────────────────────────────────────────────────
  const handleSend = useCallback(async () => {
    if (!selectedContact || sending) return;
    // Must have text or a pending file
    if (!inputText.trim() && !pendingFile) return;
    setError('');
    setSending(true);
    try {
      let attachment: AttachmentMeta | undefined;

      // Encrypt & upload the pending file if any
      if (pendingFile) {
        const fileKey = await generateFileKey();
        const { encrypted, iv } = await encryptFile(pendingFile, fileKey);
        const encryptedBlob = new Blob([encrypted], { type: 'application/octet-stream' });
        const { objectName } = await uploadEncryptedFile(encryptedBlob, pendingFile.name);

        attachment = {
          url: objectName,
          keyBase64: await exportKeyToBase64(fileKey),
          ivBase64: ivToBase64(iv),
          mimeType: pendingFile.type || 'application/octet-stream',
          name: pendingFile.name,
        };
      }

      const msg = await sendMessage(
        selectedContact.userId,
        inputText.trim() || (pendingFile ? `\ud83d\udcce ${pendingFile.name}` : ''),
        encryptionKey,
        attachment
      );
      setMessages((prev) => [...prev, msg]);
      setInputText('');
      setPendingFile(null);
      if (fileInputRef.current) fileInputRef.current.value = '';
      inputRef.current?.focus();
    } catch (err) {
      console.error('[Chat] Send failed:', err);
      setError(err instanceof Error ? err.message : 'Failed to send message.');
    } finally {
      setSending(false);
    }
  }, [selectedContact, inputText, sending, encryptionKey, pendingFile]);

  // ── Decrypt & render image attachments ──────────────────────────────────
  const decryptAndCacheImage = useCallback(
    async (msgId: string, att: AttachmentMeta) => {
      if (imageUrls[msgId]) return; // already cached
      try {
        const blob = await downloadEncryptedFile(att.url);
        const key = await importKeyFromBase64(att.keyBase64);
        const iv = ivFromBase64(att.ivBase64);
        const decryptedBlob = await decryptFile(blob, key, iv);
        const objectUrl = URL.createObjectURL(new Blob([decryptedBlob], { type: att.mimeType }));
        setImageUrls((prev) => ({ ...prev, [msgId]: objectUrl }));
      } catch (err) {
        console.error(`[Chat] Failed to decrypt image for message ${msgId}:`, err);
      }
    },
    [imageUrls]
  );

  // Auto-decrypt image attachments when messages change
  useEffect(() => {
    for (const msg of messages) {
      if (msg.attachment?.mimeType.startsWith('image/') && !imageUrls[msg.id]) {
        decryptAndCacheImage(msg.id, msg.attachment);
      }
    }
  }, [messages, imageUrls, decryptAndCacheImage]);

  // Keep the ref in sync so the unmount cleanup revokes the latest URLs
  useEffect(() => {
    imageUrlsRef.current = imageUrls;
  }, [imageUrls]);

  // Revoke object URLs on unmount
  useEffect(() => {
    return () => {
      Object.values(imageUrlsRef.current).forEach((url) => URL.revokeObjectURL(url));
    };
  }, []);

  // ── Download non-image attachment ───────────────────────────────────────
  const handleDownloadAttachment = useCallback(async (att: AttachmentMeta) => {
    try {
      const blob = await downloadEncryptedFile(att.url);
      const key = await importKeyFromBase64(att.keyBase64);
      const iv = ivFromBase64(att.ivBase64);
      const decryptedBlob = await decryptFile(blob, key, iv);

      // Trigger browser download
      const url = URL.createObjectURL(new Blob([decryptedBlob], { type: att.mimeType }));
      const a = document.createElement('a');
      a.href = url;
      a.download = att.name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('[Chat] Failed to download/decrypt attachment:', err);
      setError('Failed to decrypt attachment.');
    }
  }, []);

  // ── Start new chat ───────────────────────────────────────────────────────
  const handleNewChat = useCallback(async () => {
    if (!newUsername.trim() || resolving) return;

    if (newUsername.trim().toLowerCase() === user.username.toLowerCase()) {
      setError('Cannot start a chat with yourself.');
      return;
    }

    setError('');
    setResolving(true);
    try {
      const resolved = await resolveUsername(newUsername.trim());
      const contact = await ensureContact(resolved.id, resolved.username);
      setSelectedContact(contact);
      setShowNewChat(false);
      setNewUsername('');
    } catch {
      setError('User not found. Check the username and try again.');
    } finally {
      setResolving(false);
    }
  }, [newUsername, resolving, user.username, ensureContact]);

  // ── Lightbox helpers ─────────────────────────────────────────────────────
  const openLightbox = useCallback((src: string) => {
    setLightboxSrc(src);
    setLightboxScale(1);
    setLightboxRotation(0);
  }, []);

  const closeLightbox = useCallback(() => {
    setLightboxSrc(null);
  }, []);

  // ── Drag-and-drop handlers ──────────────────────────────────────────────
  const handleDragEnter = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current += 1;
    if (e.dataTransfer.types.includes('Files')) setDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current -= 1;
    if (dragCounter.current <= 0) {
      dragCounter.current = 0;
      setDragging(false);
    }
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current = 0;
    setDragging(false);
    const file = e.dataTransfer.files?.[0] ?? null;
    if (file) {
      setPendingFile(file);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  }, []);

  // ── Render ───────────────────────────────────────────────────────────────
  return (
    <div
      className="flex h-[100dvh] bg-gray-950 text-gray-100"
      onDragEnter={selectedContact ? handleDragEnter : undefined}
      onDragLeave={selectedContact ? handleDragLeave : undefined}
      onDragOver={selectedContact ? handleDragOver : undefined}
      onDrop={selectedContact ? handleDrop : undefined}
    >
      {/* ─── Sidebar ─────────────────────────────────────────────── */}
      <aside
        className={`${selectedContact ? 'hidden md:flex' : 'flex'
          } w-full md:w-72 flex-col border-r border-gray-800 bg-gray-900`}
      >
        {/* Sidebar header */}
        <div className="flex items-center justify-between border-b border-gray-800 px-4 py-3">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold">{user.username}</span>
            {connected ? (
              <Wifi className="h-3.5 w-3.5 text-emerald-400" />
            ) : (
              <WifiOff className="h-3.5 w-3.5 text-red-400" />
            )}
          </div>
          <button
            onClick={() => setShowNewChat(true)}
            className="rounded-md p-1.5 text-gray-400 hover:bg-gray-800 hover:text-gray-200"
            aria-label="New chat"
          >
            <MessageSquarePlus className="h-5 w-5" />
          </button>
        </div>

        {/* Contact list */}
        <div className="flex-1 overflow-y-auto">
          {contacts.length === 0 && (
            <p className="px-4 py-8 text-center text-xs text-gray-500">
              No conversations yet.
              <br />
              Press <MessageSquarePlus className="inline h-3.5 w-3.5" /> to start one.
            </p>
          )}
          {contacts.map((c) => (
            <button
              key={c.userId}
              onClick={() => setSelectedContact(c)}
              className={`flex w-full items-center gap-3 px-4 py-3 text-left transition hover:bg-gray-800/60 ${selectedContact?.userId === c.userId ? 'bg-gray-800/80' : ''
                }`}
            >
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-indigo-500/20 text-sm font-medium text-indigo-300">
                {c.username.charAt(0).toUpperCase()}
              </div>
              <span className="truncate text-sm">{c.username}</span>
            </button>
          ))}
        </div>
      </aside>

      {/* ─── Main panel ──────────────────────────────────────────── */}
      <main
        className={`${selectedContact ? 'flex' : 'hidden md:flex'
          } relative flex-1 flex-col`}
      >
        {/* Header */}
        <header className="flex h-14 items-center gap-2 border-b border-gray-800 px-4 md:px-6">
          {selectedContact && (
            <button
              onClick={() => setSelectedContact(null)}
              className="flex h-8 w-8 items-center justify-center rounded-lg text-gray-400 transition hover:bg-gray-800 hover:text-gray-200 md:hidden"
              aria-label="Back to contacts"
            >
              <ArrowLeft className="h-5 w-5" />
            </button>
          )}
          {selectedContact ? (
            <h2 className="text-sm font-semibold">{selectedContact.username}</h2>
          ) : (
            <h2 className="text-sm text-gray-500">Select a conversation or start a new one</h2>
          )}
        </header>

        {/* Drag overlay */}
        {dragging && selectedContact && (
          <div className="pointer-events-none absolute inset-0 z-40 flex items-center justify-center bg-indigo-600/10 backdrop-blur-sm">
            <div className="flex flex-col items-center gap-2 rounded-2xl border-2 border-dashed border-indigo-400 bg-gray-900/80 px-12 py-10">
              <Paperclip className="h-10 w-10 text-indigo-400" />
              <p className="text-sm font-medium text-indigo-300">Drop file to attach</p>
            </div>
          </div>
        )}

        {/* Messages area */}
        <div className="flex flex-1 flex-col overflow-y-auto px-4 py-4 md:px-6">
          {!selectedContact && (
            <div className="flex flex-1 flex-col items-center justify-center gap-3 text-gray-500">
              <MessageSquarePlus className="h-12 w-12 opacity-30" />
              <p className="text-sm">No conversation selected</p>
            </div>
          )}

          {selectedContact && messages.length === 0 && (
            <div className="flex flex-1 flex-col items-center justify-center gap-2 text-gray-500">
              <p className="text-sm">
                Send your first end-to-end encrypted message to{' '}
                <span className="font-medium text-gray-300">{selectedContact.username}</span>
              </p>
            </div>
          )}

          {messages.map((msg) => (
            <div
              key={msg.id}
              className={`mb-2 flex ${msg.direction === 'out' ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-[85%] rounded-2xl px-4 py-2 text-sm md:max-w-[70%] ${msg.direction === 'out' ? 'bg-indigo-600 text-white' : 'bg-gray-800 text-gray-100'
                  }`}
              >
                {/* Attachment rendering */}
                {msg.attachment && (
                  <div className="mb-1">
                    {msg.attachment.mimeType.startsWith('image/') ? (
                      imageUrls[msg.id] ? (
                        <img
                          src={imageUrls[msg.id]}
                          alt={msg.attachment.name}
                          className="max-h-64 cursor-pointer rounded-lg object-contain transition hover:opacity-90"
                          onClick={() => openLightbox(imageUrls[msg.id])}
                        />
                      ) : (
                        <div className="flex h-32 w-48 items-center justify-center rounded-lg bg-gray-700/50">
                          <Loader2 className="h-5 w-5 animate-spin text-gray-400" />
                        </div>
                      )
                    ) : (
                      <button
                        onClick={() => handleDownloadAttachment(msg.attachment!)}
                        className={`flex items-center gap-2 rounded-lg px-3 py-2 text-xs transition ${msg.direction === 'out'
                          ? 'bg-indigo-500/30 hover:bg-indigo-500/50'
                          : 'bg-gray-700/50 hover:bg-gray-700/80'
                          }`}
                      >
                        <FileIcon className="h-4 w-4 shrink-0" />
                        <span className="truncate">{msg.attachment.name}</span>
                        <Download className="h-3.5 w-3.5 shrink-0" />
                      </button>
                    )}
                  </div>
                )}
                {msg.text && <p className="break-words">{msg.text}</p>}
                <p
                  className={`mt-1 text-[10px] ${msg.direction === 'out' ? 'text-indigo-200/70' : 'text-gray-500'
                    }`}
                >
                  {new Date(msg.timestamp).toLocaleTimeString([], {
                    hour: '2-digit',
                    minute: '2-digit',
                  })}
                </p>
              </div>
            </div>
          ))}
          <div ref={messagesEndRef} />
        </div>

        {/* Error banner */}
        {error && (
          <div className="mx-4 mb-2 flex items-center gap-2 rounded-lg bg-red-500/10 px-3 py-2 text-sm text-red-400 md:mx-6">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span className="flex-1">{error}</span>
            <button onClick={() => setError('')} className="text-red-400 hover:text-red-300">
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        )}

        {/* Input bar */}
        {selectedContact && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSend();
            }}
            className="flex items-center gap-2 border-t border-gray-800 px-3 py-3 md:gap-3 md:px-6"
          >
            {/* Hidden file input */}
            <input
              ref={fileInputRef}
              type="file"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0] ?? null;
                setPendingFile(file);
              }}
              aria-label="Attach file"
            />

            {/* Attachment button */}
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg text-gray-400 transition hover:bg-gray-800 hover:text-gray-200"
              aria-label="Attach file"
            >
              <Paperclip className="h-4 w-4" />
            </button>

            <div className="flex flex-1 flex-col gap-1">
              {/* Pending file indicator */}
              {pendingFile && (
                <div className="flex items-center gap-2 rounded-md bg-gray-800/60 px-3 py-1 text-xs text-gray-300">
                  <FileIcon className="h-3.5 w-3.5 shrink-0 text-indigo-400" />
                  <span className="truncate">{pendingFile.name}</span>
                  <button
                    type="button"
                    onClick={() => {
                      setPendingFile(null);
                      if (fileInputRef.current) fileInputRef.current.value = '';
                    }}
                    className="ml-auto text-gray-500 hover:text-gray-300"
                    aria-label="Remove attachment"
                  >
                    <X className="h-3 w-3" />
                  </button>
                </div>
              )}
              <input
                ref={inputRef}
                type="text"
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                placeholder="Type a message…"
                className="w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2.5 text-sm text-gray-100 placeholder-gray-500 outline-none transition focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
                aria-label="Message input"
                autoFocus
              />
            </div>

            <button
              type="submit"
              disabled={(!inputText.trim() && !pendingFile) || sending}
              className="flex h-10 w-10 items-center justify-center rounded-lg bg-indigo-600 text-white transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-50"
              aria-label="Send message"
            >
              {sending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Send className="h-4 w-4" />
              )}
            </button>
          </form>
        )}
      </main>

      {/* ─── New-chat modal overlay ──────────────────────────────── */}
      {/* ─── Image lightbox ─────────────────────────────────── */}
      {lightboxSrc && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm"
          onClick={closeLightbox}
        >
          {/* Toolbar */}
          <div
            className="absolute top-4 right-4 flex items-center gap-1 z-10"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              onClick={() => setLightboxScale((s) => Math.min(s + 0.25, 5))}
              className="rounded-lg bg-gray-800/80 p-2 text-gray-300 transition hover:bg-gray-700 hover:text-white"
              aria-label="Zoom in"
            >
              <ZoomIn className="h-5 w-5" />
            </button>
            <button
              onClick={() => setLightboxScale((s) => Math.max(s - 0.25, 0.25))}
              className="rounded-lg bg-gray-800/80 p-2 text-gray-300 transition hover:bg-gray-700 hover:text-white"
              aria-label="Zoom out"
            >
              <ZoomOut className="h-5 w-5" />
            </button>
            <button
              onClick={() => setLightboxRotation((r) => r + 90)}
              className="rounded-lg bg-gray-800/80 p-2 text-gray-300 transition hover:bg-gray-700 hover:text-white"
              aria-label="Rotate"
            >
              <RotateCw className="h-5 w-5" />
            </button>
            <button
              onClick={closeLightbox}
              className="rounded-lg bg-gray-800/80 p-2 text-gray-300 transition hover:bg-gray-700 hover:text-white"
              aria-label="Close"
            >
              <X className="h-5 w-5" />
            </button>
          </div>

          {/* Image */}
          <img
            src={lightboxSrc}
            alt="Preview"
            className="max-h-[90vh] max-w-[90vw] rounded-lg object-contain transition-transform duration-200"
            style={{
              transform: `scale(${lightboxScale}) rotate(${lightboxRotation}deg)`,
            }}
            onClick={(e) => e.stopPropagation()}
            onWheel={(e) => {
              e.stopPropagation();
              setLightboxScale((s) =>
                e.deltaY < 0 ? Math.min(s + 0.15, 5) : Math.max(s - 0.15, 0.25)
              );
            }}
          />
        </div>
      )}

      {showNewChat && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="w-full max-w-sm rounded-2xl border border-gray-800 bg-gray-900 p-6 shadow-xl">
            <div className="mb-4 flex items-center justify-between">
              <h3 className="text-sm font-semibold">New Conversation</h3>
              <button
                onClick={() => {
                  setShowNewChat(false);
                  setNewUsername('');
                  setError('');
                }}
                className="text-gray-400 hover:text-gray-200"
                aria-label="Close"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleNewChat();
              }}
              className="flex flex-col gap-3"
            >
              <input
                type="text"
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                placeholder="Enter username"
                className="w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2.5 text-sm text-gray-100 placeholder-gray-500 outline-none transition focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
                aria-label="Contact username"
                autoFocus
              />

              {error && (
                <div className="flex items-center gap-2 rounded-lg bg-red-500/10 px-3 py-2 text-sm text-red-400">
                  <AlertCircle className="h-4 w-4 shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              <button
                type="submit"
                disabled={!newUsername.trim() || resolving}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-indigo-600 py-2.5 text-sm font-medium text-white transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-50"
              >
                <UserPlus className="h-4 w-4" />
                {resolving ? 'Searching…' : 'Start Chat'}
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
