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
    MessageSquarePlus,
    Send,
    UserPlus,
    AlertCircle,
    Wifi,
    WifiOff,
    X,
} from 'lucide-react';
import { db } from '@/db/db';
import type { Contact, Message } from '@/db/db';
import {
    sendMessage,
    processIncomingMessage,
    fetchAndProcessOfflineMessages,
    loadMessages,
    resolveUsername,
    resolveUserId,
} from '@/services/MessagingService';
import {
    connectSocket,
    onNewMessage,
    isConnected,
} from '@/services/SocketService';
import type { IncomingMessagePayload } from '@/services/SocketService';

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
    const [messages, setMessages] = useState<Message[]>([]);
    const [inputText, setInputText] = useState('');
    const [sending, setSending] = useState(false);
    const [error, setError] = useState('');
    const [connected, setConnected] = useState(false);

    // New-chat modal
    const [showNewChat, setShowNewChat] = useState(false);
    const [newUsername, setNewUsername] = useState('');
    const [resolving, setResolving] = useState(false);

    const messagesEndRef = useRef<HTMLDivElement>(null);
    const inputRef = useRef<HTMLInputElement>(null);

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
                    const user = await resolveUsername(userId);
                    resolvedName = user.username;
                } catch {
                    resolvedName = userId.slice(0, 8); // fallback
                }
            }

            const contact: Contact = { userId, username: resolvedName };
            await db.contacts.put(contact);
            await refreshContacts();
            return contact;
        },
        [refreshContacts],
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
                    encryptionKey,
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
        [encryptionKey, refreshContacts, selectedContact],
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
        };
    }, []);

    useEffect(() => {
        const unsub = onNewMessage(handleIncoming);
        return unsub;
    }, [handleIncoming]);

    // ── Fetch offline messages on mount ──────────────────────────────────────
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
                    const updated = await loadMessages(selectedContact.userId);
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
        loadMessages(selectedContact.userId).then(setMessages);
    }, [selectedContact]);

    // ── Auto-scroll to bottom ────────────────────────────────────────────────
    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages]);

    // ── Send a message ───────────────────────────────────────────────────────
    const handleSend = useCallback(async () => {
        if (!selectedContact || !inputText.trim() || sending) return;
        setError('');
        setSending(true);
        try {
            const msg = await sendMessage(
                selectedContact.userId,
                inputText.trim(),
                encryptionKey,
            );
            setMessages((prev) => [...prev, msg]);
            setInputText('');
            inputRef.current?.focus();
        } catch (err) {
            console.error('[Chat] Send failed:', err);
            setError(err instanceof Error ? err.message : 'Failed to send message.');
        } finally {
            setSending(false);
        }
    }, [selectedContact, inputText, sending, encryptionKey]);

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

    // ── Render ───────────────────────────────────────────────────────────────
    return (
        <div className="flex h-screen bg-gray-950 text-gray-100">
            {/* ─── Sidebar ─────────────────────────────────────────────── */}
            <aside className="flex w-72 flex-col border-r border-gray-800 bg-gray-900">
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
                            Press{' '}
                            <MessageSquarePlus className="inline h-3.5 w-3.5" /> to start one.
                        </p>
                    )}
                    {contacts.map((c) => (
                        <button
                            key={c.userId}
                            onClick={() => setSelectedContact(c)}
                            className={`flex w-full items-center gap-3 px-4 py-3 text-left transition hover:bg-gray-800/60 ${selectedContact?.userId === c.userId
                                    ? 'bg-gray-800/80'
                                    : ''
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
            <main className="flex flex-1 flex-col">
                {/* Header */}
                <header className="flex h-14 items-center border-b border-gray-800 px-6">
                    {selectedContact ? (
                        <h2 className="text-sm font-semibold">{selectedContact.username}</h2>
                    ) : (
                        <h2 className="text-sm text-gray-500">
                            Select a conversation or start a new one
                        </h2>
                    )}
                </header>

                {/* Messages area */}
                <div className="flex flex-1 flex-col overflow-y-auto px-6 py-4">
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
                                <span className="font-medium text-gray-300">
                                    {selectedContact.username}
                                </span>
                            </p>
                        </div>
                    )}

                    {messages.map((msg) => (
                        <div
                            key={msg.id}
                            className={`mb-2 flex ${msg.direction === 'out' ? 'justify-end' : 'justify-start'
                                }`}
                        >
                            <div
                                className={`max-w-[70%] rounded-2xl px-4 py-2 text-sm ${msg.direction === 'out'
                                        ? 'bg-indigo-600 text-white'
                                        : 'bg-gray-800 text-gray-100'
                                    }`}
                            >
                                <p className="wrap-break-word">{msg.text}</p>
                                <p
                                    className={`mt-1 text-[10px] ${msg.direction === 'out'
                                            ? 'text-indigo-200/70'
                                            : 'text-gray-500'
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
                    <div className="mx-6 mb-2 flex items-center gap-2 rounded-lg bg-red-500/10 px-3 py-2 text-sm text-red-400">
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
                        className="flex items-center gap-3 border-t border-gray-800 px-6 py-3"
                    >
                        <input
                            ref={inputRef}
                            type="text"
                            value={inputText}
                            onChange={(e) => setInputText(e.target.value)}
                            placeholder="Type a message…"
                            className="flex-1 rounded-lg border border-gray-700 bg-gray-800 px-4 py-2.5 text-sm text-gray-100 placeholder-gray-500 outline-none transition focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
                            aria-label="Message input"
                            autoFocus
                        />
                        <button
                            type="submit"
                            disabled={!inputText.trim() || sending}
                            className="flex h-10 w-10 items-center justify-center rounded-lg bg-indigo-600 text-white transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-50"
                            aria-label="Send message"
                        >
                            <Send className="h-4 w-4" />
                        </button>
                    </form>
                )}
            </main>

            {/* ─── New-chat modal overlay ──────────────────────────────── */}
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
