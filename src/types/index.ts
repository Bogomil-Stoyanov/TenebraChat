// User types
export interface User {
    id: string;
    username: string;
    identity_public_key: string;
    registration_id: number;
    created_at: Date;
    updated_at: Date;
}

export interface CreateUserDTO {
    username: string;
    identity_public_key: string;
    registration_id: number;
}

// Signed Pre-Key types
export interface SignedPreKey {
    id: string;
    user_id: string;
    key_id: number;
    public_key: string;
    signature: string;
    created_at: Date;
}

export interface CreateSignedPreKeyDTO {
    user_id: string;
    key_id: number;
    public_key: string;
    signature: string;
}

// One-Time Pre-Key types
export interface OneTimePreKey {
    id: string;
    user_id: string;
    key_id: number;
    public_key: string;
    created_at: Date;
}

export interface CreateOneTimePreKeyDTO {
    user_id: string;
    key_id: number;
    public_key: string;
}

// Message Queue types
export interface QueuedMessage {
    id: string;
    recipient_id: string;
    sender_id: string;
    encrypted_payload: Buffer;
    message_type: string;
    file_reference?: string;
    created_at: Date;
    expires_at: Date;
}

export interface CreateQueuedMessageDTO {
    recipient_id: string;
    sender_id: string;
    encrypted_payload: Buffer;
    message_type?: string;
    file_reference?: string;
}

// Device types
export interface Device {
    id: string;
    user_id: string;
    device_id: number;
    identity_public_key: string;
    registration_id: number;
    device_name?: string;
    last_seen_at: Date;
    created_at: Date;
}

// Pre-Key Bundle for X3DH
export interface PreKeyBundle {
    user_id: string;
    username: string;
    registration_id: number;
    identity_public_key: string;
    signed_pre_key: {
        key_id: number;
        public_key: string;
        signature: string;
    };
    one_time_pre_key?: {
        key_id: number;
        public_key: string;
    };
}

// API Response types
export interface ApiResponse<T = unknown> {
    success: boolean;
    data?: T;
    error?: string;
    message?: string;
}
